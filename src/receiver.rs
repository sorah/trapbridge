//! UDP trap listener: decode each datagram, enforce community/USM checks,
//! acknowledge v1/v2c Informs, and pass traps on to the publisher.

/// A decoded message and the reply owed to its sender, if any.
#[derive(Debug)]
pub struct Decoded {
    pub trap: crate::trap::Trap,
    pub reply: Option<Vec<u8>>,
}

/// Stateless apart from SNMPv3 security contexts; shared by all listeners.
#[derive(Debug)]
pub struct Decoder {
    communities: std::collections::HashSet<Vec<u8>>,
    usm: crate::usm::SecurityStore,
    mib: std::sync::Arc<crate::mib::MibDatabase>,
}

impl Decoder {
    pub fn new(
        communities: impl IntoIterator<Item = String>,
        usm: crate::usm::SecurityStore,
        mib: std::sync::Arc<crate::mib::MibDatabase>,
    ) -> Self {
        Self {
            communities: communities.into_iter().map(String::into_bytes).collect(),
            usm,
            mib,
        }
    }

    pub fn decode(&self, bytes: &[u8], peer: std::net::SocketAddr) -> crate::Result<Decoded> {
        match crate::usm::message_version(bytes)? {
            0 | 1 => self.decode_community(bytes, peer),
            3 => self.decode_usm(bytes, peer),
            v => Err(crate::Error::Unsupported(format!("SNMP version {v}"))),
        }
    }

    fn decode_community(&self, bytes: &[u8], peer: std::net::SocketAddr) -> crate::Result<Decoded> {
        let pdu = snmp2::Pdu::from_bytes(bytes)?;
        if !self.communities.is_empty() && !self.communities.contains(pdu.community) {
            return Err(crate::Error::CommunityRejected);
        }
        let trap = crate::trap::Trap::from_pdu(&pdu, peer, &self.mib, None)?;
        let reply = if pdu.message_type == snmp2::MessageType::InformRequest {
            let mut response = pdu.clone();
            response.message_type = snmp2::MessageType::Response;
            Some(response.to_bytes()?)
        } else {
            None
        };
        Ok(Decoded { trap, reply })
    }

    fn decode_usm(&self, bytes: &[u8], peer: std::net::SocketAddr) -> crate::Result<Decoded> {
        let header = crate::usm::Header::parse(bytes)?;
        let trap = self.usm.decode(&header, bytes, |pdu| {
            if pdu.message_type == snmp2::MessageType::InformRequest {
                return Err(crate::Error::Unsupported("SNMPv3 InformRequest".to_owned()));
            }
            crate::trap::Trap::from_pdu(&pdu, peer, &self.mib, Some(&header))
        })?;
        Ok(Decoded { trap, reply: None })
    }
}

/// Bind a listener socket.
pub async fn bind(addr: std::net::SocketAddr) -> crate::Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .map_err(|e| crate::Error::Other(format!("failed to bind {addr}: {e}")))?;
    tracing::info!(addr = %socket.local_addr()?, "listening");
    Ok(socket)
}

/// Receive datagrams until the socket fails or the publisher goes away.
pub async fn run(
    socket: tokio::net::UdpSocket,
    decoder: std::sync::Arc<Decoder>,
    tx: tokio::sync::mpsc::Sender<crate::trap::Trap>,
    metrics: std::sync::Arc<crate::metrics::Metrics>,
    reverse_dns: Option<std::sync::Arc<crate::reverse_dns::ReverseDns>>,
) -> crate::Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let decoded = match decoder.decode(&buf[..len], peer) {
            Ok(d) => d,
            Err(e) => {
                metrics.dropped(e.drop_reason());
                tracing::warn!(peer = %peer, error = %e, "dropping SNMP message");
                continue;
            }
        };
        if let Some(reply) = decoded.reply
            && let Err(e) = socket.send_to(&reply, peer).await
        {
            tracing::warn!(peer = %peer, error = %e, "failed to acknowledge inform");
        }
        metrics.received(&decoded.trap);
        tracing::debug!(
            peer = %peer,
            trap = decoded.trap.trap.name.as_deref().unwrap_or(&decoded.trap.trap.oid),
            "received trap"
        );
        match &reverse_dns {
            Some(dns) => {
                // Lookups run off the receive loop so a slow resolver cannot stall the socket.
                let (dns, task_tx, mut trap) = (dns.clone(), tx.clone(), decoded.trap);
                tokio::spawn(async move {
                    trap.source.hostname = dns.lookup(trap.source.address).await;
                    let _ = task_tx.send(trap).await;
                });
                if tx.is_closed() {
                    return Ok(());
                }
            }
            None => {
                if tx.send(decoded.trap).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/{name}.hex", env!("CARGO_MANIFEST_DIR"));
        hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
    }

    #[tokio::test]
    async fn run_counts_received_and_dropped_messages() {
        let socket = crate::receiver::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let decoder = std::sync::Arc::new(crate::receiver::Decoder::new(
            ["public".to_owned()],
            Default::default(),
            Default::default(),
        ));
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(crate::receiver::run(
            socket,
            decoder,
            tx,
            metrics.clone(),
            None,
        ));

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"\x30\x03\x02\x01", addr).await.unwrap();
        sender.send_to(&fixture("v2c_trap"), addr).await.unwrap();
        let trap = rx.recv().await.unwrap();
        assert_eq!(trap.version, crate::trap::Version::V2c);
        task.abort();

        let text = metrics.encode().unwrap();
        assert!(
            text.contains("trapbridge_received_total{version=\"v2c\",pdu_type=\"trap\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("trapbridge_dropped_total{reason=\"parse\"} 1\n"),
            "{text}"
        );
    }
}
