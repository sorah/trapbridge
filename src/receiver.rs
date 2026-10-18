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
            v => Err(crate::Error::Protocol(format!(
                "unsupported SNMP version {v}"
            ))),
        }
    }

    fn decode_community(&self, bytes: &[u8], peer: std::net::SocketAddr) -> crate::Result<Decoded> {
        let pdu = snmp2::Pdu::from_bytes(bytes)?;
        if !self.communities.is_empty() && !self.communities.contains(pdu.community) {
            return Err(crate::Error::Protocol("community not accepted".to_owned()));
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
                return Err(crate::Error::Protocol(
                    "SNMPv3 InformRequest is not supported".to_owned(),
                ));
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
) -> crate::Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let decoded = match decoder.decode(&buf[..len], peer) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(peer = %peer, error = %e, "dropping SNMP message");
                continue;
            }
        };
        if let Some(reply) = decoded.reply
            && let Err(e) = socket.send_to(&reply, peer).await
        {
            tracing::warn!(peer = %peer, error = %e, "failed to acknowledge inform");
        }
        tracing::debug!(
            peer = %peer,
            trap = decoded.trap.trap.name.as_deref().unwrap_or(&decoded.trap.trap.oid),
            "received trap"
        );
        if tx.send(decoded.trap).await.is_err() {
            return Ok(());
        }
    }
}
