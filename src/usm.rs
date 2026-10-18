//! SNMPv3 User-based Security Model glue around snmp2: header peeking and
//! per-(engine ID, user) security state.

/// msgFlags reportable bit (RFC 3412).
pub const FLAG_REPORTABLE: u8 = 0x04;

/// Upper bound on engine IDs learned for users configured without one.
const MAX_LEARNED: usize = 4096;

/// Read the msgVersion of an SNMP message without decoding the rest.
pub fn message_version(bytes: &[u8]) -> crate::Result<i64> {
    let seq = snmp2::AsnReader::from_bytes(bytes).read_raw(snmp2::asn1::TYPE_SEQUENCE)?;
    Ok(snmp2::AsnReader::from_bytes(seq).read_asn_integer()?)
}

/// Unauthenticated fields of an SNMPv3 message header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub engine_id: Vec<u8>,
    pub username: Vec<u8>,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> crate::Result<Self> {
        let seq = snmp2::AsnReader::from_bytes(bytes).read_raw(snmp2::asn1::TYPE_SEQUENCE)?;
        let mut rdr = snmp2::AsnReader::from_bytes(seq);
        if rdr.read_asn_integer()? != snmp2::Version::V3 as i64 {
            return Err(crate::Error::Protocol("not an SNMPv3 message".to_owned()));
        }
        let global = rdr.read_raw(snmp2::asn1::TYPE_SEQUENCE)?;
        let mut global = snmp2::AsnReader::from_bytes(global);
        let _msg_id = global.read_asn_integer()?;
        let _max_size = global.read_asn_integer()?;
        let flags = global
            .read_asn_octetstring()?
            .first()
            .copied()
            .unwrap_or_default();
        let model = global.read_asn_integer()?;
        if model != 3 {
            return Err(crate::Error::Protocol(format!(
                "unsupported security model {model}"
            )));
        }
        let params = rdr.read_asn_octetstring()?;
        let params = snmp2::AsnReader::from_bytes(params).read_raw(snmp2::asn1::TYPE_SEQUENCE)?;
        let mut params = snmp2::AsnReader::from_bytes(params);
        let engine_id = params.read_asn_octetstring()?.to_vec();
        let _boots = params.read_asn_integer()?;
        let _time = params.read_asn_integer()?;
        let username = params.read_asn_octetstring()?.to_vec();
        Ok(Self {
            flags,
            engine_id,
            username,
        })
    }
}

/// (engine ID, username).
type ContextKey = (Vec<u8>, Vec<u8>);

/// Security contexts for configured v3 users.
///
/// snmp2 binds a `Security` to one authoritative engine ID and tracks its
/// boots/time, so state is kept per (engine ID, username).
#[derive(Debug, Default)]
pub struct SecurityStore {
    contexts: std::sync::Mutex<std::collections::HashMap<ContextKey, snmp2::v3::Security>>,
    templates: std::collections::HashMap<Vec<u8>, snmp2::v3::Security>,
}

impl SecurityStore {
    pub fn new(users: &[crate::config::V3User]) -> crate::Result<Self> {
        let mut contexts = std::collections::HashMap::new();
        let mut templates = std::collections::HashMap::new();
        for user in users {
            let security = user.to_security();
            let username = user.username.as_bytes().to_vec();
            match user.engine_id_bytes() {
                Some(engine_id) => {
                    let engine_id = engine_id
                        .map_err(|e| crate::Error::Config(format!("invalid engine_id: {e}")))?;
                    let security = security.with_engine_id(&engine_id)?;
                    contexts.insert((engine_id, username), security);
                }
                None => {
                    templates.insert(username, security);
                }
            }
        }
        Ok(Self {
            contexts: std::sync::Mutex::new(contexts),
            templates,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty() && self.contexts.lock().unwrap().is_empty()
    }

    /// Authenticate and decrypt `bytes`, then hand the PDU to `f`.
    pub fn decode<T>(
        &self,
        header: &Header,
        bytes: &[u8],
        f: impl FnOnce(snmp2::Pdu<'_>) -> crate::Result<T>,
    ) -> crate::Result<T> {
        let key = (header.engine_id.clone(), header.username.clone());
        let mut contexts = self.contexts.lock().unwrap();
        if let Some(security) = contexts.get_mut(&key) {
            return Self::decode_with(security, bytes, f);
        }
        let Some(template) = self.templates.get(&header.username) else {
            return Err(crate::Error::Protocol(format!(
                "unknown SNMPv3 user {:?} for engine ID {}",
                String::from_utf8_lossy(&header.username),
                hex::encode(&header.engine_id)
            )));
        };
        if header.engine_id.is_empty() {
            return Err(crate::Error::Protocol(
                "SNMPv3 message without an engine ID".to_owned(),
            ));
        }
        let mut security = template.clone().with_engine_id(&header.engine_id)?;
        let result = Self::decode_with(&mut security, bytes, f)?;
        if contexts.len() < MAX_LEARNED {
            contexts.insert(key, security);
        } else {
            tracing::warn!(
                engine_id = hex::encode(&header.engine_id),
                "too many learned SNMPv3 engine IDs; not caching security state"
            );
        }
        Ok(result)
    }

    fn decode_with<T>(
        security: &mut snmp2::v3::Security,
        bytes: &[u8],
        f: impl FnOnce(snmp2::Pdu<'_>) -> crate::Result<T>,
    ) -> crate::Result<T> {
        // snmp2 zeroes the authentication parameters in the input while verifying.
        let mut buf = bytes.to_vec();
        let mut attempts = 0;
        loop {
            attempts += 1;
            match snmp2::Pdu::from_bytes_with_security(&buf, Some(&mut *security)) {
                Ok(pdu) => return f(pdu),
                // Raised after adopting a newer engine boots/time; parsing again succeeds.
                Err(snmp2::Error::AuthUpdated) if attempts < 3 => {
                    buf.copy_from_slice(bytes);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}
