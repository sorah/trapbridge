//! Owned, serializable representation of a received trap. This is the
//! EventBridge event `Detail`.

const SYS_UP_TIME_0: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const SNMP_TRAP_OID_0: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
/// snmpTraps; v1 generic traps 0..=5 map to its children 1..=6 (RFC 3584).
const SNMP_TRAPS: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 5];

#[derive(Debug, Clone, serde::Serialize)]
pub struct Trap {
    pub version: Version,
    pub source: Source,
    pub pdu_type: PduType,
    /// Absent for SNMPv1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<i32>,
    /// sysUpTime.0 (or the v1 time-stamp) in hundredths of a second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<u32>,
    pub trap: NamedOid,
    pub varbinds: Vec<Varbind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v1: Option<V1Info>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v3: Option<V3Info>,
    #[serde(skip)]
    pub received_at: std::time::SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    V1,
    V2c,
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PduType {
    Trap,
    Inform,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Source {
    pub address: std::net::IpAddr,
    pub port: u16,
    /// Reverse DNS name of `address`, when resolution is enabled and succeeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NamedOid {
    pub oid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct V1Info {
    pub enterprise: NamedOid,
    pub agent_address: std::net::IpAddr,
    pub generic_trap: i64,
    pub specific_trap: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct V3Info {
    pub username: String,
    pub engine_id: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Varbind {
    pub oid: String,
    /// `MODULE::name` of the deepest known MIB node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Sub-identifiers after the named node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(rename = "type")]
    pub kind: ValueType,
    pub value: Value,
    /// Raw octets of OCTET STRING and Opaque values, in hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hex: Option<String>,
    /// Enumeration label of an INTEGER value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    /// Labels of the bits set in a BITS value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Boolean,
    Null,
    Integer,
    OctetString,
    ObjectIdentifier,
    IpAddress,
    Counter32,
    Gauge32,
    Timeticks,
    Opaque,
    Counter64,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    String(String),
}

impl Trap {
    /// Build a trap from a decoded notification PDU (Trap-PDU, SNMPv2-Trap or
    /// InformRequest).
    pub fn from_pdu(
        pdu: &snmp2::Pdu<'_>,
        peer: std::net::SocketAddr,
        mib: &crate::mib::MibDatabase,
        v3: Option<&crate::usm::Header>,
    ) -> crate::Result<Self> {
        let version = match pdu.version()? {
            snmp2::Version::V1 => Version::V1,
            snmp2::Version::V2C => Version::V2c,
            snmp2::Version::V3 => Version::V3,
        };
        let pdu_type = match pdu.message_type {
            snmp2::MessageType::TrapV1 | snmp2::MessageType::Trap => PduType::Trap,
            snmp2::MessageType::InformRequest => PduType::Inform,
            other => {
                return Err(crate::Error::Unsupported(format!("PDU type {other:?}")));
            }
        };

        let mut varbinds = Vec::new();
        let mut uptime = None;
        let mut trap_oid = None;
        let mut v1 = None;

        if let Some(info) = &pdu.v1_trap_info {
            let enterprise = oid_components(&info.enterprise)?;
            trap_oid = Some(v1_trap_oid(
                &enterprise,
                info.generic_trap,
                info.specific_trap,
            ));
            uptime = Some(info.timestamp);
            v1 = Some(V1Info {
                enterprise: NamedOid::resolve(&enterprise, mib),
                agent_address: info.agent_addr,
                generic_trap: info.generic_trap,
                specific_trap: info.specific_trap,
            });
        }

        for (oid, value) in pdu.varbinds.clone() {
            let components = oid_components(&oid)?;
            if v1.is_none() {
                match (components.as_slice(), &value) {
                    (SYS_UP_TIME_0, snmp2::Value::Timeticks(t)) if uptime.is_none() => {
                        uptime = Some(*t);
                        continue;
                    }
                    (SNMP_TRAP_OID_0, snmp2::Value::ObjectIdentifier(o)) if trap_oid.is_none() => {
                        trap_oid = Some(oid_components(o)?);
                        continue;
                    }
                    _ => {}
                }
            }
            varbinds.push(Varbind::new(&components, &value, mib));
        }

        let trap_oid = trap_oid.ok_or_else(|| {
            crate::Error::Protocol("notification without snmpTrapOID.0".to_owned())
        })?;

        Ok(Self {
            version,
            source: Source {
                address: peer.ip().to_canonical(),
                port: peer.port(),
                hostname: None,
            },
            pdu_type,
            request_id: (version != Version::V1).then_some(pdu.req_id),
            uptime,
            trap: NamedOid::resolve(&trap_oid, mib),
            varbinds,
            v1,
            v3: v3.map(|header| V3Info {
                username: String::from_utf8_lossy(&header.username).into_owned(),
                engine_id: hex::encode(&header.engine_id),
            }),
            received_at: std::time::SystemTime::now(),
        })
    }
}

impl NamedOid {
    fn resolve(oid: &[u64], mib: &crate::mib::MibDatabase) -> Self {
        let name = mib.resolve(oid).map(|r| match r.instance() {
            Some(instance) => format!("{}.{instance}", r.qualified_name()),
            None => r.qualified_name(),
        });
        Self {
            oid: crate::mib::join_oid(oid),
            name,
        }
    }
}

/// RFC 3584 section 3.1 translation of a Trap-PDU to snmpTrapOID.
fn v1_trap_oid(enterprise: &[u64], generic: i64, specific: i64) -> Vec<u64> {
    match generic {
        0..=5 => {
            let mut oid = SNMP_TRAPS.to_vec();
            oid.push(generic as u64 + 1);
            oid
        }
        _ => {
            let mut oid = enterprise.to_vec();
            oid.push(0);
            oid.push(specific as u64);
            oid
        }
    }
}

fn oid_components(oid: &snmp2::Oid<'_>) -> crate::Result<Vec<u64>> {
    oid.iter()
        .map(|it| it.collect())
        .ok_or_else(|| crate::Error::Protocol(format!("OID {oid} has an oversized sub-identifier")))
}

impl Varbind {
    fn new(oid: &[u64], value: &snmp2::Value<'_>, mib: &crate::mib::MibDatabase) -> Self {
        let resolved = mib.resolve(oid);
        let node = resolved.map(|r| r.node);
        let mut vb = Self {
            oid: crate::mib::join_oid(oid),
            name: resolved.map(|r| r.qualified_name()),
            instance: resolved.and_then(|r| r.instance()),
            kind: ValueType::Unknown,
            value: Value::Null,
            value_hex: None,
            value_name: None,
            bits: None,
            units: node.and_then(|n| n.units.clone()),
        };
        match value {
            snmp2::Value::Boolean(b) => {
                vb.kind = ValueType::Boolean;
                vb.value = Value::Bool(*b);
            }
            snmp2::Value::Null => vb.kind = ValueType::Null,
            snmp2::Value::Integer(i) => {
                vb.kind = ValueType::Integer;
                vb.value_name = node.and_then(|n| n.enums.get(i).cloned());
                vb.value = match node.and_then(|n| n.hint.as_deref()) {
                    // Plain "d" keeps the value numeric.
                    Some(hint) if hint != "d" && vb.value_name.is_none() => {
                        crate::mib::hint::render_integer(hint, *i)
                            .map(Value::String)
                            .unwrap_or(Value::Integer(*i))
                    }
                    _ => Value::Integer(*i),
                };
            }
            snmp2::Value::OctetString(octets) => {
                vb.kind = ValueType::OctetString;
                vb.value_hex = Some(hex::encode(octets));
                if let Some(n) = node.filter(|n| n.kind == crate::mib::NodeType::Bits) {
                    vb.bits = Some(bit_labels(octets, &n.enums));
                }
                vb.value = Value::String(render_octets(octets, node));
            }
            snmp2::Value::ObjectIdentifier(o) => {
                vb.kind = ValueType::ObjectIdentifier;
                match oid_components(o) {
                    Ok(c) => {
                        let named = NamedOid::resolve(&c, mib);
                        vb.value_name = named.name;
                        vb.value = Value::String(named.oid);
                    }
                    Err(_) => vb.value = Value::String(o.to_id_string()),
                }
            }
            snmp2::Value::IpAddress(a) => {
                vb.kind = ValueType::IpAddress;
                vb.value = Value::String(std::net::Ipv4Addr::from(*a).to_string());
            }
            snmp2::Value::Counter32(c) => {
                vb.kind = ValueType::Counter32;
                vb.value = Value::Unsigned(u64::from(*c));
            }
            snmp2::Value::Unsigned32(g) => {
                vb.kind = ValueType::Gauge32;
                vb.value = Value::Unsigned(u64::from(*g));
            }
            snmp2::Value::Timeticks(t) => {
                vb.kind = ValueType::Timeticks;
                vb.value = Value::Unsigned(u64::from(*t));
            }
            snmp2::Value::Opaque(o) => {
                vb.kind = ValueType::Opaque;
                vb.value_hex = Some(hex::encode(o));
            }
            snmp2::Value::Counter64(c) => {
                vb.kind = ValueType::Counter64;
                vb.value = Value::Unsigned(*c);
            }
            snmp2::Value::NoSuchObject => vb.kind = ValueType::NoSuchObject,
            snmp2::Value::NoSuchInstance => vb.kind = ValueType::NoSuchInstance,
            snmp2::Value::EndOfMibView => vb.kind = ValueType::EndOfMibView,
            _ => {}
        }
        vb
    }
}

/// Explicit format, then DISPLAY-HINT, then text if printable, else hex.
fn render_octets(octets: &[u8], node: Option<&crate::mib::Node>) -> String {
    if let Some(node) = node {
        if let Some(s) = node.format.and_then(|f| f.render(octets)) {
            return s;
        }
        if let Some(s) = node
            .hint
            .as_deref()
            .and_then(|h| crate::mib::hint::render_octets(h, octets))
        {
            return s;
        }
    }
    match std::str::from_utf8(octets) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c.is_whitespace()) => s.to_owned(),
        _ => hex::encode(octets),
    }
}

/// BITS encoding: bit 0 is the most significant bit of the first octet.
fn bit_labels(octets: &[u8], enums: &std::collections::BTreeMap<i64, String>) -> Vec<String> {
    let mut labels = vec![];
    for (i, octet) in octets.iter().enumerate() {
        for bit in 0..8 {
            if octet & (0x80 >> bit) != 0 {
                let pos = (i * 8 + bit) as i64;
                labels.push(enums.get(&pos).cloned().unwrap_or_else(|| pos.to_string()));
            }
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    #[test]
    fn v1_generic_trap_maps_to_snmp_traps() {
        assert_eq!(
            crate::trap::v1_trap_oid(&[1, 3, 6, 1, 4, 1, 99], 2, 0),
            vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 3]
        );
    }

    #[test]
    fn v1_enterprise_specific_trap_maps_under_enterprise() {
        assert_eq!(
            crate::trap::v1_trap_oid(&[1, 3, 6, 1, 4, 1, 99], 6, 17),
            vec![1, 3, 6, 1, 4, 1, 99, 0, 17]
        );
    }

    #[test]
    fn bit_labels_use_enum_names() {
        let enums = [(0, "a".to_owned()), (9, "j".to_owned())]
            .into_iter()
            .collect();
        assert_eq!(
            crate::trap::bit_labels(&[0x80, 0x60], &enums),
            vec!["a", "j", "10"]
        );
    }

    #[test]
    fn render_octets_falls_back_to_hex_for_binary() {
        assert_eq!(crate::trap::render_octets(b"up\n", None), "up\n");
        assert_eq!(crate::trap::render_octets(&[0, 1, 0xff], None), "0001ff");
    }
}
