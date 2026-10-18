//! MIB data loaded from JSON produced by `trapbridge mib-dump`, used to name
//! OIDs and format varbind values without linking net-snmp at runtime.

pub mod hint;

/// On-disk MIB JSON document.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MibFile {
    /// Nodes keyed by dotted numeric OID.
    pub nodes: std::collections::BTreeMap<String, Node>,
}

/// A single MIB node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub name: String,
    pub module: String,
    #[serde(rename = "type")]
    pub kind: NodeType,
    /// TEXTUAL-CONVENTION name, if the syntax uses one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tc: Option<String>,
    /// Value format forced by a `mib-dump` override or implied by the TC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ValueFormat>,
    /// DISPLAY-HINT, after `mib-dump` overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub units: Option<String>,
    /// Enumerated INTEGER labels, or BITS labels keyed by bit position.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub enums: std::collections::BTreeMap<i64, String>,
    /// Dotted OIDs of the OBJECTS (or SMIv1 VARIABLES) of a notification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<String>,
}

/// net-snmp node types (`TYPE_*` in `net-snmp/library/parse.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeType {
    Other,
    ObjectIdentifier,
    OctetString,
    Integer,
    NetworkAddress,
    IpAddress,
    Counter32,
    Gauge32,
    TimeTicks,
    Opaque,
    Null,
    Counter64,
    Bits,
    NsapAddress,
    UInteger32,
    Unsigned32,
    Integer32,
    TrapType,
    NotificationType,
    ObjectGroup,
    NotificationGroup,
    ModuleIdentity,
    AgentCapabilities,
    ModuleCompliance,
    ObjectIdentity,
}

impl NodeType {
    /// Whether the node describes a trap or notification.
    pub fn is_notification(self) -> bool {
        matches!(self, NodeType::TrapType | NodeType::NotificationType)
    }
}

/// Explicit value formats, matching the `type` names of snmp_exporter's
/// generator overrides where they overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValueFormat {
    /// Text, replacing invalid UTF-8 sequences.
    DisplayString,
    /// Lowercase hex without separators.
    OctetString,
    /// Colon separated hex octets such as a MAC address.
    PhysAddress48,
    /// 4 or 16 octet IPv4 or IPv6 address.
    InetAddress,
    /// SNMPv2-TC DateAndTime rendered as RFC 3339.
    DateAndTime,
}

/// In-memory MIB lookup table.
#[derive(Debug, Default)]
pub struct MibDatabase {
    nodes: std::collections::HashMap<Vec<u64>, Node>,
}

/// Result of resolving an OID against the database.
#[derive(Debug, Clone, Copy)]
pub struct Resolved<'a> {
    pub node: &'a Node,
    /// Sub-identifiers following the node's OID, i.e. the instance.
    pub suffix: &'a [u64],
}

impl Resolved<'_> {
    /// `MODULE::name`.
    pub fn qualified_name(&self) -> String {
        format!("{}::{}", self.node.module, self.node.name)
    }

    /// Dotted instance suffix, or `None` for an exact match.
    pub fn instance(&self) -> Option<String> {
        if self.suffix.is_empty() {
            None
        } else {
            Some(crate::mib::join_oid(self.suffix))
        }
    }
}

impl MibDatabase {
    /// Load and merge MIB JSON files. Later files win on duplicate OIDs.
    pub fn load(paths: &[std::path::PathBuf]) -> crate::Result<Self> {
        let mut db = Self::default();
        for path in paths {
            let file = std::fs::File::open(path).map_err(|e| {
                crate::Error::Mib(format!("failed to open {}: {e}", path.display()))
            })?;
            let mib: MibFile =
                serde_json::from_reader(std::io::BufReader::new(file)).map_err(|e| {
                    crate::Error::Mib(format!("failed to parse {}: {e}", path.display()))
                })?;
            db.merge(mib)?;
        }
        Ok(db)
    }

    /// Add every node of `mib`, replacing existing ones with the same OID.
    pub fn merge(&mut self, mib: MibFile) -> crate::Result<()> {
        for (oid, node) in mib.nodes {
            let components = crate::mib::parse_oid(&oid)
                .ok_or_else(|| crate::Error::Mib(format!("invalid OID {oid:?}")))?;
            self.nodes.insert(components, node);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Exact-match lookup.
    pub fn get(&self, oid: &[u64]) -> Option<&Node> {
        self.nodes.get(oid)
    }

    /// Longest-prefix lookup: the deepest known node that `oid` falls under.
    pub fn resolve<'a>(&'a self, oid: &'a [u64]) -> Option<Resolved<'a>> {
        (1..=oid.len()).rev().find_map(|len| {
            self.nodes.get(&oid[..len]).map(|node| Resolved {
                node,
                suffix: &oid[len..],
            })
        })
    }
}

/// Parse a dotted numeric OID; a leading dot is accepted.
pub fn parse_oid(s: &str) -> Option<Vec<u64>> {
    let s = s.strip_prefix('.').unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|c| c.parse().ok()).collect()
}

/// Join sub-identifiers with dots.
pub fn join_oid(components: &[u64]) -> String {
    components
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    fn node(name: &str, kind: crate::mib::NodeType) -> crate::mib::Node {
        crate::mib::Node {
            name: name.to_owned(),
            module: "IF-MIB".to_owned(),
            kind,
            tc: None,
            format: None,
            hint: None,
            units: None,
            enums: Default::default(),
            objects: vec![],
        }
    }

    fn db() -> crate::mib::MibDatabase {
        let mut file = crate::mib::MibFile::default();
        file.nodes.insert(
            "1.3.6.1.2.1.2.2.1.1".to_owned(),
            node("ifIndex", crate::mib::NodeType::Integer32),
        );
        file.nodes.insert(
            "1.3.6.1.2.1.2.2.1".to_owned(),
            node("ifEntry", crate::mib::NodeType::Other),
        );
        let mut db = crate::mib::MibDatabase::default();
        db.merge(file).unwrap();
        db
    }

    #[test]
    fn resolve_returns_longest_prefix_and_instance() {
        let db = db();
        let oid = crate::mib::parse_oid("1.3.6.1.2.1.2.2.1.1.3").unwrap();
        let resolved = db.resolve(&oid).unwrap();
        assert_eq!(resolved.qualified_name(), "IF-MIB::ifIndex");
        assert_eq!(resolved.instance().as_deref(), Some("3"));
    }

    #[test]
    fn resolve_exact_match_has_no_instance() {
        let db = db();
        let oid = crate::mib::parse_oid("1.3.6.1.2.1.2.2.1.1").unwrap();
        assert_eq!(db.resolve(&oid).unwrap().instance(), None);
    }

    #[test]
    fn resolve_unknown_returns_none() {
        let db = db();
        assert!(db.resolve(&[1, 3, 6, 1, 4]).is_none());
    }

    #[test]
    fn node_json_round_trips() {
        let json = r#"{"nodes":{"1.3.6.1.2.1.2.2.1.8":{"name":"ifOperStatus","module":"IF-MIB","type":"INTEGER","enums":{"1":"up","2":"down"}}}}"#;
        let file: crate::mib::MibFile = serde_json::from_str(json).unwrap();
        let node = &file.nodes["1.3.6.1.2.1.2.2.1.8"];
        assert_eq!(node.enums[&2], "down");
        assert_eq!(serde_json::to_string(&file).unwrap(), json);
    }

    #[test]
    fn parse_oid_rejects_garbage() {
        assert_eq!(crate::mib::parse_oid(".1.3.6"), Some(vec![1, 3, 6]));
        assert_eq!(crate::mib::parse_oid("1.x"), None);
        assert_eq!(crate::mib::parse_oid(""), None);
    }
}
