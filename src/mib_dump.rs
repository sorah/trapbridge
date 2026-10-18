//! MIB tree export via net-snmp, modelled on snmp_exporter's generator: load
//! MIB modules, select subtrees and notification objects, apply overrides,
//! and produce a [`crate::mib::MibFile`].

/// `mib-dump` configuration file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MibDumpConfig {
    /// MIB search directories. Empty uses net-snmp's default (or `MIBDIRS`).
    #[serde(default)]
    pub mib_dirs: Vec<String>,
    /// MIB modules to load. Empty loads every module found.
    #[serde(default)]
    pub modules: Vec<String>,
    /// Subtree roots to export, by name (`IF-MIB::linkDown`, `ifTable`) or
    /// numeric OID. Empty exports every notification.
    #[serde(default)]
    pub include: Vec<String>,
    /// Per-node adjustments keyed by name or numeric OID.
    #[serde(default)]
    pub overrides: std::collections::BTreeMap<String, Override>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// Leave the node out of the output.
    #[serde(default)]
    pub ignore: bool,
    /// Replace the node's name.
    #[serde(default)]
    pub name: Option<String>,
    /// Force how values are formatted.
    #[serde(default, rename = "type")]
    pub format: Option<crate::mib::ValueFormat>,
    /// Replace the node's DISPLAY-HINT.
    #[serde(default)]
    pub display_hint: Option<String>,
}

impl MibDumpConfig {
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| crate::Error::Config(format!("failed to open {}: {e}", path.display())))?;
        serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|e| crate::Error::Config(format!("failed to parse {}: {e}", path.display())))
    }
}

/// A node read from net-snmp's tree, before selection and overrides.
#[derive(Debug, Clone)]
pub struct RawNode {
    pub node: crate::mib::Node,
    /// OBJECTS / VARIABLES labels as written in the MIB.
    pub varbind_labels: Vec<String>,
}

/// The loaded MIB tree, keyed by OID.
#[derive(Debug, Default)]
pub struct MibTree {
    pub nodes: std::collections::BTreeMap<Vec<u64>, RawNode>,
    /// net-snmp parser messages.
    pub parse_errors: Vec<String>,
}

impl MibTree {
    /// Load MIBs with net-snmp. Must be called at most once per process, before
    /// other threads start, because net-snmp is configured through the
    /// environment and global state.
    pub fn load(mib_dirs: &[String], modules: &[String]) -> crate::Result<Self> {
        let modules: Vec<&str> = if modules.is_empty() {
            vec!["ALL"]
        } else {
            modules.iter().map(String::as_str).collect()
        };
        let mib_dirs: Vec<&str> = mib_dirs.iter().map(String::as_str).collect();
        let config = snmp2::mibs::Config::new()
            .app_name("trapbridge")
            .mibs(&modules)
            .mib_dirs(&mib_dirs);

        // e: no symbol conflict errors, u: allow underscores, as in snmp_exporter.
        let toggles = std::ffi::CString::new("eu").unwrap();
        // SAFETY: net-snmp copies nothing from the string; it only reads the flags.
        unsafe {
            netsnmp_sys_nocrypto::snmp_mib_toggle_options(toggles.as_ptr().cast_mut());
        }
        let (result, stderr) = crate::mib_dump::capture_stderr(|| snmp2::mibs::init(&config))?;
        result?;

        let mut tree = Self {
            parse_errors: stderr
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        };
        // SAFETY: the tree is owned by net-snmp and stays valid until shutdown,
        // which never happens in this process.
        unsafe {
            let head = netsnmp_sys_nocrypto::get_tree_head();
            tree.walk(head, &mut vec![]);
        }
        Ok(tree)
    }

    /// Depth-first walk over `node` and its peers.
    unsafe fn walk(
        &mut self,
        mut node: *mut netsnmp_sys_nocrypto::Struct_tree,
        path: &mut Vec<u64>,
    ) {
        while !node.is_null() {
            // SAFETY: non-null tree nodes from net-snmp are valid.
            let t = unsafe { &*node };
            // c_ulong is 32-bit on some targets.
            #[allow(clippy::unnecessary_cast)]
            path.push(t.subid as u64);
            // SAFETY: as above, for every pointer reachable from a node.
            if let Some(raw) = unsafe { Self::convert(t) } {
                self.nodes.insert(path.clone(), raw);
            }
            unsafe { self.walk(t.child_list, path) };
            path.pop();
            node = t.next_peer;
        }
    }

    unsafe fn convert(t: &netsnmp_sys_nocrypto::Struct_tree) -> Option<RawNode> {
        let name = unsafe { cstr(t.label) }?;
        let module = unsafe {
            let m = netsnmp_sys_nocrypto::find_module(t.modid);
            if m.is_null() { None } else { cstr((*m).name) }
        }
        .unwrap_or_else(|| format!("#{}", t.modid));
        let tc = if t.tc_index >= 0 {
            unsafe { cstr(netsnmp_sys_nocrypto::get_tc_descriptor(t.tc_index)) }
        } else {
            None
        };
        let mut enums = std::collections::BTreeMap::new();
        let mut e = t.enums;
        while !e.is_null() {
            let item = unsafe { &*e };
            if let Some(label) = unsafe { cstr(item.label) } {
                enums.insert(i64::from(item.value), label);
            }
            e = item.next;
        }
        let mut varbind_labels = vec![];
        let mut v = t.varbinds;
        while !v.is_null() {
            let item = unsafe { &*v };
            if let Some(label) = unsafe { cstr(item.vblabel) } {
                varbind_labels.push(label);
            }
            v = item.next;
        }
        let format = match tc.as_deref() {
            Some("DateAndTime") => Some(crate::mib::ValueFormat::DateAndTime),
            Some("InetAddress") => Some(crate::mib::ValueFormat::InetAddress),
            _ => None,
        };
        Some(RawNode {
            node: crate::mib::Node {
                name,
                module,
                kind: node_type(t._type),
                tc,
                format,
                hint: unsafe { cstr(t.hint) },
                units: unsafe { cstr(t.units) },
                enums,
                objects: vec![],
            },
            varbind_labels,
        })
    }

    /// Resolve a name or numeric OID to a node in this tree.
    pub fn lookup(&self, name: &str) -> Option<Vec<u64>> {
        if let Some(oid) = crate::mib::parse_oid(name) {
            return self.nodes.contains_key(&oid).then_some(oid);
        }
        let (module, label) = match name.split_once("::") {
            Some((m, l)) => (Some(m), l),
            None => (None, name),
        };
        self.nodes
            .iter()
            .find(|(_, raw)| raw.node.name == label && module.is_none_or(|m| raw.node.module == m))
            .map(|(oid, _)| oid.clone())
    }

    /// Resolve a notification's OBJECTS label, preferring its own module.
    fn lookup_object(&self, label: &str, module: &str) -> Option<Vec<u64>> {
        self.lookup(&format!("{module}::{label}"))
            .or_else(|| self.lookup(label))
    }

    /// Apply `include` and `overrides` and produce the output document.
    pub fn export(&self, config: &MibDumpConfig) -> crate::Result<crate::mib::MibFile> {
        let mut selected = std::collections::BTreeSet::new();
        if config.include.is_empty() {
            selected.extend(
                self.nodes
                    .iter()
                    .filter(|(_, raw)| raw.node.kind.is_notification())
                    .map(|(oid, _)| oid.clone()),
            );
        } else {
            for root in &config.include {
                let root = self
                    .lookup(root)
                    .ok_or_else(|| crate::Error::Mib(format!("include {root:?} not found")))?;
                selected.extend(
                    self.nodes
                        .range(root.clone()..)
                        .take_while(|(oid, _)| oid.starts_with(&root))
                        .map(|(oid, _)| oid.clone()),
                );
            }
        }

        let mut out = crate::mib::MibFile::default();
        let mut objects = std::collections::BTreeSet::new();
        for oid in &selected {
            let raw = &self.nodes[oid];
            let mut node = raw.node.clone();
            for label in &raw.varbind_labels {
                match self.lookup_object(label, &node.module) {
                    Some(obj) => {
                        node.objects.push(crate::mib::join_oid(&obj));
                        objects.insert(obj);
                    }
                    None => tracing::warn!(
                        notification = format!("{}::{}", node.module, node.name),
                        object = label,
                        "notification object not found"
                    ),
                }
            }
            out.nodes.insert(crate::mib::join_oid(oid), node);
        }
        for oid in objects.difference(&selected) {
            out.nodes
                .insert(crate::mib::join_oid(oid), self.nodes[oid].node.clone());
        }

        for (key, ov) in &config.overrides {
            let oid = self
                .lookup(key)
                .ok_or_else(|| crate::Error::Mib(format!("override {key:?} not found")))?;
            let oid = crate::mib::join_oid(&oid);
            if ov.ignore {
                out.nodes.remove(&oid);
                continue;
            }
            let Some(node) = out.nodes.get_mut(&oid) else {
                tracing::warn!(key = key, "override target is not selected for export");
                continue;
            };
            if let Some(name) = &ov.name {
                node.name = name.clone();
            }
            if let Some(format) = ov.format {
                node.format = Some(format);
            }
            if let Some(hint) = &ov.display_hint {
                node.hint = Some(hint.clone());
            }
        }
        Ok(out)
    }
}

/// net-snmp `TYPE_*` constants from `net-snmp/library/parse.h`.
fn node_type(t: std::os::raw::c_int) -> crate::mib::NodeType {
    match t {
        1 => crate::mib::NodeType::ObjectIdentifier,
        2 => crate::mib::NodeType::OctetString,
        3 => crate::mib::NodeType::Integer,
        4 => crate::mib::NodeType::NetworkAddress,
        5 => crate::mib::NodeType::IpAddress,
        6 => crate::mib::NodeType::Counter32,
        7 => crate::mib::NodeType::Gauge32,
        8 => crate::mib::NodeType::TimeTicks,
        9 => crate::mib::NodeType::Opaque,
        10 => crate::mib::NodeType::Null,
        11 => crate::mib::NodeType::Counter64,
        12 => crate::mib::NodeType::Bits,
        13 => crate::mib::NodeType::NsapAddress,
        14 => crate::mib::NodeType::UInteger32,
        15 => crate::mib::NodeType::Unsigned32,
        16 => crate::mib::NodeType::Integer32,
        20 => crate::mib::NodeType::TrapType,
        21 => crate::mib::NodeType::NotificationType,
        22 => crate::mib::NodeType::ObjectGroup,
        23 => crate::mib::NodeType::NotificationGroup,
        24 => crate::mib::NodeType::ModuleIdentity,
        25 => crate::mib::NodeType::AgentCapabilities,
        26 => crate::mib::NodeType::ModuleCompliance,
        27 => crate::mib::NodeType::ObjectIdentity,
        _ => crate::mib::NodeType::Other,
    }
}

unsafe fn cstr(p: *const std::os::raw::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: net-snmp strings are NUL-terminated.
    let s = unsafe { std::ffi::CStr::from_ptr(p) };
    Some(s.to_string_lossy().into_owned())
}

/// Run `f` with fd 2 redirected into a pipe and return what was written.
/// net-snmp reports MIB parse errors only on stderr.
fn capture_stderr<T>(f: impl FnOnce() -> T) -> crate::Result<(T, String)> {
    let mut fds = [0; 2];
    // SAFETY: plain POSIX fd juggling; every fd is closed or restored below.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let saved = libc::dup(2);
        if saved < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        libc::dup2(fds[1], 2);
        libc::close(fds[1]);
        let reader = <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]);
        // The pipe is drained concurrently so a long error list cannot block net-snmp.
        let drain = std::thread::spawn(move || {
            let mut out = String::new();
            let _ = std::io::Read::read_to_string(&mut { reader }, &mut out);
            out
        });
        let result = f();
        libc::dup2(saved, 2);
        libc::close(saved);
        let output = drain.join().unwrap_or_default();
        Ok((result, output))
    }
}

#[cfg(test)]
mod tests {
    fn raw(
        name: &str,
        module: &str,
        kind: crate::mib::NodeType,
        labels: &[&str],
    ) -> crate::mib_dump::RawNode {
        crate::mib_dump::RawNode {
            node: crate::mib::Node {
                name: name.to_owned(),
                module: module.to_owned(),
                kind,
                tc: None,
                format: None,
                hint: None,
                units: None,
                enums: Default::default(),
                objects: vec![],
            },
            varbind_labels: labels.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn tree() -> crate::mib_dump::MibTree {
        let mut tree = crate::mib_dump::MibTree::default();
        let nodes = [
            (
                "1.3.6.1.2.1.2.2.1.1",
                raw("ifIndex", "IF-MIB", crate::mib::NodeType::Integer32, &[]),
            ),
            (
                "1.3.6.1.2.1.2.2.1.8",
                raw("ifOperStatus", "IF-MIB", crate::mib::NodeType::Integer, &[]),
            ),
            (
                "1.3.6.1.2.1.2.2.1.6",
                raw(
                    "ifPhysAddress",
                    "IF-MIB",
                    crate::mib::NodeType::OctetString,
                    &[],
                ),
            ),
            (
                "1.3.6.1.6.3.1.1.5",
                raw("snmpTraps", "SNMPv2-MIB", crate::mib::NodeType::Other, &[]),
            ),
            (
                "1.3.6.1.6.3.1.1.5.3",
                raw(
                    "linkDown",
                    "IF-MIB",
                    crate::mib::NodeType::NotificationType,
                    &["ifIndex", "ifOperStatus"],
                ),
            ),
            (
                "1.3.6.1.6.3.1.1.5.1",
                raw(
                    "coldStart",
                    "SNMPv2-MIB",
                    crate::mib::NodeType::NotificationType,
                    &[],
                ),
            ),
        ];
        for (oid, node) in nodes {
            tree.nodes.insert(crate::mib::parse_oid(oid).unwrap(), node);
        }
        tree
    }

    #[test]
    fn empty_include_exports_notifications_and_their_objects() {
        let out = tree().export(&Default::default()).unwrap();
        let keys: Vec<_> = out.nodes.keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "1.3.6.1.2.1.2.2.1.1",
                "1.3.6.1.2.1.2.2.1.8",
                "1.3.6.1.6.3.1.1.5.1",
                "1.3.6.1.6.3.1.1.5.3",
            ]
        );
        assert_eq!(
            out.nodes["1.3.6.1.6.3.1.1.5.3"].objects,
            vec!["1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.8"]
        );
    }

    #[test]
    fn include_selects_subtree() {
        let config = crate::mib_dump::MibDumpConfig {
            include: vec![
                "IF-MIB::ifPhysAddress".to_owned(),
                "1.3.6.1.6.3.1.1.5".to_owned(),
            ],
            ..Default::default()
        };
        let out = tree().export(&config).unwrap();
        assert!(out.nodes.contains_key("1.3.6.1.2.1.2.2.1.6"));
        assert!(out.nodes.contains_key("1.3.6.1.6.3.1.1.5"));
        assert!(out.nodes.contains_key("1.3.6.1.2.1.2.2.1.1"));
    }

    #[test]
    fn overrides_apply_and_ignore() {
        let config: crate::mib_dump::MibDumpConfig = serde_json::from_str(
            r#"{
                "include": ["ifPhysAddress", "linkDown"],
                "overrides": {
                    "ifPhysAddress": {"type": "PhysAddress48", "name": "mac"},
                    "IF-MIB::ifOperStatus": {"ignore": true}
                }
            }"#,
        )
        .unwrap();
        let out = tree().export(&config).unwrap();
        let mac = &out.nodes["1.3.6.1.2.1.2.2.1.6"];
        assert_eq!(mac.name, "mac");
        assert_eq!(mac.format, Some(crate::mib::ValueFormat::PhysAddress48));
        assert!(!out.nodes.contains_key("1.3.6.1.2.1.2.2.1.8"));
    }

    #[test]
    fn unknown_override_is_an_error() {
        let config: crate::mib_dump::MibDumpConfig =
            serde_json::from_str(r#"{"overrides": {"ifPhysAdress": {"ignore": true}}}"#).unwrap();
        assert!(tree().export(&config).is_err());
    }

    #[test]
    fn unknown_include_is_an_error() {
        let config = crate::mib_dump::MibDumpConfig {
            include: vec!["NOPE-MIB::nothing".to_owned()],
            ..Default::default()
        };
        assert!(tree().export(&config).is_err());
    }
}
