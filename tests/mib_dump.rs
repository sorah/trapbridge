//! Loading MIBs through net-snmp. net-snmp state is global, so this file holds a single test.
#![cfg(feature = "mibs")]

#[test]
fn smiv1_traps_are_exported_as_traps() {
    let dir = format!("{}/tests/fixtures/mib-dump", env!("CARGO_MANIFEST_DIR"));
    let tree = trapbridge::mib_dump::MibTree::load(&[dir], &["TEST-TRAP-MIB".to_owned()]).unwrap();
    assert_eq!(tree.parse_errors, Vec::<String>::new());
    assert!(tree.nodes.values().all(|raw| !raw.node.name.ends_with('#')));
    assert_eq!(
        tree.nodes[&vec![1, 3, 6, 1, 4, 1, 99999, 0]].node.name,
        "testTraps"
    );

    let out = tree.export(&Default::default()).unwrap();
    let a = &out.nodes["1.3.6.1.4.1.99999.0.1"];
    assert_eq!(a.name, "testTrapA");
    assert_eq!(a.kind, trapbridge::mib::NodeType::TrapType);
    assert_eq!(a.objects, vec!["1.3.6.1.4.1.99999.1".to_owned()]);
    assert_eq!(
        out.nodes["1.3.6.1.4.1.99999.0.2"].kind,
        trapbridge::mib::NodeType::TrapType
    );
    assert!(!out.nodes.contains_key("1.3.6.1.4.1.99999.0"));
}
