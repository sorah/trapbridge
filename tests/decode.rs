//! Decoding of packets captured from net-snmp's snmptrap and snmpinform.

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}.hex", env!("CARGO_MANIFEST_DIR"));
    hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
}

fn mib() -> std::sync::Arc<trapbridge::mib::MibDatabase> {
    let path = std::path::PathBuf::from(format!(
        "{}/tests/fixtures/mibs.json",
        env!("CARGO_MANIFEST_DIR")
    ));
    std::sync::Arc::new(trapbridge::mib::MibDatabase::load(&[path]).unwrap())
}

fn users(json: &str) -> trapbridge::usm::SecurityStore {
    let users: Vec<trapbridge::config::V3User> = serde_json::from_str(json).unwrap();
    trapbridge::usm::SecurityStore::new(&users).unwrap()
}

fn decoder(
    communities: &[&str],
    usm: trapbridge::usm::SecurityStore,
) -> trapbridge::receiver::Decoder {
    trapbridge::receiver::Decoder::new(communities.iter().map(|s| (*s).to_owned()), usm, mib())
}

fn peer() -> std::net::SocketAddr {
    "192.0.2.1:50000".parse().unwrap()
}

const PINNED_USER: &str = r#"[{"username": "pinned", "engine_id": "80001f8880aabbccdd", "auth_protocol": "sha1", "auth_password": "authpass123", "priv_protocol": "aes128", "priv_password": "privpass123"}]"#;

#[test]
fn v1_enterprise_specific_trap() {
    let decoded = decoder(&["public"], Default::default())
        .decode(&fixture("v1_trap"), peer())
        .unwrap();
    let trap = decoded.trap;
    assert!(decoded.reply.is_none());
    assert_eq!(trap.version, trapbridge::trap::Version::V1);
    assert_eq!(trap.trap.oid, "1.3.6.1.4.1.8072.2.3.0.17");
    let v1 = trap.v1.unwrap();
    assert_eq!(v1.agent_address.to_string(), "192.0.2.10");
    assert_eq!(v1.specific_trap, 17);
    assert_eq!(trap.varbinds[0].oid, "1.3.6.1.2.1.1.5.0");
    assert_eq!(
        trap.varbinds[0].value,
        trapbridge::trap::Value::String("host1".to_owned())
    );
}

#[test]
fn v2c_trap_with_mib_names() {
    let trap = decoder(&[], Default::default())
        .decode(&fixture("v2c_trap"), peer())
        .unwrap()
        .trap;
    assert_eq!(trap.version, trapbridge::trap::Version::V2c);
    assert_eq!(trap.trap.name.as_deref(), Some("IF-MIB::linkDown"));
    assert!(trap.uptime.is_some());
    let names: Vec<_> = trap
        .varbinds
        .iter()
        .map(|v| v.name.as_deref().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "IF-MIB::ifIndex",
            "IF-MIB::ifAdminStatus",
            "IF-MIB::ifOperStatus",
            "IF-MIB::ifPhysAddress"
        ]
    );
    assert_eq!(trap.varbinds[2].value_name.as_deref(), Some("down"));
    assert_eq!(trap.varbinds[2].instance.as_deref(), Some("3"));
    assert_eq!(
        trap.varbinds[3].value,
        trapbridge::trap::Value::String("00:1b:21:aa:bb:cc".to_owned())
    );
}

#[test]
fn v2c_community_must_be_accepted() {
    let err = decoder(&["private"], Default::default())
        .decode(&fixture("v2c_trap"), peer())
        .unwrap_err();
    assert!(err.to_string().contains("community"), "{err}");
    assert_eq!(
        err.drop_reason(),
        trapbridge::metrics::DropReason::Community
    );
}

#[test]
fn v2c_inform_is_acknowledged() {
    let request = fixture("v2c_inform");
    let decoded = decoder(&[], Default::default())
        .decode(&request, peer())
        .unwrap();
    assert_eq!(decoded.trap.pdu_type, trapbridge::trap::PduType::Inform);
    assert_eq!(decoded.trap.trap.name.as_deref(), Some("IF-MIB::linkUp"));
    let reply = decoded.reply.unwrap();
    let response = snmp2::Pdu::from_bytes(&reply).unwrap();
    let inform = snmp2::Pdu::from_bytes(&request).unwrap();
    assert_eq!(response.message_type, snmp2::MessageType::Response);
    assert_eq!(response.req_id, inform.req_id);
    assert_eq!(response.community, b"public");
    assert_eq!(response.varbinds.count(), inform.varbinds.count());
}

#[test]
fn v3_auth_priv_trap_with_pinned_engine_id() {
    let trap = decoder(&[], users(PINNED_USER))
        .decode(&fixture("v3_authpriv_trap"), peer())
        .unwrap()
        .trap;
    assert_eq!(trap.version, trapbridge::trap::Version::V3);
    assert_eq!(trap.trap.name.as_deref(), Some("IF-MIB::linkDown"));
    let v3 = trap.v3.unwrap();
    assert_eq!(v3.username, "pinned");
    assert_eq!(v3.engine_id, "80001f8880aabbccdd");
}

#[test]
fn v3_trap_with_learned_engine_id() {
    let decoder = decoder(
        &[],
        users(
            r#"[{"username": "pinned", "auth_protocol": "sha1", "auth_password": "authpass123", "priv_protocol": "aes128", "priv_password": "privpass123"}]"#,
        ),
    );
    for _ in 0..2 {
        decoder
            .decode(&fixture("v3_authpriv_trap"), peer())
            .unwrap();
    }
}

#[test]
fn v3_wrong_password_is_rejected() {
    let err = decoder(
        &[],
        users(r#"[{"username": "pinned", "engine_id": "80001f8880aabbccdd", "auth_protocol": "sha1", "auth_password": "wrongpass99", "priv_protocol": "aes128", "priv_password": "privpass123"}]"#),
    )
    .decode(&fixture("v3_authpriv_trap"), peer())
    .unwrap_err();
    assert!(err.to_string().contains("HMAC"), "{err}");
    assert_eq!(err.drop_reason(), trapbridge::metrics::DropReason::Usm);
}

#[test]
fn v3_unknown_user_is_rejected() {
    let err = decoder(&[], Default::default())
        .decode(&fixture("v3_authpriv_trap"), peer())
        .unwrap_err();
    assert!(err.to_string().contains("unknown SNMPv3 user"), "{err}");
    assert_eq!(err.drop_reason(), trapbridge::metrics::DropReason::Usm);
}

#[test]
fn garbage_is_rejected() {
    let err = decoder(&[], Default::default())
        .decode(b"\x30\x03\x02\x01", peer())
        .unwrap_err();
    assert_eq!(err.drop_reason(), trapbridge::metrics::DropReason::Parse);
}

#[test]
fn unknown_snmp_version_is_unsupported() {
    let err = decoder(&[], Default::default())
        .decode(b"\x30\x03\x02\x01\x02", peer())
        .unwrap_err();
    assert_eq!(
        err.drop_reason(),
        trapbridge::metrics::DropReason::Unsupported
    );
}
