//! Server configuration loaded from the `--config` JSON file. Scalar options
//! are CLI flags; this file holds what does not fit on a command line.

/// Contents of the `--config` file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Accepted SNMPv1/v2c communities, merged with `--community`. When both
    /// are empty, any community is accepted.
    #[serde(default)]
    pub communities: Vec<String>,
    /// SNMPv3 USM users.
    #[serde(default)]
    pub v3_users: Vec<V3User>,
}

/// An SNMPv3 USM user.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3User {
    pub username: String,
    /// Authoritative (sender) engine ID in hex. When omitted, the user is
    /// accepted from any engine ID and keys are localized per engine on demand.
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub auth_protocol: Option<AuthProtocol>,
    #[serde(default)]
    pub auth_password: Option<String>,
    #[serde(default)]
    pub priv_protocol: Option<PrivProtocol>,
    #[serde(default)]
    pub priv_password: Option<String>,
    /// Key extension for AES-192/256 with short-digest auth protocols.
    #[serde(default)]
    pub key_extension: Option<KeyExtension>,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProtocol {
    Md5,
    #[serde(alias = "sha")]
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivProtocol {
    Des,
    #[serde(alias = "aes")]
    Aes128,
    Aes192,
    Aes256,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyExtension {
    Blumenthal,
    Reeder,
}

impl Config {
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| crate::Error::Config(format!("failed to open {}: {e}", path.display())))?;
        let config: Config =
            serde_json::from_reader(std::io::BufReader::new(file)).map_err(|e| {
                crate::Error::Config(format!("failed to parse {}: {e}", path.display()))
            })?;
        for user in &config.v3_users {
            user.validate()?;
        }
        Ok(config)
    }
}

impl V3User {
    pub fn validate(&self) -> crate::Result<()> {
        let err = |msg: &str| {
            Err(crate::Error::Config(format!(
                "v3_users[{:?}]: {msg}",
                self.username
            )))
        };
        if self.auth_protocol.is_some() != self.auth_password.is_some() {
            return err("auth_protocol and auth_password must be set together");
        }
        if self.priv_protocol.is_some() != self.priv_password.is_some() {
            return err("priv_protocol and priv_password must be set together");
        }
        if self.priv_protocol.is_some() && self.auth_protocol.is_none() {
            return err("privacy requires authentication");
        }
        if let Some(Err(e)) = self.engine_id_bytes() {
            return err(&format!("invalid engine_id: {e}"));
        }
        Ok(())
    }

    /// Decoded `engine_id`; a leading `0x` is accepted.
    pub fn engine_id_bytes(&self) -> Option<Result<Vec<u8>, hex::FromHexError>> {
        self.engine_id.as_deref().map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(s)
        })
    }

    /// Build an snmp2 security context without an engine ID.
    pub fn to_security(&self) -> snmp2::v3::Security {
        let auth_password = self.auth_password.as_deref().unwrap_or_default();
        let mut security =
            snmp2::v3::Security::new(self.username.as_bytes(), auth_password.as_bytes());
        security = match (&self.auth_protocol, &self.priv_protocol) {
            (None, _) => security.with_auth(snmp2::v3::Auth::NoAuthNoPriv),
            (Some(_), None) => security.with_auth(snmp2::v3::Auth::AuthNoPriv),
            (Some(_), Some(cipher)) => security.with_auth(snmp2::v3::Auth::AuthPriv {
                cipher: snmp2::v3::Cipher::from(*cipher),
                privacy_password: self.priv_password.clone().unwrap_or_default().into_bytes(),
            }),
        };
        if let Some(proto) = self.auth_protocol {
            security = security.with_auth_protocol(snmp2::v3::AuthProtocol::from(proto));
        }
        if let Some(ext) = self.key_extension {
            security = security.with_key_extension_method(snmp2::v3::KeyExtension::from(ext));
        }
        security
    }
}

impl From<AuthProtocol> for snmp2::v3::AuthProtocol {
    fn from(p: AuthProtocol) -> Self {
        match p {
            AuthProtocol::Md5 => snmp2::v3::AuthProtocol::Md5,
            AuthProtocol::Sha1 => snmp2::v3::AuthProtocol::Sha1,
            AuthProtocol::Sha224 => snmp2::v3::AuthProtocol::Sha224,
            AuthProtocol::Sha256 => snmp2::v3::AuthProtocol::Sha256,
            AuthProtocol::Sha384 => snmp2::v3::AuthProtocol::Sha384,
            AuthProtocol::Sha512 => snmp2::v3::AuthProtocol::Sha512,
        }
    }
}

impl From<PrivProtocol> for snmp2::v3::Cipher {
    fn from(p: PrivProtocol) -> Self {
        match p {
            PrivProtocol::Des => snmp2::v3::Cipher::Des,
            PrivProtocol::Aes128 => snmp2::v3::Cipher::Aes128,
            PrivProtocol::Aes192 => snmp2::v3::Cipher::Aes192,
            PrivProtocol::Aes256 => snmp2::v3::Cipher::Aes256,
        }
    }
}

impl From<KeyExtension> for snmp2::v3::KeyExtension {
    fn from(k: KeyExtension) -> Self {
        match k {
            KeyExtension::Blumenthal => snmp2::v3::KeyExtension::Blumenthal,
            KeyExtension::Reeder => snmp2::v3::KeyExtension::Reeder,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_full_config() {
        let config: crate::config::Config = serde_json::from_str(
            r#"{
                "communities": ["public"],
                "v3_users": [
                    {"username": "a", "engine_id": "0x8000000001020304", "auth_protocol": "sha", "auth_password": "authpass", "priv_protocol": "aes", "priv_password": "privpass"},
                    {"username": "b"}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(config.communities, vec!["public"]);
        assert_eq!(
            config.v3_users[0].engine_id_bytes().unwrap().unwrap(),
            vec![0x80, 0, 0, 0, 1, 2, 3, 4]
        );
        for user in &config.v3_users {
            user.validate().unwrap();
        }
    }

    #[test]
    fn rejects_priv_without_auth() {
        let user: crate::config::V3User = serde_json::from_str(
            r#"{"username": "a", "priv_protocol": "des", "priv_password": "privpass"}"#,
        )
        .unwrap();
        assert!(user.validate().is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(serde_json::from_str::<crate::config::Config>(r#"{"comunities": []}"#).is_err());
    }
}
