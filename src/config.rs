//! Configuration loading and static validation.
//!
//! Validation is offline: it never performs DNS lookups or inspects kernel state, so a
//! configuration that passes here may still fail to converge at runtime.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::Deserialize;

/// Default location of the configuration file.
pub const DEFAULT_PATH: &str = "/etc/gre-controller/config.toml";

/// Linux `IFNAMSIZ`, including the terminating NUL byte.
const IFNAMSIZ: usize = 16;

/// A validated configuration snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub tunnels: BTreeMap<InterfaceName, Tunnel>,
}

/// A validated tunnel definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub family: Family,
    pub local: Endpoint,
    pub remote: Endpoint,
    /// Overlay addresses with their host bits preserved, in declaration order.
    pub addresses: Vec<IpNet>,
}

/// Underlay address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Family::Ipv4, IpAddr::V4(_)) | (Family::Ipv6, IpAddr::V6(_))
        )
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        })
    }
}

/// An underlay endpoint as declared in the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Address(IpAddr),
    Name(DnsName),
}

/// A syntactically valid DNS name. Whether it resolves is only known at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(name: &str) -> Option<Self> {
        is_valid_dns_name(name).then(|| Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Linux interface name accepted for managed tunnels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn new(name: &str) -> Result<Self, InterfaceNameError> {
        if name.is_empty() {
            return Err(InterfaceNameError::Empty);
        }
        // Mirrors the kernel's `dev_valid_name()`: `/`, `:` and C `isspace()` characters
        // are rejected. `%` is additionally rejected because the kernel would treat the name
        // as a template such as `gre%d`, and NUL because it would truncate the name.
        if let Some(c) = name.chars().find(|&c| {
            matches!(
                c,
                '/' | ':' | '%' | '\0' | ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r'
            )
        }) {
            return Err(InterfaceNameError::InvalidCharacter(c));
        }
        if name.len() >= IFNAMSIZ {
            return Err(InterfaceNameError::TooLong);
        }
        if name == "." || name == ".." {
            return Err(InterfaceNameError::Reserved);
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceNameError {
    Empty,
    TooLong,
    InvalidCharacter(char),
    Reserved,
}

impl fmt::Display for InterfaceNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("interface name is empty"),
            Self::TooLong => write!(f, "interface name is longer than {} bytes", IFNAMSIZ - 1),
            Self::InvalidCharacter(c) => {
                write!(f, "interface name contains invalid character {c:?}")
            }
            Self::Reserved => f.write_str("interface name is reserved"),
        }
    }
}

/// Error returned when a configuration snapshot cannot be used.
///
/// Every variant means "no usable configuration"; none of them may be interpreted as an
/// empty set of tunnels.
#[derive(Debug)]
pub enum ConfigError {
    Read { path: PathBuf, source: io::Error },
    Parse(toml::de::Error),
    Invalid(Vec<ValidationError>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Self::Parse(err) => write!(f, "cannot parse configuration: {err}"),
            Self::Invalid(errors) => {
                f.write_str("invalid configuration:")?;
                for error in errors {
                    write!(f, "\n  {error}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse(err) => Some(err),
            Self::Invalid(_) => None,
        }
    }
}

/// A validation failure within a single tunnel definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// The tunnel's key as written in the configuration.
    pub tunnel: String,
    pub issue: Issue,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tunnels.{:?}: {}", self.tunnel, self.issue)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    InterfaceName(InterfaceNameError),
    InvalidEndpoint {
        field: &'static str,
        value: String,
    },
    UnspecifiedEndpoint {
        field: &'static str,
    },
    EndpointFamilyMismatch {
        field: &'static str,
        address: IpAddr,
        family: Family,
    },
    NoAddresses,
    InvalidAddress {
        value: String,
    },
    UnusableAddress {
        address: IpNet,
    },
    DuplicateAddress {
        address: IpAddr,
    },
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceName(err) => write!(f, "{err}"),
            Self::InvalidEndpoint { field, value } => write!(
                f,
                "`{field}` is neither an IP address nor a valid DNS name: {value:?}"
            ),
            Self::UnspecifiedEndpoint { field } => {
                write!(f, "`{field}` must not be an unspecified address")
            }
            Self::EndpointFamilyMismatch {
                field,
                address,
                family,
            } => write!(
                f,
                "`{field}` address {address} does not match family {family}"
            ),
            Self::NoAddresses => f.write_str("`addresses` must not be empty"),
            Self::InvalidAddress { value } => write!(
                f,
                "`addresses` entry is not an address in CIDR notation: {value:?}"
            ),
            Self::UnusableAddress { address } => write!(
                f,
                "`addresses` entry {address} is an unspecified or multicast address"
            ),
            Self::DuplicateAddress { address } => {
                write!(f, "`addresses` contains {address} more than once")
            }
        }
    }
}

/// Reads and validates the configuration file at `path`.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text)
}

/// Parses and validates configuration text.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(ConfigError::Parse)?;

    let mut tunnels = BTreeMap::new();
    let mut errors = Vec::new();
    for (key, raw_tunnel) in raw.tunnels {
        let mut issues = Vec::new();
        let name = InterfaceName::new(&key)
            .map_err(|err| issues.push(Issue::InterfaceName(err)))
            .ok();
        let tunnel = raw_tunnel.validate(&mut issues);
        match (name, tunnel) {
            (Some(name), Some(tunnel)) if issues.is_empty() => {
                tunnels.insert(name, tunnel);
            }
            _ => errors.extend(issues.into_iter().map(|issue| ValidationError {
                tunnel: key.clone(),
                issue,
            })),
        }
    }

    if errors.is_empty() {
        Ok(Config { tunnels })
    } else {
        Err(ConfigError::Invalid(errors))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    // Required: a blank file must not be mistaken for "delete every tunnel".
    tunnels: BTreeMap<String, RawTunnel>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunnel {
    family: Family,
    local: String,
    remote: String,
    addresses: Vec<String>,
}

impl RawTunnel {
    /// Returns the validated tunnel, or `None` after recording at least one issue.
    fn validate(self, issues: &mut Vec<Issue>) -> Option<Tunnel> {
        let before = issues.len();
        let local = validate_endpoint("local", &self.local, self.family, issues);
        let remote = validate_endpoint("remote", &self.remote, self.family, issues);
        let addresses = validate_addresses(&self.addresses, issues);
        if issues.len() > before {
            return None;
        }
        Some(Tunnel {
            family: self.family,
            local: local?,
            remote: remote?,
            addresses,
        })
    }
}

fn validate_endpoint(
    field: &'static str,
    value: &str,
    family: Family,
    issues: &mut Vec<Issue>,
) -> Option<Endpoint> {
    if let Ok(address) = value.parse::<IpAddr>() {
        if !family.matches(address) {
            issues.push(Issue::EndpointFamilyMismatch {
                field,
                address,
                family,
            });
            return None;
        }
        if address.is_unspecified() {
            issues.push(Issue::UnspecifiedEndpoint { field });
            return None;
        }
        return Some(Endpoint::Address(address));
    }
    match DnsName::new(value) {
        Some(name) => Some(Endpoint::Name(name)),
        None => {
            issues.push(Issue::InvalidEndpoint {
                field,
                value: value.to_owned(),
            });
            None
        }
    }
}

fn validate_addresses(values: &[String], issues: &mut Vec<Issue>) -> Vec<IpNet> {
    if values.is_empty() {
        issues.push(Issue::NoAddresses);
        return Vec::new();
    }
    let mut addresses: Vec<IpNet> = Vec::with_capacity(values.len());
    for value in values {
        let Ok(address) = value.parse::<IpNet>() else {
            issues.push(Issue::InvalidAddress {
                value: value.clone(),
            });
            continue;
        };
        let ip = address.addr();
        if ip.is_unspecified() || ip.is_multicast() {
            issues.push(Issue::UnusableAddress { address });
        } else if addresses.iter().any(|existing| existing.addr() == ip) {
            // The same address with a different prefix length is still a duplicate.
            issues.push(Issue::DuplicateAddress { address: ip });
        } else {
            addresses.push(address);
        }
    }
    addresses
}

fn is_valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let labels_valid = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    // An all-numeric final label (e.g. "10.0.1") could be read as a legacy IPv4
    // literal by the resolver.
    let last_label_numeric = labels
        .last()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()));
    labels_valid && !last_label_numeric
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel_toml(name: &str, family: &str, local: &str, remote: &str, addresses: &str) -> String {
        format!(
            "[tunnels.{name}]\nfamily = \"{family}\"\nlocal = \"{local}\"\nremote = \"{remote}\"\naddresses = {addresses}\n"
        )
    }

    fn issues(text: &str) -> Vec<Issue> {
        match parse(text) {
            Err(ConfigError::Invalid(errors)) => errors.into_iter().map(|e| e.issue).collect(),
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    fn assert_parse_error(text: &str) {
        match parse(text) {
            Err(ConfigError::Parse(_)) => {}
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    fn name(s: &str) -> InterfaceName {
        InterfaceName::new(s).unwrap()
    }

    #[test]
    fn parses_documented_examples() {
        let text = r#"
            [tunnels.gre-peer01]
            family = "ipv6"
            local = "my-gateway.example.com"
            remote = "peer-gateway.example.com"
            addresses = ["10.0.1.1/31"]

            [tunnels.gre-peer02]
            family = "ipv6"
            local = "my-gateway.example.com"
            remote = "2001:db8:2::1"
            addresses = ["10.0.2.0/31", "fd00:2::1/127"]
        "#;
        let config = parse(text).unwrap();
        assert_eq!(config.tunnels.len(), 2);

        let peer01 = &config.tunnels[&name("gre-peer01")];
        assert_eq!(peer01.family, Family::Ipv6);
        assert_eq!(
            peer01.local,
            Endpoint::Name(DnsName::new("my-gateway.example.com").unwrap())
        );
        assert_eq!(peer01.addresses, vec!["10.0.1.1/31".parse().unwrap()]);

        let peer02 = &config.tunnels[&name("gre-peer02")];
        assert_eq!(
            peer02.remote,
            Endpoint::Address("2001:db8:2::1".parse().unwrap())
        );
        assert_eq!(peer02.addresses.len(), 2);
    }

    #[test]
    fn preserves_host_bits() {
        let config = parse(&tunnel_toml(
            "gre1",
            "ipv4",
            "192.0.2.1",
            "198.51.100.1",
            r#"["10.0.0.5/24"]"#,
        ))
        .unwrap();
        let address = config.tunnels[&name("gre1")].addresses[0];
        assert_eq!(address.addr(), "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(address.prefix_len(), 24);
    }

    #[test]
    fn explicit_empty_tunnels_table_is_valid() {
        let config = parse("[tunnels]\n").unwrap();
        assert!(config.tunnels.is_empty());
    }

    #[test]
    fn missing_tunnels_table_is_rejected() {
        assert_parse_error("");
        assert_parse_error("   \n\n");
        assert_parse_error("# [tunnels]\n");
    }

    #[test]
    fn rejects_unknown_fields() {
        assert_parse_error("[tunnels]\n[extra]\n");
        assert_parse_error(&format!(
            "{}mtu = 1400\n",
            tunnel_toml(
                "gre1",
                "ipv4",
                "192.0.2.1",
                "198.51.100.1",
                r#"["10.0.0.1/31"]"#
            )
        ));
    }

    #[test]
    fn rejects_missing_fields() {
        assert_parse_error(
            "[tunnels.gre1]\nfamily = \"ipv4\"\nlocal = \"192.0.2.1\"\naddresses = [\"10.0.0.1/31\"]\n",
        );
    }

    #[test]
    fn rejects_unknown_family() {
        assert_parse_error(&tunnel_toml(
            "gre1",
            "inet",
            "192.0.2.1",
            "198.51.100.1",
            r#"["10.0.0.1/31"]"#,
        ));
    }

    #[test]
    fn rejects_duplicate_tables() {
        let tunnel = tunnel_toml(
            "gre1",
            "ipv4",
            "192.0.2.1",
            "198.51.100.1",
            r#"["10.0.0.1/31"]"#,
        );
        assert_parse_error(&format!("{tunnel}{tunnel}"));
    }

    #[test]
    fn rejects_literal_endpoint_family_mismatch() {
        let found = issues(&tunnel_toml(
            "gre1",
            "ipv4",
            "2001:db8::1",
            "198.51.100.1",
            r#"["10.0.0.1/31"]"#,
        ));
        assert_eq!(
            found,
            vec![Issue::EndpointFamilyMismatch {
                field: "local",
                address: "2001:db8::1".parse().unwrap(),
                family: Family::Ipv4,
            }]
        );

        let found = issues(&tunnel_toml(
            "gre1",
            "ipv6",
            "2001:db8::1",
            "198.51.100.1",
            r#"["10.0.0.1/31"]"#,
        ));
        assert!(matches!(
            found.as_slice(),
            [Issue::EndpointFamilyMismatch {
                field: "remote",
                ..
            }]
        ));
    }

    #[test]
    fn rejects_unspecified_endpoint() {
        let found = issues(&tunnel_toml(
            "gre1",
            "ipv6",
            "::",
            "2001:db8::2",
            r#"["10.0.0.1/31"]"#,
        ));
        assert_eq!(found, vec![Issue::UnspecifiedEndpoint { field: "local" }]);
    }

    #[test]
    fn rejects_invalid_endpoint_names() {
        for value in [
            "",
            ".",
            "-peer.example.com",
            "peer-.example.com",
            "peer..example.com",
            "peer_gw.example.com",
            "10.0.1",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.0.2.1:4754",
        ] {
            let found = issues(&tunnel_toml(
                "gre1",
                "ipv4",
                value,
                "198.51.100.1",
                r#"["10.0.0.1/31"]"#,
            ));
            assert!(
                matches!(
                    found.as_slice(),
                    [Issue::InvalidEndpoint { field: "local", .. }]
                ),
                "{value:?} was not rejected: {found:?}"
            );
        }
    }

    #[test]
    fn dns_name_syntax() {
        for valid in [
            "localhost",
            "peer.example.com",
            "peer.example.com.",
            "1peer.example",
            "xn--bcher-kva.example",
        ] {
            assert!(DnsName::new(valid).is_some(), "{valid:?} was rejected");
        }

        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = ["a".repeat(63).as_str(); 4].join(".") + ".example";
        for invalid in [
            long_label.as_str(),
            long_name.as_str(),
            "peer.123",
            "peer example",
        ] {
            assert!(DnsName::new(invalid).is_none(), "{invalid:?} was accepted");
        }
    }

    #[test]
    fn rejects_invalid_cidr() {
        for value in [
            "10.0.0.1",
            "10.0.0.1/33",
            "2001:db8::1/129",
            "peer.example/31",
        ] {
            let found = issues(&tunnel_toml(
                "gre1",
                "ipv4",
                "192.0.2.1",
                "198.51.100.1",
                &format!("[\"{value}\"]"),
            ));
            assert_eq!(
                found,
                vec![Issue::InvalidAddress {
                    value: value.to_owned()
                }]
            );
        }
    }

    #[test]
    fn rejects_empty_address_list() {
        let found = issues(&tunnel_toml(
            "gre1",
            "ipv4",
            "192.0.2.1",
            "198.51.100.1",
            "[]",
        ));
        assert_eq!(found, vec![Issue::NoAddresses]);
    }

    #[test]
    fn rejects_unusable_addresses() {
        for value in ["0.0.0.0/0", "::/0", "224.0.0.1/32", "ff02::1/128"] {
            let found = issues(&tunnel_toml(
                "gre1",
                "ipv4",
                "192.0.2.1",
                "198.51.100.1",
                &format!("[\"{value}\"]"),
            ));
            assert!(
                matches!(found.as_slice(), [Issue::UnusableAddress { .. }]),
                "{value:?} was not rejected: {found:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_addresses() {
        let found = issues(&tunnel_toml(
            "gre1",
            "ipv4",
            "192.0.2.1",
            "198.51.100.1",
            r#"["10.0.0.1/31", "10.0.0.1/24", "fd00::1/64", "fd00:0::1/127"]"#,
        ));
        assert_eq!(
            found,
            vec![
                Issue::DuplicateAddress {
                    address: "10.0.0.1".parse().unwrap()
                },
                Issue::DuplicateAddress {
                    address: "fd00::1".parse().unwrap()
                },
            ]
        );
    }

    #[test]
    fn interface_name_rules() {
        // Names the kernel accepts are not restricted further for now.
        for valid in [
            "gre-peer01",
            "gre.100",
            "gre_x",
            "abcdefghijklmno",
            "gré",
            "gre0",
            "all",
        ] {
            assert!(InterfaceName::new(valid).is_ok(), "{valid:?} was rejected");
        }

        assert_eq!(InterfaceName::new(""), Err(InterfaceNameError::Empty));
        assert_eq!(
            InterfaceName::new("abcdefghijklmnop"),
            Err(InterfaceNameError::TooLong)
        );
        for (invalid, c) in [
            ("gre/1", '/'),
            ("gre 1", ' '),
            ("gre:1", ':'),
            ("gre%d", '%'),
            ("gre\0", '\0'),
            ("gre\t1", '\t'),
            ("gre\x0b1", '\x0b'),
        ] {
            assert_eq!(
                InterfaceName::new(invalid),
                Err(InterfaceNameError::InvalidCharacter(c))
            );
        }
        // Multi-byte characters count by their UTF-8 length, as in the kernel.
        assert_eq!(
            InterfaceName::new("éééééééé"),
            Err(InterfaceNameError::TooLong)
        );
        for reserved in [".", ".."] {
            assert_eq!(
                InterfaceName::new(reserved),
                Err(InterfaceNameError::Reserved)
            );
        }
    }

    #[test]
    fn rejects_invalid_interface_name_key() {
        let found = issues(&tunnel_toml(
            "\"..\"",
            "ipv4",
            "192.0.2.1",
            "198.51.100.1",
            r#"["10.0.0.1/31"]"#,
        ));
        assert_eq!(
            found,
            vec![Issue::InterfaceName(InterfaceNameError::Reserved)]
        );

        let found = issues(&tunnel_toml(
            "\"gre 1\"",
            "ipv4",
            "192.0.2.1",
            "198.51.100.1",
            r#"["10.0.0.1/31"]"#,
        ));
        assert_eq!(
            found,
            vec![Issue::InterfaceName(InterfaceNameError::InvalidCharacter(
                ' '
            ))]
        );
    }

    #[test]
    fn reports_every_invalid_tunnel() {
        let text = tunnel_toml("gre1", "ipv4", "2001:db8::1", "198.51.100.1", "[]")
            + &tunnel_toml(
                "gre2",
                "ipv4",
                "192.0.2.1",
                "198.51.100.1",
                r#"["10.0.0.1/31"]"#,
            )
            + &tunnel_toml(
                "\"gre/3\"",
                "ipv4",
                "192.0.2.1",
                "198.51.100.1",
                r#"["bad"]"#,
            );
        let Err(ConfigError::Invalid(errors)) = parse(&text) else {
            panic!("expected a validation error");
        };
        let found: Vec<(&str, &Issue)> = errors
            .iter()
            .map(|e| (e.tunnel.as_str(), &e.issue))
            .collect();
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(found.iter().all(|(tunnel, _)| *tunnel != "gre2"));
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let err = load(Path::new("/nonexistent/gre-controller/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
