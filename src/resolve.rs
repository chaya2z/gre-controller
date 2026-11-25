//! Endpoint resolution.
//!
//! Turns the configured endpoints of each tunnel into single underlay addresses. Literal
//! addresses are used as they are; DNS names are looked up through a [`Resolver`]. The
//! selection rules are pure, so they are tested with a fake resolver.
//!
//! A tunnel resolves only if both endpoints resolve. Otherwise the reasons are returned,
//! and the tunnel must be passed to [`plan`](crate::plan::plan) as
//! [`DesiredTunnel::Unresolved`](crate::plan::DesiredTunnel::Unresolved), which leaves its
//! interface untouched for the pass.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::config::{Config, DnsName, Endpoint, Family, InterfaceName};
use crate::plan::{Endpoints, ObservedLink, TunnelSpec};

/// Looks up the addresses of a DNS name.
pub trait Resolver {
    /// Returns every address the name resolves to, in any family and possibly with
    /// duplicates. The caller filters them.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails, for example because the name does not
    /// exist or no name server answered.
    fn lookup(&self, name: &DnsName) -> io::Result<Vec<IpAddr>>;
}

/// Resolves names with the host's resolver (`getaddrinfo(3)`), so `/etc/hosts`,
/// `nsswitch.conf` and the system's DNS configuration apply. Blocks the calling thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup(&self, name: &DnsName) -> io::Result<Vec<IpAddr>> {
        // The port is required by the API and irrelevant here.
        let addresses = (name.as_str(), 0).to_socket_addrs()?;
        Ok(addresses.map(|address| address.ip()).collect())
    }
}

/// Resolves the endpoints of every configured tunnel.
///
/// - `observed` is the kernel snapshot. An owned interface's current endpoints are kept
///   while they remain eligible, so the controller does not switch between several valid
///   candidates.
/// - `host_addresses` are all addresses assigned to the host. The local endpoint must be
///   one of them.
///
/// Each DNS name is looked up once per call, even if several tunnels use it.
#[must_use]
pub fn resolve(
    config: &Config,
    observed: &BTreeMap<InterfaceName, ObservedLink>,
    host_addresses: &BTreeSet<IpAddr>,
    resolver: &impl Resolver,
) -> BTreeMap<InterfaceName, Result<TunnelSpec, Unresolved>> {
    let mut lookups = BTreeMap::new();
    for endpoint in config
        .tunnels
        .values()
        .flat_map(|tunnel| [&tunnel.local, &tunnel.remote])
    {
        if let Endpoint::Name(name) = endpoint {
            lookups
                .entry(name.as_str())
                .or_insert_with(|| resolver.lookup(name).map_err(Arc::new));
        }
    }

    config
        .tunnels
        .iter()
        .map(|(name, tunnel)| {
            let current = observed
                .get(name)
                .and_then(ObservedLink::owned_endpoints)
                .filter(|&(family, _)| family == tunnel.family)
                .map(|(_, endpoints)| endpoints);
            let local = resolve_endpoint(
                &tunnel.local,
                tunnel.family,
                Some(host_addresses),
                current.map(|endpoints| endpoints.local),
                &lookups,
            );
            let remote = resolve_endpoint(
                &tunnel.remote,
                tunnel.family,
                None,
                current.map(|endpoints| endpoints.remote),
                &lookups,
            );
            let result = match (local, remote) {
                (Ok(local), Ok(remote)) => Ok(TunnelSpec {
                    family: tunnel.family,
                    endpoints: Endpoints { local, remote },
                    addresses: tunnel.addresses.clone(),
                }),
                (local, remote) => Err(Unresolved(
                    [(Side::Local, local), (Side::Remote, remote)]
                        .into_iter()
                        .filter_map(|(side, result)| {
                            Some(EndpointError {
                                side,
                                reason: result.err()?,
                            })
                        })
                        .collect(),
                )),
            };
            (name.clone(), result)
        })
        .collect()
}

type Lookups<'a> = BTreeMap<&'a str, Result<Vec<IpAddr>, Arc<io::Error>>>;

/// Selects the address of one endpoint.
///
/// `assigned` restricts the candidates to addresses assigned to the host (local endpoint).
fn resolve_endpoint(
    endpoint: &Endpoint,
    family: Family,
    assigned: Option<&BTreeSet<IpAddr>>,
    current: Option<IpAddr>,
    lookups: &Lookups<'_>,
) -> Result<IpAddr, Reason> {
    let candidates: BTreeSet<IpAddr> = match endpoint {
        // Validation already checked the family of literal addresses.
        Endpoint::Address(address) => BTreeSet::from([*address]),
        Endpoint::Name(name) => {
            let addresses = lookups[name.as_str()]
                .as_ref()
                .map_err(|error| Reason::Lookup {
                    name: name.clone(),
                    error: Arc::clone(error),
                })?;
            let eligible: BTreeSet<IpAddr> = addresses
                .iter()
                .copied()
                .filter(|&address| family.matches(address) && !address.is_unspecified())
                .collect();
            if eligible.is_empty() {
                return Err(Reason::NoAddress {
                    name: name.clone(),
                    family,
                });
            }
            eligible
        }
    };

    let candidates = match assigned {
        Some(assigned) => {
            let usable: BTreeSet<IpAddr> = candidates.intersection(assigned).copied().collect();
            if usable.is_empty() {
                return Err(Reason::NotAssigned(candidates.into_iter().collect()));
            }
            usable
        }
        None => candidates,
    };

    if let Some(current) = current
        && candidates.contains(&current)
    {
        return Ok(current);
    }
    let mut iter = candidates.iter().copied();
    match (iter.next(), iter.next()) {
        (Some(address), None) => Ok(address),
        _ => Err(Reason::Ambiguous(candidates.into_iter().collect())),
    }
}

/// Why a tunnel's endpoints could not be resolved. Holds at least one error.
#[derive(Debug, Clone)]
pub struct Unresolved(pub Vec<EndpointError>);

impl fmt::Display for Unresolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, error) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Unresolved {}

/// Which endpoint of a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Local => "local",
            Self::Remote => "remote",
        })
    }
}

/// An endpoint that could not be resolved to a single usable address.
#[derive(Debug, Clone)]
pub struct EndpointError {
    pub side: Side,
    pub reason: Reason,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` {}", self.side, self.reason)
    }
}

impl std::error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.reason {
            Reason::Lookup { error, .. } => Some(error.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Reason {
    /// The name lookup failed.
    Lookup {
        name: DnsName,
        error: Arc<io::Error>,
    },
    /// The name resolved, but to no usable address of the tunnel's family.
    NoAddress { name: DnsName, family: Family },
    /// None of the candidates is assigned to the host (local endpoint only).
    NotAssigned(Vec<IpAddr>),
    /// Several candidates remain and none of them is the current endpoint.
    Ambiguous(Vec<IpAddr>),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup { name, error } => {
                write!(f, "cannot resolve {}: {error}", name.as_str())
            }
            Self::NoAddress { name, family } => {
                write!(f, "{} has no usable {family} address", name.as_str())
            }
            Self::NotAssigned(candidates) => {
                write!(
                    f,
                    "is not assigned to this host: {}",
                    AddressList(candidates)
                )
            }
            Self::Ambiguous(candidates) => {
                write!(f, "has several candidates: {}", AddressList(candidates))
            }
        }
    }
}

struct AddressList<'a>(&'a [IpAddr]);

impl fmt::Display for AddressList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, address) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{address}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::config;
    use crate::plan::{LinkKind, OWNER_ALIAS};

    /// Answers lookups from a table and records every lookup.
    #[derive(Default)]
    struct FakeResolver {
        answers: BTreeMap<&'static str, Vec<&'static str>>,
        lookups: RefCell<Vec<String>>,
    }

    impl FakeResolver {
        fn new(answers: &[(&'static str, &[&'static str])]) -> Self {
            Self {
                answers: answers
                    .iter()
                    .map(|&(name, addresses)| (name, addresses.to_vec()))
                    .collect(),
                ..Self::default()
            }
        }
    }

    impl Resolver for FakeResolver {
        fn lookup(&self, name: &DnsName) -> io::Result<Vec<IpAddr>> {
            self.lookups.borrow_mut().push(name.as_str().to_owned());
            let addresses = self
                .answers
                .get(name.as_str())
                .ok_or_else(|| io::Error::other("name not found"))?;
            Ok(addresses.iter().map(|a| a.parse().unwrap()).collect())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ips(addresses: &[&str]) -> Vec<IpAddr> {
        addresses.iter().copied().map(ip).collect()
    }

    fn name(s: &str) -> InterfaceName {
        InterfaceName::new(s).unwrap()
    }

    fn tunnel(name: &str, family: &str, local: &str, remote: &str) -> String {
        format!(
            "[tunnels.{name}]\nfamily = \"{family}\"\nlocal = \"{local}\"\nremote = \"{remote}\"\naddresses = [\"10.0.0.1/31\"]\n"
        )
    }

    const HOST_V4: &str = "192.0.2.1";
    const HOST_V6: &str = "2001:db8:1::1";

    fn host() -> BTreeSet<IpAddr> {
        BTreeSet::from([ip(HOST_V4), ip(HOST_V6), ip("127.0.0.1")])
    }

    fn owned(kind: LinkKind) -> ObservedLink {
        ObservedLink {
            index: 7,
            kind,
            alias: Some(OWNER_ALIAS.to_owned()),
            addresses: Vec::new(),
            up: true,
        }
    }

    fn resolve_with(
        config: &str,
        observed: &BTreeMap<InterfaceName, ObservedLink>,
        resolver: &FakeResolver,
    ) -> BTreeMap<InterfaceName, Result<TunnelSpec, Unresolved>> {
        resolve(&config::parse(config).unwrap(), observed, &host(), resolver)
    }

    /// Resolves a single tunnel named `gre1` and returns its endpoints or error reasons.
    fn resolve_one(
        family: &str,
        local: &str,
        remote: &str,
        current: Option<ObservedLink>,
        resolver: &FakeResolver,
    ) -> Result<Endpoints, Vec<(Side, Reason)>> {
        let observed = current
            .into_iter()
            .map(|link| (name("gre1"), link))
            .collect();
        let mut results = resolve_with(&tunnel("gre1", family, local, remote), &observed, resolver);
        match results.remove(&name("gre1")).unwrap() {
            Ok(spec) => Ok(spec.endpoints),
            Err(Unresolved(errors)) => {
                Err(errors.into_iter().map(|e| (e.side, e.reason)).collect())
            }
        }
    }

    fn endpoints(local: &str, remote: &str) -> Endpoints {
        Endpoints {
            local: ip(local),
            remote: ip(remote),
        }
    }

    #[track_caller]
    fn assert_ambiguous(reason: &Reason, expected: &[&str]) {
        match reason {
            Reason::Ambiguous(candidates) => assert_eq!(candidates, &ips(expected)),
            other => panic!("expected an ambiguous endpoint, got {other:?}"),
        }
    }

    #[test]
    fn uses_literal_addresses_without_lookup() {
        let resolver = FakeResolver::default();
        assert_eq!(
            resolve_one("ipv4", HOST_V4, "198.51.100.1", None, &resolver).unwrap(),
            endpoints(HOST_V4, "198.51.100.1")
        );
        assert!(resolver.lookups.borrow().is_empty());
    }

    #[test]
    fn builds_spec_from_configuration() {
        let resolver = FakeResolver::new(&[("peer.example", &["2001:db8:2::1"])]);
        let config = format!(
            "[tunnels.gre1]\nfamily = \"ipv6\"\nlocal = \"{HOST_V6}\"\nremote = \"peer.example\"\naddresses = [\"10.0.2.0/31\", \"fd00:2::1/127\"]\n"
        );
        let results = resolve_with(&config, &BTreeMap::new(), &resolver);
        assert_eq!(
            results[&name("gre1")].as_ref().unwrap(),
            &TunnelSpec {
                family: Family::Ipv6,
                endpoints: endpoints(HOST_V6, "2001:db8:2::1"),
                addresses: vec![
                    "10.0.2.0/31".parse().unwrap(),
                    "fd00:2::1/127".parse().unwrap()
                ],
            }
        );
    }

    #[test]
    fn filters_by_family_and_ignores_duplicates() {
        let resolver = FakeResolver::new(&[(
            "peer.example",
            &["2001:db8:2::1", "198.51.100.1", "198.51.100.1"],
        )]);
        assert_eq!(
            resolve_one("ipv4", HOST_V4, "peer.example", None, &resolver).unwrap(),
            endpoints(HOST_V4, "198.51.100.1")
        );
    }

    #[test]
    fn ignores_unspecified_results() {
        let resolver = FakeResolver::new(&[("peer.example", &["0.0.0.0", "198.51.100.1"])]);
        assert_eq!(
            resolve_one("ipv4", HOST_V4, "peer.example", None, &resolver).unwrap(),
            endpoints(HOST_V4, "198.51.100.1")
        );
    }

    #[test]
    fn reports_name_without_usable_address() {
        let resolver = FakeResolver::new(&[("peer.example", &["2001:db8:2::1", "0.0.0.0"])]);
        let errors = resolve_one("ipv4", HOST_V4, "peer.example", None, &resolver).unwrap_err();
        assert!(
            matches!(
                &errors[..],
                [(Side::Remote, Reason::NoAddress { name, family: Family::Ipv4 })]
                    if name.as_str() == "peer.example"
            ),
            "{errors:?}"
        );
    }

    #[test]
    fn reports_lookup_failure() {
        let resolver = FakeResolver::default();
        let errors = resolve_one("ipv4", HOST_V4, "peer.example", None, &resolver).unwrap_err();
        assert!(
            matches!(&errors[..], [(Side::Remote, Reason::Lookup { name, .. })] if name.as_str() == "peer.example"),
            "{errors:?}"
        );
    }

    #[test]
    fn multiple_candidates_without_current_are_ambiguous() {
        let resolver = FakeResolver::new(&[("peer.example", &["198.51.100.2", "198.51.100.1"])]);
        let errors = resolve_one("ipv4", HOST_V4, "peer.example", None, &resolver).unwrap_err();
        let [(Side::Remote, reason)] = &errors[..] else {
            panic!("expected one remote error, got {errors:?}");
        };
        assert_ambiguous(reason, &["198.51.100.1", "198.51.100.2"]);
    }

    #[test]
    fn keeps_current_endpoint_while_eligible() {
        let resolver = FakeResolver::new(&[("peer.example", &["198.51.100.1", "198.51.100.2"])]);
        let current = owned(LinkKind::Gre(endpoints(HOST_V4, "198.51.100.2")));
        assert_eq!(
            resolve_one("ipv4", HOST_V4, "peer.example", Some(current), &resolver).unwrap(),
            endpoints(HOST_V4, "198.51.100.2")
        );
    }

    #[test]
    fn switches_to_unique_candidate_when_current_is_gone() {
        let resolver = FakeResolver::new(&[("peer.example", &["198.51.100.3"])]);
        let current = owned(LinkKind::Gre(endpoints(HOST_V4, "198.51.100.2")));
        assert_eq!(
            resolve_one("ipv4", HOST_V4, "peer.example", Some(current), &resolver).unwrap(),
            endpoints(HOST_V4, "198.51.100.3")
        );
    }

    #[test]
    fn does_not_switch_between_new_candidates() {
        let resolver = FakeResolver::new(&[("peer.example", &["198.51.100.3", "198.51.100.4"])]);
        let current = owned(LinkKind::Gre(endpoints(HOST_V4, "198.51.100.2")));
        let errors =
            resolve_one("ipv4", HOST_V4, "peer.example", Some(current), &resolver).unwrap_err();
        assert_ambiguous(&errors[0].1, &["198.51.100.3", "198.51.100.4"]);
    }

    #[test]
    fn ignores_endpoints_of_unowned_or_other_family_interfaces() {
        let resolver = FakeResolver::new(&[("peer.example", &["198.51.100.1", "198.51.100.2"])]);
        let unowned = ObservedLink {
            alias: None,
            ..owned(LinkKind::Gre(endpoints(HOST_V4, "198.51.100.2")))
        };
        // An owned ip6gre interface cannot hold an IPv4 endpoint, but its endpoints must
        // not be consulted for an ipv4 tunnel either way.
        let other_family = owned(LinkKind::Ip6Gre(endpoints(HOST_V6, "2001:db8:2::1")));
        for current in [unowned, other_family] {
            let errors =
                resolve_one("ipv4", HOST_V4, "peer.example", Some(current), &resolver).unwrap_err();
            assert_ambiguous(&errors[0].1, &["198.51.100.1", "198.51.100.2"]);
        }
    }

    #[test]
    fn local_literal_must_be_assigned() {
        let resolver = FakeResolver::default();
        let errors =
            resolve_one("ipv4", "192.0.2.99", "198.51.100.1", None, &resolver).unwrap_err();
        assert!(
            matches!(&errors[..], [(Side::Local, Reason::NotAssigned(c))] if c == &ips(&["192.0.2.99"])),
            "{errors:?}"
        );
    }

    #[test]
    fn local_name_selects_the_assigned_address() {
        let resolver = FakeResolver::new(&[("me.example", &["192.0.2.99", HOST_V4])]);
        assert_eq!(
            resolve_one("ipv4", "me.example", "198.51.100.1", None, &resolver).unwrap(),
            endpoints(HOST_V4, "198.51.100.1")
        );
    }

    #[test]
    fn local_name_without_assigned_address_is_reported() {
        let resolver = FakeResolver::new(&[("me.example", &["192.0.2.99", "192.0.2.98"])]);
        let errors =
            resolve_one("ipv4", "me.example", "198.51.100.1", None, &resolver).unwrap_err();
        assert!(
            matches!(&errors[..], [(Side::Local, Reason::NotAssigned(c))] if c == &ips(&["192.0.2.98", "192.0.2.99"])),
            "{errors:?}"
        );
    }

    #[test]
    fn local_name_with_several_assigned_addresses_keeps_current() {
        let resolver = FakeResolver::new(&[("me.example", &[HOST_V4, "127.0.0.1"])]);
        let errors =
            resolve_one("ipv4", "me.example", "198.51.100.1", None, &resolver).unwrap_err();
        assert_ambiguous(&errors[0].1, &["127.0.0.1", HOST_V4]);

        let current = owned(LinkKind::Gre(endpoints(HOST_V4, "198.51.100.1")));
        assert_eq!(
            resolve_one(
                "ipv4",
                "me.example",
                "198.51.100.1",
                Some(current),
                &resolver
            )
            .unwrap(),
            endpoints(HOST_V4, "198.51.100.1")
        );
    }

    #[test]
    fn reports_both_endpoints() {
        let resolver = FakeResolver::default();
        let errors =
            resolve_one("ipv6", "me.example", "peer.example", None, &resolver).unwrap_err();
        let sides: Vec<Side> = errors.iter().map(|&(side, _)| side).collect();
        assert_eq!(sides, [Side::Local, Side::Remote]);
    }

    #[test]
    fn looks_up_each_name_once() {
        let resolver = FakeResolver::new(&[
            ("me.example", &[HOST_V4]),
            ("peer1.example", &["198.51.100.1"]),
            ("peer2.example", &["198.51.100.2"]),
        ]);
        let config = [
            tunnel("gre1", "ipv4", "me.example", "peer1.example"),
            tunnel("gre2", "ipv4", "me.example", "peer2.example"),
            tunnel("gre3", "ipv4", "me.example", "peer1.example"),
        ]
        .concat();
        let results = resolve_with(&config, &BTreeMap::new(), &resolver);
        assert!(results.values().all(Result::is_ok), "{results:?}");
        assert_eq!(
            *resolver.lookups.borrow(),
            ["me.example", "peer1.example", "peer2.example"]
        );
    }

    #[test]
    fn failures_are_isolated_per_tunnel() {
        let resolver = FakeResolver::new(&[("peer1.example", &["198.51.100.1"])]);
        let config = [
            tunnel("gre1", "ipv4", HOST_V4, "peer1.example"),
            tunnel("gre2", "ipv4", HOST_V4, "missing.example"),
        ]
        .concat();
        let results = resolve_with(&config, &BTreeMap::new(), &resolver);
        assert!(results[&name("gre1")].is_ok());
        assert!(results[&name("gre2")].is_err());
    }

    #[test]
    fn error_messages() {
        let resolver = FakeResolver::new(&[("peer.example", &["198.51.100.1", "198.51.100.2"])]);
        let results = resolve_with(
            &tunnel("gre1", "ipv4", "192.0.2.99", "peer.example"),
            &BTreeMap::new(),
            &resolver,
        );
        let error = results[&name("gre1")].as_ref().unwrap_err();
        assert_eq!(
            error.to_string(),
            "`local` is not assigned to this host: 192.0.2.99; \
             `remote` has several candidates: 198.51.100.1, 198.51.100.2"
        );

        let resolver = FakeResolver::default();
        let results = resolve_with(
            &tunnel("gre1", "ipv6", HOST_V6, "peer.example"),
            &BTreeMap::new(),
            &resolver,
        );
        assert_eq!(
            results[&name("gre1")].as_ref().unwrap_err().to_string(),
            "`remote` cannot resolve peer.example: name not found"
        );
    }

    #[test]
    fn system_resolver_reads_hosts_file() {
        // `localhost` is defined in /etc/hosts on the supported distributions, so this
        // does not need network access.
        let addresses = SystemResolver
            .lookup(&DnsName::new("localhost").unwrap())
            .unwrap();
        assert!(addresses.iter().any(IpAddr::is_loopback), "{addresses:?}");
    }
}
