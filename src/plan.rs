//! Reconciliation planning.
//!
//! Compares the desired tunnels with a snapshot of the kernel's interfaces and decides,
//! per interface, what has to change. This module performs no I/O: endpoint resolution
//! and kernel access happen elsewhere and pass their results in, so every rule of the
//! reconciliation model can be tested without privileges.
//!
//! The caller must only call [`plan`] with a complete, successfully obtained kernel
//! snapshot. A failed query must never be passed in as an empty snapshot.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::{Family, InterfaceName};

/// Interface alias (`IFLA_IFALIAS`) that marks an interface as created by this controller.
///
/// Changing this value would orphan the interfaces created by earlier releases.
pub const OWNER_ALIAS: &str = "gre-controller";

/// Underlay endpoints of a GRE interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints {
    pub local: IpAddr,
    pub remote: IpAddr,
}

/// A tunnel whose endpoints have been resolved to single addresses.
///
/// Both endpoints are expected to match `family`; the resolver guarantees this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSpec {
    pub family: Family,
    pub endpoints: Endpoints,
    /// Overlay addresses in declaration order.
    pub addresses: Vec<IpNet>,
}

/// Desired state of one configured tunnel for this pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredTunnel {
    Resolved(TunnelSpec),
    /// An endpoint could not be resolved to a single usable address. The tunnel stays
    /// declared, so its interface must not be created, modified, or deleted this pass.
    Unresolved,
}

/// Kind of an existing interface, with the GRE endpoints where applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkKind {
    Gre(Endpoints),
    Ip6Gre(Endpoints),
    /// Any other kind, as reported by the kernel (for example `"gretap"` or `"dummy"`).
    /// An empty string stands for an interface without a kind, such as a physical NIC.
    Other(String),
}

/// An existing interface in the kernel snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLink {
    pub kind: LinkKind,
    pub alias: Option<String>,
    /// Every address assigned to the interface, including kernel-generated ones.
    pub addresses: Vec<IpNet>,
    /// Whether the interface is administratively UP (`IFF_UP`).
    pub up: bool,
}

impl ObservedLink {
    /// Whether this controller owns the interface: it carries the ownership alias and
    /// is a GRE interface. A matching name alone is not ownership.
    #[must_use]
    pub fn is_owned(&self) -> bool {
        self.owned_gre().is_ok()
    }

    /// The underlay family and current endpoints, if this controller owns the interface.
    #[must_use]
    pub fn owned_endpoints(&self) -> Option<(Family, Endpoints)> {
        self.owned_gre().ok()
    }

    fn owned_gre(&self) -> Result<(Family, Endpoints), Conflict> {
        if self.alias.as_deref() != Some(OWNER_ALIAS) {
            return Err(Conflict::NotMarked);
        }
        match &self.kind {
            LinkKind::Gre(endpoints) => Ok((Family::Ipv4, *endpoints)),
            LinkKind::Ip6Gre(endpoints) => Ok((Family::Ipv6, *endpoints)),
            LinkKind::Other(kind) => Err(Conflict::UnexpectedKind(kind.clone())),
        }
    }
}

/// What to do with one interface in this pass. Interfaces that need nothing are omitted
/// from the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Create the interface with the ownership alias, assign the addresses, and bring it UP.
    Create(TunnelSpec),
    /// Apply the changes to the owned interface in place, in order.
    Update(Vec<Change>),
    /// The underlay family changed: delete the owned interface and create it again.
    Replace(TunnelSpec),
    /// The owned interface is no longer declared.
    Delete,
    /// A declared tunnel's name is taken by an interface this controller does not own.
    /// Do not adopt or modify it.
    Conflict(Conflict),
    /// The declared tunnel's endpoints are unresolved. Leave the interface as it is, or
    /// do not create it if it is missing.
    Defer,
}

/// A change to an owned interface that is kept in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    SetEndpoints(Endpoints),
    RemoveAddress(IpNet),
    AddAddress(IpNet),
    SetUp,
}

/// Why an existing interface with a declared name is not owned by this controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    /// The interface does not carry the ownership alias.
    NotMarked,
    /// The interface carries the ownership alias but is not a GRE interface.
    UnexpectedKind(String),
}

/// Decides what to change so that the kernel matches the desired tunnels.
///
/// `observed` must contain every interface in the network namespace. Unowned interfaces
/// are never changed; owned interfaces whose names are not declared are deleted.
/// Unchanged tunnels produce no entry, so a converged state yields an empty plan.
#[must_use]
pub fn plan(
    desired: &BTreeMap<InterfaceName, DesiredTunnel>,
    observed: &BTreeMap<InterfaceName, ObservedLink>,
) -> BTreeMap<InterfaceName, Decision> {
    let declared = desired
        .iter()
        .filter_map(|(name, tunnel)| Some((name.clone(), decide(tunnel, observed.get(name))?)));
    let removed = observed
        .iter()
        .filter(|&(name, link)| !desired.contains_key(name) && link.is_owned())
        .map(|(name, _)| (name.clone(), Decision::Delete));
    declared.chain(removed).collect()
}

/// Decides what to do with a declared tunnel and the interface of the same name, if any.
fn decide(desired: &DesiredTunnel, link: Option<&ObservedLink>) -> Option<Decision> {
    let Some(link) = link else {
        return Some(match desired {
            DesiredTunnel::Resolved(spec) => Decision::Create(spec.clone()),
            DesiredTunnel::Unresolved => Decision::Defer,
        });
    };
    let (family, endpoints) = match link.owned_gre() {
        Ok(owned) => owned,
        Err(conflict) => return Some(Decision::Conflict(conflict)),
    };
    let DesiredTunnel::Resolved(spec) = desired else {
        return Some(Decision::Defer);
    };
    if family != spec.family {
        return Some(Decision::Replace(spec.clone()));
    }

    let mut changes = Vec::new();
    if endpoints != spec.endpoints {
        changes.push(Change::SetEndpoints(spec.endpoints));
    }
    // Removals come first: an IPv6 address can only be assigned once per interface, so
    // changing its prefix length means removing the old entry before adding the new one.
    changes.extend(
        link.addresses
            .iter()
            .filter(|&address| !spec.addresses.contains(address) && !is_kernel_generated(address))
            .copied()
            .map(Change::RemoveAddress),
    );
    changes.extend(
        spec.addresses
            .iter()
            .filter(|&address| !link.addresses.contains(address))
            .copied()
            .map(Change::AddAddress),
    );
    if !link.up {
        changes.push(Change::SetUp);
    }
    (!changes.is_empty()).then_some(Decision::Update(changes))
}

/// Addresses the kernel may assign by itself. They are kept unless declared, because
/// removing them would only make the kernel add them again (and break IPv6 on the link).
fn is_kernel_generated(address: &IpNet) -> bool {
    matches!(address.addr(), IpAddr::V6(ip) if ip.is_unicast_link_local())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> InterfaceName {
        InterfaceName::new(s).unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn endpoints(local: &str, remote: &str) -> Endpoints {
        Endpoints {
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
        }
    }

    fn v4_endpoints() -> Endpoints {
        endpoints("192.0.2.1", "198.51.100.1")
    }

    fn v6_endpoints() -> Endpoints {
        endpoints("2001:db8:1::1", "2001:db8:2::1")
    }

    fn v4_spec(addresses: &[&str]) -> TunnelSpec {
        TunnelSpec {
            family: Family::Ipv4,
            endpoints: v4_endpoints(),
            addresses: addresses.iter().copied().map(net).collect(),
        }
    }

    /// An owned, UP `gre` interface that matches `v4_spec(addresses)`.
    fn owned_v4(addresses: &[&str]) -> ObservedLink {
        ObservedLink {
            kind: LinkKind::Gre(v4_endpoints()),
            alias: Some(OWNER_ALIAS.to_owned()),
            addresses: addresses.iter().copied().map(net).collect(),
            up: true,
        }
    }

    /// Plans a single declared tunnel named `gre1` against an optional existing interface.
    fn plan_one(desired: DesiredTunnel, link: Option<ObservedLink>) -> Option<Decision> {
        let desired = BTreeMap::from([(name("gre1"), desired)]);
        let observed = link.into_iter().map(|link| (name("gre1"), link)).collect();
        let mut decisions = plan(&desired, &observed);
        let decision = decisions.remove(&name("gre1"));
        assert!(decisions.is_empty(), "unexpected decisions: {decisions:?}");
        decision
    }

    fn update(link: ObservedLink, spec: TunnelSpec) -> Vec<Change> {
        match plan_one(DesiredTunnel::Resolved(spec), Some(link)) {
            Some(Decision::Update(changes)) => changes,
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[test]
    fn creates_missing_interface() {
        let spec = v4_spec(&["10.0.1.1/31"]);
        assert_eq!(
            plan_one(DesiredTunnel::Resolved(spec.clone()), None),
            Some(Decision::Create(spec))
        );
    }

    #[test]
    fn matching_interface_needs_nothing() {
        let link = owned_v4(&["10.0.1.1/31"]);
        assert_eq!(
            plan_one(
                DesiredTunnel::Resolved(v4_spec(&["10.0.1.1/31"])),
                Some(link)
            ),
            None
        );

        let link = ObservedLink {
            kind: LinkKind::Ip6Gre(v6_endpoints()),
            ..owned_v4(&["10.0.2.0/31", "fd00:2::1/127", "fe80::1/64"])
        };
        let spec = TunnelSpec {
            family: Family::Ipv6,
            endpoints: v6_endpoints(),
            addresses: vec![net("fd00:2::1/127"), net("10.0.2.0/31")],
        };
        assert_eq!(plan_one(DesiredTunnel::Resolved(spec), Some(link)), None);
    }

    #[test]
    fn converged_state_yields_empty_plan() {
        let desired = BTreeMap::from([
            (
                name("gre1"),
                DesiredTunnel::Resolved(v4_spec(&["10.0.1.1/31"])),
            ),
            (
                name("gre2"),
                DesiredTunnel::Resolved(v4_spec(&["10.0.2.1/31"])),
            ),
        ]);
        let observed = BTreeMap::from([
            (name("gre1"), owned_v4(&["10.0.1.1/31"])),
            (name("gre2"), owned_v4(&["10.0.2.1/31"])),
            (
                name("eth0"),
                ObservedLink {
                    kind: LinkKind::Other(String::new()),
                    alias: None,
                    addresses: vec![net("192.0.2.1/24")],
                    up: true,
                },
            ),
        ]);
        assert!(plan(&desired, &observed).is_empty());
    }

    #[test]
    fn updates_endpoints_in_place() {
        let new = endpoints("192.0.2.1", "203.0.113.7");
        let spec = TunnelSpec {
            endpoints: new,
            ..v4_spec(&["10.0.1.1/31"])
        };
        assert_eq!(
            update(owned_v4(&["10.0.1.1/31"]), spec),
            vec![Change::SetEndpoints(new)]
        );
    }

    #[test]
    fn reconciles_address_set() {
        let link = owned_v4(&["10.0.1.1/31", "10.9.9.9/32"]);
        let spec = v4_spec(&["10.0.1.1/31", "fd00:1::1/127"]);
        assert_eq!(
            update(link, spec),
            vec![
                Change::RemoveAddress(net("10.9.9.9/32")),
                Change::AddAddress(net("fd00:1::1/127")),
            ]
        );
    }

    #[test]
    fn changed_prefix_length_removes_before_adding() {
        let link = owned_v4(&["fd00:1::1/64"]);
        let spec = v4_spec(&["fd00:1::1/127"]);
        assert_eq!(
            update(link, spec),
            vec![
                Change::RemoveAddress(net("fd00:1::1/64")),
                Change::AddAddress(net("fd00:1::1/127")),
            ]
        );
    }

    #[test]
    fn keeps_kernel_generated_link_local_addresses() {
        let link = owned_v4(&["10.0.1.1/31", "fe80::c000:201/64", "fe80::1/10"]);
        assert_eq!(
            plan_one(
                DesiredTunnel::Resolved(v4_spec(&["10.0.1.1/31"])),
                Some(link)
            ),
            None
        );
    }

    #[test]
    fn adds_declared_link_local_address() {
        let link = owned_v4(&["10.0.1.1/31"]);
        let spec = v4_spec(&["10.0.1.1/31", "fe80::1/64"]);
        assert_eq!(
            update(link, spec),
            vec![Change::AddAddress(net("fe80::1/64"))]
        );
    }

    #[test]
    fn removes_non_link_local_ipv6_addresses() {
        // fec0::/10 (deprecated site-local) is adjacent to fe80::/10 but not link-local.
        let link = owned_v4(&["10.0.1.1/31", "fec0::1/64"]);
        assert_eq!(
            update(link, v4_spec(&["10.0.1.1/31"])),
            vec![Change::RemoveAddress(net("fec0::1/64"))]
        );
    }

    #[test]
    fn brings_down_interface_up() {
        let link = ObservedLink {
            up: false,
            ..owned_v4(&["10.0.1.1/31"])
        };
        assert_eq!(update(link, v4_spec(&["10.0.1.1/31"])), vec![Change::SetUp]);
    }

    #[test]
    fn orders_changes() {
        let new = endpoints("192.0.2.1", "203.0.113.7");
        let link = ObservedLink {
            up: false,
            ..owned_v4(&["10.0.1.1/31"])
        };
        let spec = TunnelSpec {
            endpoints: new,
            ..v4_spec(&["10.0.2.1/31"])
        };
        assert_eq!(
            update(link, spec),
            vec![
                Change::SetEndpoints(new),
                Change::RemoveAddress(net("10.0.1.1/31")),
                Change::AddAddress(net("10.0.2.1/31")),
                Change::SetUp,
            ]
        );
    }

    #[test]
    fn replaces_interface_when_family_changes() {
        let spec = TunnelSpec {
            family: Family::Ipv6,
            endpoints: v6_endpoints(),
            addresses: vec![net("10.0.1.1/31")],
        };
        assert_eq!(
            plan_one(
                DesiredTunnel::Resolved(spec.clone()),
                Some(owned_v4(&["10.0.1.1/31"]))
            ),
            Some(Decision::Replace(spec))
        );
    }

    #[test]
    fn reports_conflict_for_unmarked_interface() {
        for alias in [None, Some("something-else".to_owned())] {
            let link = ObservedLink {
                alias,
                ..owned_v4(&["10.0.1.1/31"])
            };
            assert_eq!(
                plan_one(
                    DesiredTunnel::Resolved(v4_spec(&["10.0.1.1/31"])),
                    Some(link)
                ),
                Some(Decision::Conflict(Conflict::NotMarked))
            );
        }
    }

    #[test]
    fn reports_conflict_for_marked_interface_of_other_kind() {
        let link = ObservedLink {
            kind: LinkKind::Other("gretap".to_owned()),
            ..owned_v4(&[])
        };
        assert_eq!(
            plan_one(
                DesiredTunnel::Resolved(v4_spec(&["10.0.1.1/31"])),
                Some(link)
            ),
            Some(Decision::Conflict(Conflict::UnexpectedKind(
                "gretap".to_owned()
            )))
        );
    }

    #[test]
    fn reports_conflict_even_when_unresolved() {
        let link = ObservedLink {
            alias: None,
            ..owned_v4(&[])
        };
        assert_eq!(
            plan_one(DesiredTunnel::Unresolved, Some(link)),
            Some(Decision::Conflict(Conflict::NotMarked))
        );
    }

    #[test]
    fn defers_unresolved_tunnels() {
        // A missing interface is not created.
        assert_eq!(
            plan_one(DesiredTunnel::Unresolved, None),
            Some(Decision::Defer)
        );
        // An existing interface is kept as it is, even if it differs from the declaration.
        let link = ObservedLink {
            up: false,
            ..owned_v4(&["10.9.9.9/32"])
        };
        assert_eq!(
            plan_one(DesiredTunnel::Unresolved, Some(link)),
            Some(Decision::Defer)
        );
    }

    #[test]
    fn deletes_only_owned_undeclared_interfaces() {
        let observed = BTreeMap::from([
            (name("gre-old"), owned_v4(&["10.0.1.1/31"])),
            (
                name("gre-old6"),
                ObservedLink {
                    kind: LinkKind::Ip6Gre(v6_endpoints()),
                    ..owned_v4(&[])
                },
            ),
            (
                name("gre-unowned"),
                ObservedLink {
                    alias: None,
                    ..owned_v4(&[])
                },
            ),
            (
                name("dummy0"),
                ObservedLink {
                    kind: LinkKind::Other("dummy".to_owned()),
                    ..owned_v4(&[])
                },
            ),
        ]);
        assert_eq!(
            plan(&BTreeMap::new(), &observed),
            BTreeMap::from([
                (name("gre-old"), Decision::Delete),
                (name("gre-old6"), Decision::Delete),
            ])
        );
    }

    #[test]
    fn renamed_tunnel_creates_new_and_deletes_old() {
        let spec = v4_spec(&["10.0.1.1/31"]);
        let desired = BTreeMap::from([(name("gre-new"), DesiredTunnel::Resolved(spec.clone()))]);
        let observed = BTreeMap::from([(name("gre-old"), owned_v4(&["10.0.1.1/31"]))]);
        assert_eq!(
            plan(&desired, &observed),
            BTreeMap::from([
                (name("gre-new"), Decision::Create(spec)),
                (name("gre-old"), Decision::Delete),
            ])
        );
    }

    #[test]
    fn tunnels_are_decided_independently() {
        let desired = BTreeMap::from([
            (name("gre-a"), DesiredTunnel::Unresolved),
            (
                name("gre-b"),
                DesiredTunnel::Resolved(v4_spec(&["10.0.2.1/31"])),
            ),
            (
                name("gre-c"),
                DesiredTunnel::Resolved(v4_spec(&["10.0.3.1/31"])),
            ),
        ]);
        let observed = BTreeMap::from([
            (name("gre-a"), owned_v4(&["10.0.1.1/31"])),
            (
                name("gre-b"),
                ObservedLink {
                    alias: None,
                    ..owned_v4(&[])
                },
            ),
        ]);
        assert_eq!(
            plan(&desired, &observed),
            BTreeMap::from([
                (name("gre-a"), Decision::Defer),
                (name("gre-b"), Decision::Conflict(Conflict::NotMarked)),
                (name("gre-c"), Decision::Create(v4_spec(&["10.0.3.1/31"]))),
            ])
        );
    }
}
