//! Applies a reconciliation plan to the kernel over rtnetlink.
//!
//! Each interface is handled independently: a failure stops the remaining operations
//! for that interface and is reported, but does not affect other interfaces. Nothing is
//! retried here; the next pass observes the result and plans again.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::packet_core::{NLA_TYPE_MASK, Nla};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{
    InfoData, InfoGre, InfoGre6, InfoKind, LinkAttribute, LinkInfo, LinkMessage,
};
use rtnetlink::{Handle, LinkGre, LinkGre6, LinkMessageBuilder, LinkUnspec};

use crate::config::{Family, InterfaceName};
use crate::observe::{Snapshot, TunnelSettings};
use crate::plan::{ADDRESS_PROTOCOL, Change, Decision, Endpoints, OWNER_ALIAS, TunnelSpec};

/// Applies every decision that changes the kernel. `Conflict` and `Defer` change
/// nothing and get no entry in the result.
///
/// `snapshot` must be the snapshot the decisions were planned from. Existing interfaces
/// are addressed by the index recorded there, so an interface that was deleted and
/// recreated in the meantime is not touched: its operations fail with `ENODEV`.
/// Endpoint changes keep the settings recorded there.
///
/// Deletions run first, so that a renamed tunnel's old interface is gone before the new
/// one is created with the same addresses.
pub async fn apply(
    handle: &Handle,
    decisions: &BTreeMap<InterfaceName, Decision>,
    snapshot: &Snapshot,
) -> BTreeMap<InterfaceName, Result<(), ApplyError>> {
    let (deletions, others): (Vec<_>, Vec<_>) = decisions
        .iter()
        .partition(|(_, decision)| matches!(decision, Decision::Delete));
    let mut results = BTreeMap::new();
    for (name, decision) in deletions.into_iter().chain(others) {
        let index = snapshot.links.get(name).map(|link| link.index);
        let result = match (decision, index) {
            (Decision::Create(spec), _) => create(handle, name, spec).await,
            (Decision::Update(changes), Some(index)) => {
                let settings = snapshot.tunnel_settings.get(name);
                update(handle, index, changes, settings).await
            }
            (Decision::Replace(spec), Some(index)) => match delete_link(handle, index).await {
                Ok(()) => create(handle, name, spec).await,
                Err(error) => Err(error),
            },
            (Decision::Delete, Some(index)) => delete_link(handle, index).await,
            (Decision::Update(_) | Decision::Replace(_) | Decision::Delete, None) => {
                Err(ApplyError::NotObserved)
            }
            (Decision::Conflict(_) | Decision::Defer, _) => continue,
        };
        results.insert(name.clone(), result);
    }
    results
}

/// Creates the interface, marks it, assigns the addresses, and brings it UP.
///
/// The kernel ignores the alias when creating an interface, so it is set in a second
/// request. Until then the interface is unmarked, which the next pass would report as a
/// conflict. If setting the alias fails, the interface is deleted again. It stays DOWN
/// until it is marked, so an interface left behind by a crash in between carries no
/// traffic.
async fn create(
    handle: &Handle,
    name: &InterfaceName,
    spec: &TunnelSpec,
) -> Result<(), ApplyError> {
    let message = tunnel(spec.family, spec.endpoints, name);
    handle
        .link()
        .add(message)
        .execute()
        .await
        .map_err(Operation::CreateLink.with())?;

    let index = find_index(handle, name).await?;
    let mark = LinkUnspec::new_with_index(index).alias(OWNER_ALIAS).build();
    if let Err(error) = change_link(handle, mark).await {
        return Err(match delete_link(handle, index).await {
            Ok(()) => Operation::SetAlias.with()(error),
            Err(cleanup) => ApplyError::UnmarkedLinkLeft {
                error,
                cleanup: Box::new(cleanup),
            },
        });
    }

    for &address in &spec.addresses {
        add_address(handle, index, address).await?;
    }
    set_up(handle, index).await
}

async fn update(
    handle: &Handle,
    index: u32,
    changes: &[Change],
    settings: Option<&TunnelSettings>,
) -> Result<(), ApplyError> {
    // Build the endpoint change before sending anything: without the current settings,
    // none of the changes for this interface are made.
    let mut endpoint_change = None;
    for change in changes {
        if let Change::SetEndpoints(endpoints) = *change {
            let settings = settings.ok_or(ApplyError::SettingsUnavailable)?;
            endpoint_change = Some(
                endpoint_change_message(index, settings, endpoints)
                    .ok_or(ApplyError::SettingsUnavailable)?,
            );
        }
    }
    for change in changes {
        match *change {
            Change::SetEndpoints(_) => {
                if let Some(message) = endpoint_change.take() {
                    change_link(handle, message)
                        .await
                        .map_err(Operation::SetEndpoints.with())?;
                }
            }
            Change::RemoveAddress(address) => remove_address(handle, index, address).await?,
            Change::AddAddress(address) => add_address(handle, index, address).await?,
            Change::SetUp => set_up(handle, index).await?,
        }
    }
    Ok(())
}

/// The link message that creates a tunnel. Every GRE parameter that is not sent gets
/// the kernel's default.
fn tunnel(family: Family, endpoints: Endpoints, name: &InterfaceName) -> LinkMessage {
    match (family, endpoints.local, endpoints.remote) {
        (Family::Ipv4, IpAddr::V4(local), IpAddr::V4(remote)) => {
            LinkMessageBuilder::<LinkGre>::new_with_info_kind(InfoKind::GreTun)
                .name(name.as_str())
                .local(local)
                .remote(remote)
                .build()
        }
        (Family::Ipv6, IpAddr::V6(local), IpAddr::V6(remote)) => {
            LinkMessageBuilder::<LinkGre6>::new_with_info_kind(InfoKind::GreTun6)
                .name(name.as_str())
                .local(local)
                .remote(remote)
                .build()
        }
        // `resolve` guarantees that both endpoints match the family.
        _ => unreachable!("endpoints {endpoints:?} do not match {family:?}"),
    }
}

/// `IFLA_GRE_*` attributes that `ipgre_changelink()` applies to a `gre` interface:
/// link, input/output flags and keys, local, remote, TTL, TOS, PMTU discovery,
/// encapsulation type/flags/ports, ignore-DF, and fwmark.
const GRE_WRITABLE: [u16; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 17, 19, 20];

/// `IFLA_GRE_*` attributes that `ip6gre_changelink()` applies to an `ip6gre`
/// interface: link, input/output flags and keys, local, remote, hop limit,
/// encapsulation limit, flow info, tunnel flags, encapsulation type/flags/ports, and
/// fwmark.
const IP6GRE_WRITABLE: [u16; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 20];

/// The link message that changes the endpoints of an existing tunnel and keeps
/// everything else.
///
/// On a change, the kernel resets every GRE parameter that is not sent, and `ip6gre`
/// recomputes the MTU unless `IFLA_MTU` is sent. So the message carries the current MTU
/// and every writable parameter as reported, with only local and remote replaced.
/// Read-only attributes, such as `IFLA_GRE_COLLECT_METADATA`, are left out.
///
/// Returns `None` if the settings are not of the endpoints' family.
fn endpoint_change_message(
    index: u32,
    settings: &TunnelSettings,
    endpoints: Endpoints,
) -> Option<LinkMessage> {
    let writable = |kind: u16, list: &[u16]| list.contains(&(kind & NLA_TYPE_MASK));
    let (kind, data) = match (&settings.data, endpoints.local, endpoints.remote) {
        (InfoData::GreTun(current), IpAddr::V4(local), IpAddr::V4(remote)) => {
            let mut data: Vec<_> = current
                .iter()
                .filter(|attribute| writable(attribute.kind(), &GRE_WRITABLE))
                .filter(|attribute| !matches!(attribute, InfoGre::Local(_) | InfoGre::Remote(_)))
                .cloned()
                .collect();
            data.extend([InfoGre::Local(local), InfoGre::Remote(remote)]);
            (InfoKind::GreTun, InfoData::GreTun(data))
        }
        (InfoData::GreTun6(current), IpAddr::V6(local), IpAddr::V6(remote)) => {
            let mut data: Vec<_> = current
                .iter()
                .filter(|attribute| writable(attribute.kind(), &IP6GRE_WRITABLE))
                .filter(|attribute| !matches!(attribute, InfoGre6::Local(_) | InfoGre6::Remote(_)))
                .cloned()
                .collect();
            data.extend([InfoGre6::Local(local), InfoGre6::Remote(remote)]);
            (InfoKind::GreTun6, InfoData::GreTun6(data))
        }
        _ => return None,
    };
    let mut message = LinkMessage::default();
    message.header.index = index;
    message.attributes = vec![
        LinkAttribute::Mtu(settings.mtu),
        LinkAttribute::LinkInfo(vec![LinkInfo::Kind(kind), LinkInfo::Data(data)]),
    ];
    Some(message)
}

async fn find_index(handle: &Handle, name: &InterfaceName) -> Result<u32, ApplyError> {
    // A request for one interface by name, not a dump, so it does not end with
    // `NLMSG_DONE` and works on the handle from `observe::connect`.
    let link = handle
        .link()
        .get()
        .match_name(name.as_str().to_owned())
        .execute()
        .try_next()
        .await
        .map_err(Operation::FindCreatedLink.with())?;
    link.map(|link| link.header.index)
        .ok_or(ApplyError::CreatedLinkNotFound)
}

async fn set_up(handle: &Handle, index: u32) -> Result<(), ApplyError> {
    let message = LinkUnspec::new_with_index(index).up().build();
    change_link(handle, message)
        .await
        .map_err(Operation::SetUp.with())
}

/// Changes an existing link (`RTM_NEWLINK` without `NLM_F_CREATE` or `NLM_F_EXCL`).
/// The kernel rejects `NLM_F_EXCL` for an existing link, and only `RTM_NEWLINK` passes
/// tunnel parameters to the driver; `RTM_SETLINK` does not.
async fn change_link(handle: &Handle, message: LinkMessage) -> Result<(), rtnetlink::Error> {
    handle.link().change(message).execute().await
}

async fn delete_link(handle: &Handle, index: u32) -> Result<(), ApplyError> {
    handle
        .link()
        .del(index)
        .execute()
        .await
        .map_err(Operation::DeleteLink.with())
}

/// Adds an address marked with [`ADDRESS_PROTOCOL`].
///
/// The request uses `NLM_F_EXCL`, never `NLM_F_REPLACE`: replacing an existing address
/// would overwrite its protocol and adopt an address that someone else added.
async fn add_address(handle: &Handle, index: u32, address: IpNet) -> Result<(), ApplyError> {
    let mut request = handle
        .address()
        .add(index, address.addr(), address.prefix_len());
    // Replace the builder's message, which also sets a broadcast address for IPv4.
    let message = request.message_mut();
    *message = address_message(index, address);
    message
        .attributes
        .push(AddressAttribute::Protocol(ADDRESS_PROTOCOL.into()));
    request
        .execute()
        .await
        .map_err(Operation::AddAddress(address).with())
}

async fn remove_address(handle: &Handle, index: u32, address: IpNet) -> Result<(), ApplyError> {
    handle
        .address()
        .del(address_message(index, address))
        .execute()
        .await
        .map_err(Operation::RemoveAddress(address).with())
}

/// An address message without a peer: `IFA_LOCAL` and `IFA_ADDRESS` are both the
/// interface's own address, as `ip address add` sends it.
fn address_message(index: u32, address: IpNet) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.prefix_len = address.prefix_len();
    message.header.family = match address {
        IpNet::V4(_) => AddressFamily::Inet,
        IpNet::V6(_) => AddressFamily::Inet6,
    };
    message.attributes = vec![
        AddressAttribute::Local(address.addr()),
        AddressAttribute::Address(address.addr()),
    ];
    message
}

/// A kernel operation that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    CreateLink,
    FindCreatedLink,
    SetAlias,
    SetEndpoints,
    AddAddress(IpNet),
    RemoveAddress(IpNet),
    SetUp,
    DeleteLink,
}

impl Operation {
    fn with(self) -> impl FnOnce(rtnetlink::Error) -> ApplyError {
        move |error| ApplyError::Netlink {
            operation: self,
            error,
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateLink => f.write_str("create interface"),
            Self::FindCreatedLink => f.write_str("look up created interface"),
            Self::SetAlias => f.write_str("set ownership alias"),
            Self::SetEndpoints => f.write_str("set endpoints"),
            Self::AddAddress(address) => write!(f, "add address {address}"),
            Self::RemoveAddress(address) => write!(f, "remove address {address}"),
            Self::SetUp => f.write_str("set interface up"),
            Self::DeleteLink => f.write_str("delete interface"),
        }
    }
}

/// Why applying the decision for one interface failed. Operations before the failed one
/// took effect; later ones were not attempted.
#[derive(Debug)]
pub enum ApplyError {
    Netlink {
        operation: Operation,
        error: rtnetlink::Error,
    },
    /// The interface was created, but the lookup by name found nothing. It was deleted
    /// or renamed in the meantime.
    CreatedLinkNotFound,
    /// Setting the ownership alias failed, and so did deleting the new interface. It is
    /// left behind unmarked and has to be deleted by hand.
    UnmarkedLinkLeft {
        error: rtnetlink::Error,
        cleanup: Box<Self>,
    },
    /// The decision needs an existing interface, but it is not in the snapshot.
    NotObserved,
    /// The endpoints should change, but the snapshot has no complete settings of the
    /// right kind for the interface, so they could not be kept. Nothing was changed.
    SettingsUnavailable,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netlink { operation, error } => write!(f, "cannot {operation}: {error}"),
            Self::CreatedLinkNotFound => {
                f.write_str("created interface disappeared before it was marked")
            }
            Self::UnmarkedLinkLeft { error, cleanup } => write!(
                f,
                "cannot set ownership alias ({error}), and {cleanup}; \
                 the unmarked interface must be deleted manually"
            ),
            Self::NotObserved => f.write_str("interface is missing from the snapshot"),
            Self::SettingsUnavailable => f.write_str(
                "current tunnel settings are unknown, so the endpoints cannot be changed \
                 without resetting them",
            ),
        }
    }
}

impl std::error::Error for ApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Netlink { error, .. } | Self::UnmarkedLinkLeft { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rtnetlink::packet_core::DefaultNla;
    use rtnetlink::packet_route::link::GreIOFlags;

    use super::*;

    fn endpoints(local: &str, remote: &str) -> Endpoints {
        Endpoints {
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
        }
    }

    /// The MTU and tunnel parameters of a change message.
    fn parts(message: &LinkMessage) -> (u32, &InfoKind, &InfoData) {
        assert_eq!(message.header.index, 7);
        match message.attributes.as_slice() {
            [LinkAttribute::Mtu(mtu), LinkAttribute::LinkInfo(info)] => match info.as_slice() {
                [LinkInfo::Kind(kind), LinkInfo::Data(data)] => (*mtu, kind, data),
                other => panic!("unexpected link info {other:?}"),
            },
            other => panic!("unexpected attributes {other:?}"),
        }
    }

    #[test]
    fn gre_endpoint_change_keeps_writable_settings() {
        // IFLA_GRE_IGNORE_DF (19) has no named variant.
        let ignore_df = InfoGre::Other(DefaultNla::new(19, vec![0]));
        let settings = TunnelSettings {
            mtu: 1400,
            data: InfoData::GreTun(vec![
                InfoGre::Link(0),
                InfoGre::IFlags(GreIOFlags::Key),
                InfoGre::OFlags(GreIOFlags::Key),
                InfoGre::IKey(1234),
                InfoGre::OKey(1234),
                InfoGre::Local(Ipv4Addr::new(192, 0, 2, 1)),
                InfoGre::Remote(Ipv4Addr::new(198, 51, 100, 1)),
                InfoGre::Ttl(33),
                InfoGre::Tos(0),
                InfoGre::PathMTUDiscovery(true),
                InfoGre::FwMask(5),
                ignore_df.clone(),
                // Read-only or not applicable to `gre`.
                InfoGre::CollectMetadata,
                InfoGre::ErSpanVer(1),
                InfoGre::Other(DefaultNla::new(99, vec![1])),
            ]),
        };
        let message =
            endpoint_change_message(7, &settings, endpoints("192.0.2.2", "203.0.113.2")).unwrap();
        let (mtu, kind, data) = parts(&message);
        assert_eq!(mtu, 1400);
        assert_eq!(*kind, InfoKind::GreTun);
        assert_eq!(
            *data,
            InfoData::GreTun(vec![
                InfoGre::Link(0),
                InfoGre::IFlags(GreIOFlags::Key),
                InfoGre::OFlags(GreIOFlags::Key),
                InfoGre::IKey(1234),
                InfoGre::OKey(1234),
                InfoGre::Ttl(33),
                InfoGre::Tos(0),
                InfoGre::PathMTUDiscovery(true),
                InfoGre::FwMask(5),
                ignore_df,
                InfoGre::Local(Ipv4Addr::new(192, 0, 2, 2)),
                InfoGre::Remote(Ipv4Addr::new(203, 0, 113, 2)),
            ])
        );
    }

    #[test]
    fn ip6gre_endpoint_change_keeps_writable_settings() {
        // IFLA_GRE_FLAGS (13) has no named variant.
        let flags = InfoGre6::Other(DefaultNla::new(13, vec![1, 0, 0, 0]));
        let settings = TunnelSettings {
            mtu: 1380,
            data: InfoData::GreTun6(vec![
                InfoGre6::Link(0),
                InfoGre6::IKey(1234),
                InfoGre6::OKey(1234),
                InfoGre6::Local("2001:db8::1".parse().unwrap()),
                InfoGre6::Remote("2001:db8::2".parse().unwrap()),
                InfoGre6::Ttl(33),
                InfoGre6::EncapLimit(4),
                InfoGre6::FlowLabel(0),
                flags.clone(),
                InfoGre6::FwMask(0),
                // Read-only or not applicable to `ip6gre`.
                InfoGre6::CollectMetadata,
                InfoGre6::Tos(0),
                InfoGre6::ErSpanIndex(1),
            ]),
        };
        let message =
            endpoint_change_message(7, &settings, endpoints("2001:db8::3", "2001:db8::4")).unwrap();
        let (mtu, kind, data) = parts(&message);
        assert_eq!(mtu, 1380);
        assert_eq!(*kind, InfoKind::GreTun6);
        assert_eq!(
            *data,
            InfoData::GreTun6(vec![
                InfoGre6::Link(0),
                InfoGre6::IKey(1234),
                InfoGre6::OKey(1234),
                InfoGre6::Ttl(33),
                InfoGre6::EncapLimit(4),
                InfoGre6::FlowLabel(0),
                flags,
                InfoGre6::FwMask(0),
                InfoGre6::Local("2001:db8::3".parse::<Ipv6Addr>().unwrap()),
                InfoGre6::Remote("2001:db8::4".parse::<Ipv6Addr>().unwrap()),
            ])
        );
    }

    #[test]
    fn endpoint_change_needs_settings_of_the_same_family() {
        let gre = TunnelSettings {
            mtu: 1476,
            data: InfoData::GreTun(vec![]),
        };
        assert!(
            endpoint_change_message(7, &gre, endpoints("2001:db8::1", "2001:db8::2")).is_none()
        );
        let gre6 = TunnelSettings {
            mtu: 1448,
            data: InfoData::GreTun6(vec![]),
        };
        assert!(endpoint_change_message(7, &gre6, endpoints("192.0.2.1", "192.0.2.2")).is_none());
    }

    /// Without settings, an update that changes the endpoints sends nothing at all, not
    /// even its address changes. The handle is never used, so no socket is needed.
    #[tokio::test]
    async fn update_without_settings_changes_nothing() {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        drop(connection);
        let changes = [
            Change::AddAddress("10.0.0.1/30".parse().unwrap()),
            Change::SetEndpoints(endpoints("192.0.2.1", "192.0.2.2")),
        ];
        assert!(matches!(
            update(&handle, 7, &changes, None).await,
            Err(ApplyError::SettingsUnavailable)
        ));
    }
}
