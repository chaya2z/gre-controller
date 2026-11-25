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
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{InfoKind, LinkMessage};
use rtnetlink::{Handle, LinkGre, LinkGre6, LinkMessageBuilder, LinkUnspec};

use crate::config::{Family, InterfaceName};
use crate::plan::{
    ADDRESS_PROTOCOL, Change, Decision, Endpoints, OWNER_ALIAS, ObservedLink, TunnelSpec,
};

/// Applies every decision that changes the kernel. `Conflict` and `Defer` change
/// nothing and get no entry in the result.
///
/// `observed` must be the snapshot the decisions were planned from. Existing interfaces
/// are addressed by the index recorded there, so an interface that was deleted and
/// recreated in the meantime is not touched: its operations fail with `ENODEV`.
///
/// Deletions run first, so that a renamed tunnel's old interface is gone before the new
/// one is created with the same addresses.
pub async fn apply(
    handle: &Handle,
    decisions: &BTreeMap<InterfaceName, Decision>,
    observed: &BTreeMap<InterfaceName, ObservedLink>,
) -> BTreeMap<InterfaceName, Result<(), ApplyError>> {
    let (deletions, others): (Vec<_>, Vec<_>) = decisions
        .iter()
        .partition(|(_, decision)| matches!(decision, Decision::Delete));
    let mut results = BTreeMap::new();
    for (name, decision) in deletions.into_iter().chain(others) {
        let index = observed.get(name).map(|link| link.index);
        let result = match (decision, index) {
            (Decision::Create(spec), _) => create(handle, name, spec).await,
            (Decision::Update(changes), Some(index)) => update(handle, index, changes).await,
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
    let message = tunnel(spec.family, spec.endpoints, Target::New(name));
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

async fn update(handle: &Handle, index: u32, changes: &[Change]) -> Result<(), ApplyError> {
    for change in changes {
        match *change {
            Change::SetEndpoints(endpoints) => set_endpoints(handle, index, endpoints).await?,
            Change::RemoveAddress(address) => remove_address(handle, index, address).await?,
            Change::AddAddress(address) => add_address(handle, index, address).await?,
            Change::SetUp => set_up(handle, index).await?,
        }
    }
    Ok(())
}

/// Which interface a link message is for.
enum Target<'a> {
    New(&'a InterfaceName),
    Existing(u32),
}

impl Target<'_> {
    fn apply<T>(self, builder: LinkMessageBuilder<T>) -> LinkMessageBuilder<T> {
        match self {
            Self::New(name) => builder.name(name.as_str()),
            Self::Existing(index) => builder.index(index),
        }
    }
}

/// The link message that sets the tunnel kind and endpoints. Creation and endpoint
/// changes send the same attributes. On a change, the kernel resets every GRE parameter
/// that is not sent to its default, as it does on creation.
fn tunnel(family: Family, endpoints: Endpoints, target: Target<'_>) -> LinkMessage {
    match (family, endpoints.local, endpoints.remote) {
        (Family::Ipv4, IpAddr::V4(local), IpAddr::V4(remote)) => target
            .apply(LinkMessageBuilder::<LinkGre>::new_with_info_kind(
                InfoKind::GreTun,
            ))
            .local(local)
            .remote(remote)
            .build(),
        (Family::Ipv6, IpAddr::V6(local), IpAddr::V6(remote)) => target
            .apply(LinkMessageBuilder::<LinkGre6>::new_with_info_kind(
                InfoKind::GreTun6,
            ))
            .local(local)
            .remote(remote)
            .build(),
        // `resolve` guarantees that both endpoints match the family.
        _ => unreachable!("endpoints {endpoints:?} do not match {family:?}"),
    }
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

async fn set_endpoints(
    handle: &Handle,
    index: u32,
    endpoints: Endpoints,
) -> Result<(), ApplyError> {
    let family = if endpoints.local.is_ipv4() {
        Family::Ipv4
    } else {
        Family::Ipv6
    };
    let message = tunnel(family, endpoints, Target::Existing(index));
    change_link(handle, message)
        .await
        .map_err(Operation::SetEndpoints.with())
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
