//! Kernel snapshot over rtnetlink (read-only).
//!
//! Dumps every interface and address in the network namespace and converts them into
//! the inputs of [`resolve`](crate::resolve::resolve) and [`plan`](crate::plan::plan).
//! Nothing here changes kernel state.
//!
//! A snapshot is only returned if both dumps completed. An interrupted, truncated, or
//! failed dump is an error, never an empty or partial snapshot, because the planner
//! would read missing owned interfaces as deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::IpAddr;

use futures_util::{Stream, StreamExt};
use ipnet::IpNet;
use rtnetlink::Handle;
use rtnetlink::packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use rtnetlink::packet_route::link::{
    InfoData, InfoGre, InfoGre6, InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};

use crate::config::{InterfaceName, InterfaceNameError};
use crate::plan::{Endpoints, LinkKind, ObservedAddress, ObservedLink};

/// Interfaces and addresses of the network namespace at one point in time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    /// Every interface, keyed by name.
    pub links: BTreeMap<InterfaceName, ObservedLink>,
    /// Addresses that a tunnel may use as its local endpoint: every address assigned to
    /// an interface this controller does not own, except IPv6 addresses that are still
    /// tentative or failed duplicate address detection.
    pub host_addresses: BTreeSet<IpAddr>,
}

/// Opens an rtnetlink connection for [`observe`] and spawns it on the current Tokio
/// runtime.
///
/// The connection forwards `NLMSG_DONE` to the caller, which [`observe`] needs to tell a
/// complete dump from a truncated one. Do not use the returned handle with rtnetlink's
/// own dump requests (`handle.link().get()` and similar), which do not expect it.
///
/// # Errors
///
/// Returns an error if the netlink socket cannot be opened.
///
/// # Panics
///
/// Panics if called outside a Tokio runtime.
pub fn connect() -> io::Result<Handle> {
    let (mut connection, handle, _) = rtnetlink::new_connection()?;
    connection.set_forward_done(true);
    tokio::spawn(connection);
    Ok(handle)
}

/// Takes a snapshot of all interfaces and addresses.
///
/// # Errors
///
/// Returns an error if either dump fails or is incomplete, or if the kernel reports an
/// interface or address that cannot be represented. The caller must then skip the pass.
pub async fn observe(handle: &mut Handle) -> Result<Snapshot, ObserveError> {
    let links = dump(handle, RouteNetlinkMessage::GetLink(LinkMessage::default())).await?;
    let addresses = dump(
        handle,
        RouteNetlinkMessage::GetAddress(AddressMessage::default()),
    )
    .await?;
    let links = links.into_iter().filter_map(|message| match message {
        RouteNetlinkMessage::NewLink(link) => Some(link),
        _ => None,
    });
    let addresses = addresses.into_iter().filter_map(|message| match message {
        RouteNetlinkMessage::NewAddress(address) => Some(address),
        _ => None,
    });
    snapshot(links, addresses)
}

async fn dump(
    handle: &mut Handle,
    request: RouteNetlinkMessage,
) -> Result<Vec<RouteNetlinkMessage>, ObserveError> {
    let mut message = NetlinkMessage::from(request);
    message.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let responses = handle.request(message).map_err(ObserveError::Request)?;
    collect_dump(responses).await
}

/// Collects the messages of one dump, requiring a final `NLMSG_DONE`.
async fn collect_dump(
    responses: impl Stream<Item = NetlinkMessage<RouteNetlinkMessage>>,
) -> Result<Vec<RouteNetlinkMessage>, ObserveError> {
    let mut responses = std::pin::pin!(responses);
    let mut messages = Vec::new();
    while let Some(response) = responses.next().await {
        // The kernel sets this flag when the dumped table changed while the dump was
        // in progress, so the result may be inconsistent.
        if response.header.flags & NLM_F_DUMP_INTR != 0 {
            return Err(ObserveError::Interrupted);
        }
        match response.payload {
            NetlinkPayload::InnerMessage(message) => messages.push(message),
            NetlinkPayload::Done(_) => return Ok(messages),
            NetlinkPayload::Error(error) => return Err(ObserveError::Netlink(error.to_io())),
            NetlinkPayload::Overrun(_) => return Err(ObserveError::Incomplete),
            // `NLMSG_NOOP` carries nothing.
            _ => {}
        }
    }
    // The connection closed or dropped the request before `NLMSG_DONE`.
    Err(ObserveError::Incomplete)
}

/// Builds a snapshot from dumped messages.
fn snapshot(
    links: impl IntoIterator<Item = LinkMessage>,
    addresses: impl IntoIterator<Item = AddressMessage>,
) -> Result<Snapshot, ObserveError> {
    let mut by_index = BTreeMap::new();
    for message in links {
        let (name, link) = observed_link(&message)?;
        by_index.insert(message.header.index, (name, link));
    }

    let mut host_addresses = BTreeSet::new();
    for message in addresses {
        // An address whose interface is not in the link dump belongs to an interface
        // that was removed in between. The next pass sees the current state.
        let Some((_, link)) = by_index.get_mut(&message.header.index) else {
            continue;
        };
        let (address, flags) = observed_address(&message)?;
        link.addresses.push(address);
        let usable = !flags.intersects(AddressFlags::Tentative | AddressFlags::Dadfailed);
        if usable && !link.is_owned() {
            host_addresses.insert(address.net.addr());
        }
    }

    Ok(Snapshot {
        links: by_index.into_values().collect(),
        host_addresses,
    })
}

fn observed_link(message: &LinkMessage) -> Result<(InterfaceName, ObservedLink), ObserveError> {
    let index = message.header.index;
    let mut name = None;
    let mut alias = None;
    let mut kind = None;
    let mut data = None;
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = Some(value),
            LinkAttribute::IfAlias(value) => alias = Some(value.clone()),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    match info {
                        LinkInfo::Kind(value) => kind = Some(value),
                        LinkInfo::Data(value) => data = Some(value),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let name = name.ok_or(ObserveError::MissingName { index })?;
    // Every name the kernel accepts also passes this check (see `InterfaceName::new`).
    // If one does not, fail the snapshot: skipping the interface could hide an owned one.
    let name = InterfaceName::new(name).map_err(|error| ObserveError::InvalidName {
        name: name.clone(),
        error,
    })?;
    let kind = match (kind, data) {
        (Some(InfoKind::GreTun), data) => LinkKind::Gre(gre_endpoints(data)),
        (Some(InfoKind::GreTun6), data) => LinkKind::Ip6Gre(gre6_endpoints(data)),
        (Some(kind), _) => LinkKind::Other(kind.to_string()),
        // Interfaces without a kind, such as physical NICs.
        (None, _) => LinkKind::Other(String::new()),
    };
    let link = ObservedLink {
        index,
        kind,
        alias,
        addresses: Vec::new(),
        up: message.header.flags.contains(LinkFlags::Up),
    };
    Ok((name, link))
}

/// Endpoints of a `gre` interface. Missing attributes read as unspecified, which never
/// matches a resolved endpoint.
fn gre_endpoints(data: Option<&InfoData>) -> Endpoints {
    let mut endpoints = Endpoints {
        local: IpAddr::from([0, 0, 0, 0]),
        remote: IpAddr::from([0, 0, 0, 0]),
    };
    if let Some(InfoData::GreTun(attributes)) = data {
        for attribute in attributes {
            match attribute {
                InfoGre::Local(address) => endpoints.local = (*address).into(),
                InfoGre::Remote(address) => endpoints.remote = (*address).into(),
                _ => {}
            }
        }
    }
    endpoints
}

/// Endpoints of an `ip6gre` interface, like [`gre_endpoints`].
fn gre6_endpoints(data: Option<&InfoData>) -> Endpoints {
    let mut endpoints = Endpoints {
        local: IpAddr::from([0u16; 8]),
        remote: IpAddr::from([0u16; 8]),
    };
    if let Some(InfoData::GreTun6(attributes)) = data {
        for attribute in attributes {
            match attribute {
                InfoGre6::Local(address) => endpoints.local = (*address).into(),
                InfoGre6::Remote(address) => endpoints.remote = (*address).into(),
                _ => {}
            }
        }
    }
    endpoints
}

fn observed_address(
    message: &AddressMessage,
) -> Result<(ObservedAddress, AddressFlags), ObserveError> {
    let index = message.header.index;
    let mut local = None;
    let mut address = None;
    // The header holds only the low 8 bits; `IFA_FLAGS` carries all of them.
    let mut flags = AddressFlags::from_bits_retain(u32::from(message.header.flags.bits()));
    // The kernel omits `IFA_PROTO` when it is 0.
    let mut protocol = 0;
    for attribute in &message.attributes {
        match attribute {
            AddressAttribute::Local(value) => local = Some(*value),
            AddressAttribute::Address(value) => address = Some(*value),
            AddressAttribute::Flags(value) => flags = *value,
            AddressAttribute::Protocol(value) => protocol = u8::from(*value),
            _ => {}
        }
    }
    // On point-to-point interfaces such as GRE, `IFA_ADDRESS` can be the peer and
    // `IFA_LOCAL` the interface's own address. Without a peer both are the same, and
    // IPv6 often sends only `IFA_ADDRESS`. Prefer `IFA_LOCAL`, as iproute2 does.
    let ip = local
        .or(address)
        .ok_or(ObserveError::MissingAddress { index })?;
    let prefix_len = message.header.prefix_len;
    let net = IpNet::new(ip, prefix_len).map_err(|_| ObserveError::InvalidPrefixLength {
        index,
        address: ip,
        prefix_len,
    })?;
    Ok((ObservedAddress { net, protocol }, flags))
}

/// Why a snapshot could not be taken.
#[derive(Debug)]
pub enum ObserveError {
    /// The request could not be sent on the netlink connection.
    Request(rtnetlink::Error),
    /// The kernel answered the dump with an error.
    Netlink(io::Error),
    /// The kernel's tables changed during the dump (`NLM_F_DUMP_INTR`).
    Interrupted,
    /// The dump ended without `NLMSG_DONE`, or messages were lost (`ENOBUFS`).
    Incomplete,
    MissingName {
        index: u32,
    },
    InvalidName {
        name: String,
        error: InterfaceNameError,
    },
    MissingAddress {
        index: u32,
    },
    InvalidPrefixLength {
        index: u32,
        address: IpAddr,
        prefix_len: u8,
    },
}

impl fmt::Display for ObserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => write!(f, "netlink request failed: {error}"),
            Self::Netlink(error) => write!(f, "netlink dump failed: {error}"),
            Self::Interrupted => f.write_str("netlink dump was interrupted by a concurrent change"),
            Self::Incomplete => f.write_str("netlink dump ended before it was complete"),
            Self::MissingName { index } => write!(f, "interface {index} has no name"),
            Self::InvalidName { name, error } => {
                write!(f, "unexpected interface name {name:?}: {error}")
            }
            Self::MissingAddress { index } => {
                write!(f, "address on interface {index} has no IP address")
            }
            Self::InvalidPrefixLength {
                index,
                address,
                prefix_len,
            } => write!(
                f,
                "address {address} on interface {index} has invalid prefix length {prefix_len}"
            ),
        }
    }
}

impl std::error::Error for ObserveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Netlink(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::num::NonZeroI32;

    use futures_util::stream;
    use rtnetlink::packet_core::{DoneMessage, ErrorMessage, NetlinkHeader};
    use rtnetlink::packet_route::AddressFamily;

    use super::*;
    use crate::plan::{ADDRESS_PROTOCOL, OWNER_ALIAS};

    fn name(s: &str) -> InterfaceName {
        InterfaceName::new(s).unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(link: &ObservedLink) -> Vec<IpNet> {
        link.addresses.iter().map(|address| address.net).collect()
    }

    fn link(index: u32, name: &str, up: bool, extra: Vec<LinkAttribute>) -> LinkMessage {
        let mut message = LinkMessage::default();
        message.header.index = index;
        if up {
            message.header.flags = LinkFlags::Up;
        }
        message.attributes = vec![LinkAttribute::IfName(name.to_owned())];
        message.attributes.extend(extra);
        message
    }

    fn link_info(kind: InfoKind, data: Option<InfoData>) -> LinkAttribute {
        let mut infos = vec![LinkInfo::Kind(kind)];
        infos.extend(data.map(LinkInfo::Data));
        LinkAttribute::LinkInfo(infos)
    }

    fn alias() -> LinkAttribute {
        LinkAttribute::IfAlias(OWNER_ALIAS.to_owned())
    }

    fn gre(local: Ipv4Addr, remote: Ipv4Addr) -> LinkAttribute {
        link_info(
            InfoKind::GreTun,
            Some(InfoData::GreTun(vec![
                InfoGre::Ttl(64),
                InfoGre::Local(local),
                InfoGre::Remote(remote),
            ])),
        )
    }

    fn address(index: u32, net: &str, attributes: Vec<AddressAttribute>) -> AddressMessage {
        let net = self::net(net);
        let mut message = AddressMessage::default();
        message.header.index = index;
        message.header.prefix_len = net.prefix_len();
        message.header.family = match net {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        message.attributes = attributes;
        message
    }

    /// An address message as the kernel sends it without a peer.
    fn plain_address(index: u32, net: &str) -> AddressMessage {
        let ip = self::net(net).addr();
        let mut attributes = vec![AddressAttribute::Address(ip)];
        if ip.is_ipv4() {
            attributes.push(AddressAttribute::Local(ip));
        }
        address(index, net, attributes)
    }

    #[test]
    fn reads_interfaces_and_addresses() {
        let links = [
            link(1, "lo", true, vec![]),
            link(2, "eth0", true, vec![]),
            link(
                3,
                "gre1",
                false,
                vec![
                    alias(),
                    gre(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 1)),
                ],
            ),
            link(
                4,
                "gre6",
                true,
                vec![
                    alias(),
                    link_info(
                        InfoKind::GreTun6,
                        Some(InfoData::GreTun6(vec![
                            InfoGre6::Local("2001:db8:1::1".parse().unwrap()),
                            InfoGre6::Remote("2001:db8:2::1".parse().unwrap()),
                        ])),
                    ),
                ],
            ),
            link(5, "tap0", true, vec![link_info(InfoKind::GreTap, None)]),
        ];
        let addresses = [
            plain_address(1, "127.0.0.1/8"),
            plain_address(2, "192.0.2.1/24"),
            plain_address(2, "2001:db8:1::1/64"),
            plain_address(3, "10.0.1.1/31"),
            plain_address(4, "fd00:1::1/127"),
            plain_address(4, "fe80::1/64"),
        ];
        let snapshot = snapshot(links, addresses).unwrap();

        assert_eq!(
            snapshot.links[&name("gre1")],
            ObservedLink {
                index: 3,
                kind: LinkKind::Gre(Endpoints {
                    local: ip("192.0.2.1"),
                    remote: ip("198.51.100.1"),
                }),
                alias: Some(OWNER_ALIAS.to_owned()),
                addresses: vec![ObservedAddress {
                    net: net("10.0.1.1/31"),
                    protocol: 0,
                }],
                up: false,
            }
        );
        assert_eq!(
            snapshot.links[&name("gre6")].kind,
            LinkKind::Ip6Gre(Endpoints {
                local: ip("2001:db8:1::1"),
                remote: ip("2001:db8:2::1"),
            })
        );
        assert_eq!(
            nets(&snapshot.links[&name("gre6")]),
            [net("fd00:1::1/127"), net("fe80::1/64")]
        );
        assert_eq!(
            snapshot.links[&name("eth0")],
            ObservedLink {
                index: 2,
                kind: LinkKind::Other(String::new()),
                alias: None,
                addresses: vec![
                    ObservedAddress {
                        net: net("192.0.2.1/24"),
                        protocol: 0,
                    },
                    ObservedAddress {
                        net: net("2001:db8:1::1/64"),
                        protocol: 0,
                    },
                ],
                up: true,
            }
        );
        assert_eq!(
            snapshot.links[&name("tap0")].kind,
            LinkKind::Other("gretap".to_owned())
        );
        // Addresses on owned interfaces are not host addresses.
        assert_eq!(
            snapshot.host_addresses,
            BTreeSet::from([ip("127.0.0.1"), ip("192.0.2.1"), ip("2001:db8:1::1")])
        );
    }

    #[test]
    fn unowned_gre_addresses_are_host_addresses() {
        let links = [link(
            3,
            "gre-other",
            true,
            vec![gre(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(198, 51, 100, 1),
            )],
        )];
        let snapshot = snapshot(links, [plain_address(3, "10.9.0.1/30")]).unwrap();
        assert_eq!(snapshot.host_addresses, BTreeSet::from([ip("10.9.0.1")]));
    }

    #[test]
    fn missing_gre_endpoints_read_as_unspecified() {
        let links = [
            link(3, "gre1", true, vec![link_info(InfoKind::GreTun, None)]),
            link(4, "gre6", true, vec![link_info(InfoKind::GreTun6, None)]),
        ];
        let snapshot = snapshot(links, []).unwrap();
        assert_eq!(
            snapshot.links[&name("gre1")].kind,
            LinkKind::Gre(Endpoints {
                local: Ipv4Addr::UNSPECIFIED.into(),
                remote: Ipv4Addr::UNSPECIFIED.into(),
            })
        );
        assert_eq!(
            snapshot.links[&name("gre6")].kind,
            LinkKind::Ip6Gre(Endpoints {
                local: Ipv6Addr::UNSPECIFIED.into(),
                remote: Ipv6Addr::UNSPECIFIED.into(),
            })
        );
    }

    #[test]
    fn prefers_local_over_peer_address() {
        let links = [link(2, "eth0", true, vec![])];
        let addresses = [address(
            2,
            "10.0.0.1/32",
            vec![
                AddressAttribute::Address(ip("10.0.0.2")),
                AddressAttribute::Local(ip("10.0.0.1")),
            ],
        )];
        let snapshot = snapshot(links, addresses).unwrap();
        assert_eq!(nets(&snapshot.links[&name("eth0")]), [net("10.0.0.1/32")]);
        assert_eq!(snapshot.host_addresses, BTreeSet::from([ip("10.0.0.1")]));
    }

    #[test]
    fn unusable_ipv6_addresses_are_not_host_addresses() {
        let links = [link(2, "eth0", true, vec![])];
        let flagged = |net, flags| {
            let mut message = plain_address(2, net);
            message.attributes.push(AddressAttribute::Flags(flags));
            message
        };
        let addresses = [
            flagged("2001:db8:1::1/64", AddressFlags::Tentative),
            flagged("2001:db8:1::2/64", AddressFlags::Dadfailed),
            flagged("2001:db8:1::3/64", AddressFlags::Deprecated),
            flagged("2001:db8:1::4/64", AddressFlags::Permanent),
        ];
        let snapshot = snapshot(links, addresses).unwrap();
        // All of them are still on the interface.
        assert_eq!(snapshot.links[&name("eth0")].addresses.len(), 4);
        assert_eq!(
            snapshot.host_addresses,
            BTreeSet::from([ip("2001:db8:1::3"), ip("2001:db8:1::4")])
        );
    }

    #[test]
    fn reads_address_protocol() {
        let links = [link(
            3,
            "gre1",
            true,
            vec![alias(), gre(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)],
        )];
        let with_protocol = |net, protocol: u8| {
            let mut message = plain_address(3, net);
            message
                .attributes
                .push(AddressAttribute::Protocol(protocol.into()));
            message
        };
        let addresses = [
            plain_address(3, "10.0.1.1/31"),
            with_protocol("10.0.2.1/31", ADDRESS_PROTOCOL),
            with_protocol("fe80::1/64", 3),
        ];
        let snapshot = snapshot(links, addresses).unwrap();
        let protocols: Vec<_> = snapshot.links[&name("gre1")]
            .addresses
            .iter()
            .map(|address| (address.net, address.protocol, address.is_owned()))
            .collect();
        assert_eq!(
            protocols,
            [
                (net("10.0.1.1/31"), 0, false),
                (net("10.0.2.1/31"), ADDRESS_PROTOCOL, true),
                (net("fe80::1/64"), 3, false),
            ]
        );
    }

    #[test]
    fn ignores_addresses_of_unknown_interfaces() {
        let snapshot = snapshot(
            [link(1, "lo", true, vec![])],
            [plain_address(9, "192.0.2.1/24")],
        )
        .unwrap();
        assert_eq!(snapshot.host_addresses, BTreeSet::new());
        assert_eq!(
            snapshot.links[&name("lo")].addresses,
            Vec::<ObservedAddress>::new()
        );
    }

    #[test]
    fn rejects_unrepresentable_messages() {
        assert!(matches!(
            snapshot(
                [link(7, "", true, vec![])].map(|mut m| {
                    m.attributes.clear();
                    m
                }),
                []
            ),
            Err(ObserveError::MissingName { index: 7 })
        ));
        assert!(matches!(
            snapshot([link(7, "bad:name", true, vec![])], []),
            Err(ObserveError::InvalidName { .. })
        ));
        assert!(matches!(
            snapshot(
                [link(1, "lo", true, vec![])],
                [address(1, "127.0.0.1/8", vec![])]
            ),
            Err(ObserveError::MissingAddress { index: 1 })
        ));
        let mut too_long = plain_address(1, "127.0.0.1/8");
        too_long.header.prefix_len = 33;
        assert!(matches!(
            snapshot([link(1, "lo", true, vec![])], [too_long]),
            Err(ObserveError::InvalidPrefixLength { prefix_len: 33, .. })
        ));
    }

    fn response(
        flags: u16,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut header = NetlinkHeader::default();
        header.flags = flags;
        NetlinkMessage::new(header, payload)
    }

    fn inner(index: u32) -> NetlinkPayload<RouteNetlinkMessage> {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link(
            index,
            "lo",
            true,
            vec![],
        )))
    }

    fn done() -> NetlinkPayload<RouteNetlinkMessage> {
        NetlinkPayload::Done(DoneMessage::default())
    }

    async fn collect(
        responses: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    ) -> Result<Vec<RouteNetlinkMessage>, ObserveError> {
        collect_dump(stream::iter(responses)).await
    }

    #[tokio::test]
    async fn dump_requires_done() {
        let messages = collect(vec![
            response(0, inner(1)),
            response(0, inner(2)),
            response(0, done()),
        ])
        .await
        .unwrap();
        assert_eq!(messages.len(), 2);

        assert!(matches!(
            collect(vec![response(0, inner(1))]).await,
            Err(ObserveError::Incomplete)
        ));
        assert!(matches!(
            collect(vec![]).await,
            Err(ObserveError::Incomplete)
        ));
    }

    #[tokio::test]
    async fn dump_rejects_interrupted_overrun_and_errors() {
        assert!(matches!(
            collect(vec![
                response(0, inner(1)),
                response(NLM_F_DUMP_INTR, done())
            ])
            .await,
            Err(ObserveError::Interrupted)
        ));
        assert!(matches!(
            collect(vec![
                response(NLM_F_DUMP_INTR, inner(1)),
                response(0, done())
            ])
            .await,
            Err(ObserveError::Interrupted)
        ));
        assert!(matches!(
            collect(vec![response(0, NetlinkPayload::Overrun(Vec::new()))]).await,
            Err(ObserveError::Incomplete)
        ));
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(-1);
        match collect(vec![response(0, NetlinkPayload::Error(error))]).await {
            Err(ObserveError::Netlink(error)) => assert_eq!(error.raw_os_error(), Some(1)),
            other => panic!("expected a netlink error, got {other:?}"),
        }
    }
}
