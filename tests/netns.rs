//! Privileged integration tests. They change the kernel's network state, so they only
//! run inside the dedicated network namespace that `scripts/netns-test.sh` creates:
//!
//! ```sh
//! scripts/netns-test.sh
//! ```
//!
//! The `observe` tests set up interfaces with iproute2, independently of the code under
//! test. The `apply` tests change the kernel with `apply` and check the result with
//! `observe`, so they also cover the round trip of the ownership markers.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use std::collections::BTreeMap;

use gre_controller::apply;
use gre_controller::config::{Family, InterfaceName};
use gre_controller::observe::{self, Snapshot, TunnelSettings};
use gre_controller::plan::{
    self, ADDRESS_PROTOCOL, Decision, DesiredTunnel, Endpoints, LinkKind, OWNER_ALIAS,
    ObservedLink, TunnelSpec,
};
use ipnet::IpNet;
use rtnetlink::packet_route::link::{InfoData, InfoGre, InfoGre6};

/// Panics unless the process runs in the namespace named by `GRE_CONTROLLER_TEST_NETNS`,
/// so that `cargo test -- --ignored` cannot change the host's own namespace.
fn require_test_netns() {
    let name = std::env::var("GRE_CONTROLLER_TEST_NETNS")
        .expect("GRE_CONTROLLER_TEST_NETNS is not set; run scripts/netns-test.sh");
    let current = fs::metadata("/proc/self/ns/net").unwrap();
    let expected = fs::metadata(Path::new("/run/netns").join(&name))
        .unwrap_or_else(|e| panic!("network namespace {name} not found: {e}"));
    assert_eq!(
        (current.dev(), current.ino()),
        (expected.dev(), expected.ino()),
        "not running inside network namespace {name}"
    );
}

fn ip(args: &[&str]) {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn snapshot() -> Snapshot {
    let mut handle = observe::connect().unwrap();
    observe::observe(&mut handle).await.unwrap()
}

fn link<'a>(snapshot: &'a Snapshot, name: &str) -> &'a ObservedLink {
    &snapshot.links[&InterfaceName::new(name).unwrap()]
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn has(link: &ObservedLink, net: IpNet) -> bool {
    link.addresses.iter().any(|address| address.net == net)
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn observes_owned_gre() {
    require_test_netns();
    ip(&[
        "link",
        "add",
        "gt4",
        "type",
        "gre",
        "local",
        "192.0.2.1",
        "remote",
        "198.51.100.1",
    ]);
    ip(&["link", "set", "gt4", "alias", OWNER_ALIAS]);
    ip(&["address", "add", "10.0.0.1/30", "dev", "gt4"]);
    ip(&["link", "set", "gt4", "up"]);

    let snapshot = snapshot().await;
    let gt4 = link(&snapshot, "gt4");

    assert_eq!(
        gt4.kind,
        LinkKind::Gre(Endpoints {
            local: addr("192.0.2.1"),
            remote: addr("198.51.100.1"),
        })
    );
    assert_eq!(gt4.alias.as_deref(), Some(OWNER_ALIAS));
    assert!(gt4.is_owned());
    assert!(gt4.up);
    assert!(has(gt4, net("10.0.0.1/30")), "{gt4:?}");
    assert!(!snapshot.host_addresses.contains(&addr("10.0.0.1")));
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn observes_owned_ip6gre() {
    require_test_netns();
    ip(&[
        "link",
        "add",
        "gt6",
        "type",
        "ip6gre",
        "local",
        "2001:db8::1",
        "remote",
        "2001:db8::2",
    ]);
    ip(&["link", "set", "gt6", "alias", OWNER_ALIAS]);
    ip(&["address", "add", "10.0.1.1/30", "dev", "gt6"]);
    ip(&["address", "add", "fd00:1::1/64", "dev", "gt6"]);
    ip(&["link", "set", "gt6", "up"]);

    let snapshot = snapshot().await;
    let gt6 = link(&snapshot, "gt6");

    assert_eq!(
        gt6.kind,
        LinkKind::Ip6Gre(Endpoints {
            local: addr("2001:db8::1"),
            remote: addr("2001:db8::2"),
        })
    );
    assert!(gt6.is_owned());
    assert!(gt6.up);
    assert!(has(gt6, net("10.0.1.1/30")), "{gt6:?}");
    assert!(has(gt6, net("fd00:1::1/64")), "{gt6:?}");
    assert!(!snapshot.host_addresses.contains(&addr("10.0.1.1")));
    assert!(!snapshot.host_addresses.contains(&addr("fd00:1::1")));
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn unowned_gre_addresses_are_host_addresses() {
    require_test_netns();
    ip(&[
        "link",
        "add",
        "gtx",
        "type",
        "gre",
        "local",
        "192.0.2.2",
        "remote",
        "198.51.100.2",
    ]);
    ip(&["address", "add", "10.0.2.1/30", "dev", "gtx"]);

    let snapshot = snapshot().await;
    let gtx = link(&snapshot, "gtx");

    assert!(matches!(gtx.kind, LinkKind::Gre(_)));
    assert_eq!(gtx.alias, None);
    assert!(!gtx.is_owned());
    assert!(!gtx.up);
    assert!(snapshot.host_addresses.contains(&addr("10.0.2.1")));
}

/// An IPv6 address added to a down interface that does duplicate address detection
/// stays tentative until the interface comes up. An IPv4 address on a down interface
/// still counts.
#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn tentative_addresses_are_not_host_addresses() {
    require_test_netns();
    ip(&["link", "add", "va", "type", "veth", "peer", "name", "vb"]);
    ip(&["address", "add", "2001:db8:1::7/64", "dev", "va"]);
    ip(&["address", "add", "198.51.100.7/24", "dev", "va"]);

    let snapshot = snapshot().await;
    let va = link(&snapshot, "va");

    assert_eq!(va.kind, LinkKind::Other("veth".into()));
    assert!(!va.up);
    assert!(has(va, net("2001:db8:1::7/64")), "{va:?}");
    assert!(has(va, net("198.51.100.7/24")), "{va:?}");
    assert!(!snapshot.host_addresses.contains(&addr("2001:db8:1::7")));
    assert!(snapshot.host_addresses.contains(&addr("198.51.100.7")));
}

fn name(s: &str) -> InterfaceName {
    InterfaceName::new(s).unwrap()
}

fn spec(family: Family, local: &str, remote: &str, addresses: &[&str]) -> TunnelSpec {
    TunnelSpec {
        family,
        endpoints: Endpoints {
            local: addr(local),
            remote: addr(remote),
        },
        addresses: addresses.iter().copied().map(net).collect(),
    }
}

/// Runs one reconciliation pass for `desired` and returns its decisions. Every applied
/// decision must succeed.
async fn reconcile(desired: &[(&str, &TunnelSpec)]) -> BTreeMap<InterfaceName, Decision> {
    let desired: BTreeMap<_, _> = desired
        .iter()
        .map(|&(n, spec)| (name(n), DesiredTunnel::Resolved(spec.clone())))
        .collect();
    let mut handle = observe::connect().unwrap();
    let before = observe::observe(&mut handle).await.unwrap();
    let decisions = plan::plan(&desired, &before.links);
    for (name, result) in apply::apply(&handle, &decisions, &before).await {
        if let Err(error) = result {
            panic!("{name}: {error}");
        }
    }
    decisions
}

/// Checks that the interface matches `spec` and that every declared address carries the
/// controller's protocol.
fn assert_matches(snapshot: &Snapshot, n: &str, spec: &TunnelSpec) {
    let link = link(snapshot, n);
    assert_eq!(
        link.owned_endpoints(),
        Some((spec.family, spec.endpoints)),
        "{link:?}"
    );
    assert_eq!(link.alias.as_deref(), Some(OWNER_ALIAS));
    assert!(link.up, "{link:?}");
    for net in &spec.addresses {
        let address = link.addresses.iter().find(|address| address.net == *net);
        assert_eq!(
            address.map(|address| address.protocol),
            Some(ADDRESS_PROTOCOL),
            "{net} on {link:?}"
        );
    }
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn creates_tunnels_and_converges() {
    require_test_netns();
    let v4 = spec(
        Family::Ipv4,
        "192.0.2.10",
        "198.51.100.10",
        &["10.1.0.1/30", "fd00:a::1/64"],
    );
    let v6 = spec(
        Family::Ipv6,
        "2001:db8::10",
        "2001:db8::11",
        &["10.1.1.1/30", "fd00:b::1/64"],
    );
    let decisions = reconcile(&[("ap-v4", &v4), ("ap-v6", &v6)]).await;
    assert!(matches!(decisions[&name("ap-v4")], Decision::Create(_)));
    assert!(matches!(decisions[&name("ap-v6")], Decision::Create(_)));

    let snapshot = snapshot().await;
    assert_matches(&snapshot, "ap-v4", &v4);
    assert_matches(&snapshot, "ap-v6", &v6);
    let (hop_limit, _, _) = ttl_and_keys(&snapshot.tunnel_settings[&name("ap-v6")]);
    assert_eq!(hop_limit, Some(64));

    // A second pass has nothing to do.
    let decisions = reconcile(&[("ap-v4", &v4), ("ap-v6", &v6)]).await;
    assert!(
        !decisions.contains_key(&name("ap-v4")) && !decisions.contains_key(&name("ap-v6")),
        "{decisions:?}"
    );
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn removes_only_its_own_addresses() {
    require_test_netns();
    let old = spec(
        Family::Ipv4,
        "192.0.2.30",
        "198.51.100.30",
        &["10.3.0.1/30", "10.3.1.1/30", "fe80::30/64"],
    );
    reconcile(&[("own-addr", &old)]).await;
    // Added by someone else: no protocol, and a protocol that is not the controller's.
    ip(&["address", "add", "10.3.2.1/30", "dev", "own-addr"]);
    ip(&[
        "address",
        "add",
        "10.3.3.1/30",
        "dev",
        "own-addr",
        "proto",
        "99",
    ]);

    let new = spec(
        Family::Ipv4,
        "192.0.2.30",
        "198.51.100.30",
        &["10.3.0.1/30"],
    );
    reconcile(&[("own-addr", &new)]).await;

    let snapshot = snapshot().await;
    assert_matches(&snapshot, "own-addr", &new);
    let link = link(&snapshot, "own-addr");
    assert!(!has(link, net("10.3.1.1/30")), "{link:?}");
    assert!(!has(link, net("fe80::30/64")), "{link:?}");
    assert!(has(link, net("10.3.2.1/30")), "{link:?}");
    assert!(has(link, net("10.3.3.1/30")), "{link:?}");
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn does_not_adopt_existing_addresses() {
    require_test_netns();
    let first = spec(
        Family::Ipv4,
        "192.0.2.40",
        "198.51.100.40",
        &["10.4.0.1/30"],
    );
    reconcile(&[("adopt", &first)]).await;
    ip(&["address", "add", "10.4.1.1/30", "dev", "adopt"]);

    // Declaring the existing address changes nothing, and it keeps no protocol.
    let declared = spec(
        Family::Ipv4,
        "192.0.2.40",
        "198.51.100.40",
        &["10.4.0.1/30", "10.4.1.1/30"],
    );
    let decisions = reconcile(&[("adopt", &declared)]).await;
    assert!(!decisions.contains_key(&name("adopt")), "{decisions:?}");
    let after = snapshot().await;
    let address = link(&after, "adopt")
        .addresses
        .iter()
        .find(|address| address.net == net("10.4.1.1/30"))
        .copied()
        .unwrap();
    assert_eq!(address.protocol, 0);

    // Undeclaring it again does not remove it.
    reconcile(&[("adopt", &first)]).await;
    assert!(has(link(&snapshot().await, "adopt"), net("10.4.1.1/30")));
}

/// The kernel marks the IPv6 link-local address it generates for an `ip6gre` interface
/// with `IFAPROT_KERNEL_LL` (3), so it is never the controller's to remove.
#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn keeps_kernel_link_local_address() {
    require_test_netns();
    let tunnel = spec(
        Family::Ipv6,
        "2001:db8::50",
        "2001:db8::51",
        &["fd00:e::1/64"],
    );
    reconcile(&[("kernel-ll", &tunnel)]).await;

    let snapshot = snapshot().await;
    let link = link(&snapshot, "kernel-ll");
    let kernel: Vec<_> = link
        .addresses
        .iter()
        .filter(
            |address| matches!(address.net.addr(), IpAddr::V6(ip) if ip.is_unicast_link_local()),
        )
        .collect();
    assert!(!kernel.is_empty(), "no link-local address: {link:?}");
    assert!(
        kernel.iter().all(|address| address.protocol == 3),
        "{kernel:?}"
    );

    let decisions = reconcile(&[("kernel-ll", &tunnel)]).await;
    assert!(!decisions.contains_key(&name("kernel-ll")), "{decisions:?}");
}

#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn replaces_deletes_and_leaves_unowned_interfaces() {
    require_test_netns();
    let v4 = spec(
        Family::Ipv4,
        "192.0.2.60",
        "198.51.100.60",
        &["10.6.0.1/30"],
    );
    // The kernel refuses two GRE tunnels with the same endpoints and keys.
    let gone = spec(
        Family::Ipv4,
        "192.0.2.62",
        "198.51.100.62",
        &["10.6.1.1/30"],
    );
    reconcile(&[("swap", &v4), ("gone", &gone)]).await;
    // Same name as a declared tunnel, but not created by the controller.
    ip(&[
        "link",
        "add",
        "foreign",
        "type",
        "gre",
        "local",
        "192.0.2.61",
        "remote",
        "198.51.100.61",
    ]);

    let v6 = spec(
        Family::Ipv6,
        "2001:db8::60",
        "2001:db8::61",
        &["10.6.0.1/30"],
    );
    let decisions = reconcile(&[("swap", &v6), ("foreign", &v4)]).await;
    assert_eq!(decisions[&name("swap")], Decision::Replace(v6.clone()));
    assert_eq!(decisions[&name("gone")], Decision::Delete);
    assert!(matches!(decisions[&name("foreign")], Decision::Conflict(_)));

    let snapshot = snapshot().await;
    assert_matches(&snapshot, "swap", &v6);
    assert!(!snapshot.links.contains_key(&name("gone")));
    let foreign = link(&snapshot, "foreign");
    assert_eq!(foreign.alias, None);
    assert!(foreign.addresses.is_empty() && !foreign.up, "{foreign:?}");
}

/// The current tunnel settings without the endpoints, which are expected to change.
fn settings_without_endpoints(snapshot: &Snapshot, n: &str) -> TunnelSettings {
    let mut settings = snapshot.tunnel_settings[&name(n)].clone();
    match &mut settings.data {
        InfoData::GreTun(data) => {
            data.retain(|attribute| !matches!(attribute, InfoGre::Local(_) | InfoGre::Remote(_)));
        }
        InfoData::GreTun6(data) => {
            data.retain(|attribute| !matches!(attribute, InfoGre6::Local(_) | InfoGre6::Remote(_)));
        }
        other => panic!("{n}: unexpected settings {other:?}"),
    }
    settings
}

/// TTL (hop limit) and input/output keys as reported.
fn ttl_and_keys(settings: &TunnelSettings) -> (Option<u8>, Option<u32>, Option<u32>) {
    let (mut ttl, mut ikey, mut okey) = (None, None, None);
    match &settings.data {
        InfoData::GreTun(data) => {
            for attribute in data {
                match attribute {
                    InfoGre::Ttl(value) => ttl = Some(*value),
                    InfoGre::IKey(value) => ikey = Some(*value),
                    InfoGre::OKey(value) => okey = Some(*value),
                    _ => {}
                }
            }
        }
        InfoData::GreTun6(data) => {
            for attribute in data {
                match attribute {
                    InfoGre6::Ttl(value) => ttl = Some(*value),
                    InfoGre6::IKey(value) => ikey = Some(*value),
                    InfoGre6::OKey(value) => okey = Some(*value),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    (ttl, ikey, okey)
}

/// An endpoint change keeps the interface and everything the controller does not
/// manage: ifindex, addresses, MTU, TTL / hop limit, and GRE keys set by hand.
#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn endpoint_change_keeps_unmanaged_settings() {
    require_test_netns();
    let cases = [
        (
            "ep-v4",
            "gre",
            "ttl",
            spec(
                Family::Ipv4,
                "192.0.2.20",
                "198.51.100.20",
                &["10.2.0.1/30", "fd00:c::1/64"],
            ),
            spec(
                Family::Ipv4,
                "192.0.2.21",
                "198.51.100.21",
                &["10.2.0.1/30", "fd00:c::1/64"],
            ),
        ),
        (
            "ep-v6",
            "ip6gre",
            "hoplimit",
            spec(
                Family::Ipv6,
                "2001:db8::20",
                "2001:db8::21",
                &["10.2.1.1/30", "fd00:d::1/64"],
            ),
            spec(
                Family::Ipv6,
                "2001:db8::22",
                "2001:db8::23",
                &["10.2.1.1/30", "fd00:d::1/64"],
            ),
        ),
    ];
    for (n, kind, ttl_option, old, new) in &cases {
        reconcile(&[(n, old)]).await;
        // Settings the controller does not manage, changed by hand. The MTU comes last:
        // adding a key lengthens the GRE header, and the kernel lowers the MTU to match
        // unless the request carries one, which `ip link set ... type` does not.
        ip(&[
            "link", "set", "dev", n, "type", kind, ttl_option, "33", "key", "1234",
        ]);
        ip(&["link", "set", "dev", n, "mtu", "1400"]);

        let before = snapshot().await;
        let before_settings = settings_without_endpoints(&before, n);
        assert_eq!(before_settings.mtu, 1400, "{n}: setup failed");
        let (ttl, ikey, okey) = ttl_and_keys(&before_settings);
        assert_eq!(ttl, Some(33), "{n}: setup failed: {before_settings:?}");
        assert!(
            ikey.is_some_and(|key| key != 0) && ikey == okey,
            "{n}: setup failed: {before_settings:?}"
        );
        let before = link(&before, n).clone();

        let decisions = reconcile(&[(n, new)]).await;
        assert_eq!(
            decisions[&name(n)],
            Decision::Update(vec![plan::Change::SetEndpoints(new.endpoints)])
        );

        let after = snapshot().await;
        assert_matches(&after, n, new);
        assert_eq!(
            settings_without_endpoints(&after, n),
            before_settings,
            "{n}: settings changed"
        );
        let after = link(&after, n);
        assert_eq!(after.index, before.index, "{n}: ifindex changed");
        assert_eq!(after.addresses, before.addresses, "{n}: addresses changed");
    }
}

/// A `gre-controller run` process whose log lines are collected in the background.
struct Controller {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Controller {
    fn start(config: &str) -> Self {
        let path = std::env::temp_dir().join(format!("gre-controller-{}.toml", std::process::id()));
        fs::write(&path, config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_gre-controller"))
            .args(["run", "--config"])
            .arg(&path)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                eprintln!("controller: {line}");
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    /// Waits for a log line that contains every one of `parts`.
    fn wait_for(&self, parts: &[&str]) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if parts.iter().all(|part| line.contains(part)) => return,
                Ok(_) => {}
                Err(error) => panic!("no log line with {parts:?}: {error}"),
            }
        }
    }

    /// Sends `SIGTERM` and requires a successful exit.
    fn stop(mut self) {
        let pid = self.child.id().to_string();
        let status = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
        assert!(status.success());
        let status = self.child.wait().unwrap();
        assert!(status.success(), "controller exited with {status}");
        self.wait_for(&["stopped"]);
    }
}

/// End to end: `run` creates the declared tunnel, keeps it when stopped, and changes
/// nothing while the configuration is invalid.
#[tokio::test]
#[ignore = "changes kernel state; run scripts/netns-test.sh"]
async fn run_reconciles_and_stops_without_teardown() {
    require_test_netns();
    // The local endpoint must be an address of the host.
    // veth is already known to work on the CI runner.
    ip(&[
        "link",
        "add",
        "uplink",
        "type",
        "veth",
        "peer",
        "name",
        "uplink-peer",
    ]);
    ip(&["address", "add", "192.0.2.80/24", "dev", "uplink"]);
    ip(&["link", "set", "uplink", "up"]);
    let config = r#"
[tunnels.run-gre]
family = "ipv4"
local = "192.0.2.80"
remote = "198.51.100.80"
addresses = ["10.8.0.1/30"]
"#;
    let tunnel = spec(
        Family::Ipv4,
        "192.0.2.80",
        "198.51.100.80",
        &["10.8.0.1/30"],
    );

    let controller = Controller::start(config);
    controller.wait_for(&["run-gre", "created"]);
    controller.stop();
    assert_matches(&snapshot().await, "run-gre", &tunnel);

    // An invalid configuration is not an empty one: the tunnel stays.
    let controller = Controller::start(&config.replace("10.8.0.1/30", "10.8.0.1"));
    controller.wait_for(&["invalid configuration"]);
    controller.stop();
    assert_matches(&snapshot().await, "run-gre", &tunnel);
}
