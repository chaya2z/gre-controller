//! Privileged integration tests. They change the kernel's network state, so they only
//! run inside the dedicated network namespace that `scripts/netns-test.sh` creates:
//!
//! ```sh
//! scripts/netns-test.sh
//! ```
//!
//! Interfaces are set up with iproute2, independently of the code under test.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use gre_controller::config::InterfaceName;
use gre_controller::observe::{self, Snapshot};
use gre_controller::plan::{Endpoints, LinkKind, OWNER_ALIAS, ObservedLink};
use ipnet::IpNet;

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
    assert!(gt4.addresses.contains(&net("10.0.0.1/30")), "{gt4:?}");
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
    assert!(gt6.addresses.contains(&net("10.0.1.1/30")), "{gt6:?}");
    assert!(gt6.addresses.contains(&net("fd00:1::1/64")), "{gt6:?}");
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
    assert!(va.addresses.contains(&net("2001:db8:1::7/64")), "{va:?}");
    assert!(va.addresses.contains(&net("198.51.100.7/24")), "{va:?}");
    assert!(!snapshot.host_addresses.contains(&addr("2001:db8:1::7")));
    assert!(snapshot.host_addresses.contains(&addr("198.51.100.7")));
}
