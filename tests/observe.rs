//! Reads the kernel state of the test process's network namespace. Needs no privileges.

use gre_controller::config::InterfaceName;
use gre_controller::observe;
use gre_controller::plan::LinkKind;

#[tokio::test]
async fn observes_loopback() {
    let mut handle = observe::connect().expect("cannot open a netlink socket");
    let snapshot = observe::observe(&mut handle)
        .await
        .expect("snapshot failed");

    let lo = &snapshot.links[&InterfaceName::new("lo").unwrap()];
    assert_eq!(lo.kind, LinkKind::Other(String::new()));
    assert!(lo.up);
    assert!(
        lo.addresses.iter().any(|a| a.net.addr().is_loopback()),
        "{lo:?}"
    );
    assert!(
        snapshot
            .host_addresses
            .iter()
            .any(std::net::IpAddr::is_loopback),
        "{snapshot:?}"
    );
}

#[tokio::test]
async fn repeated_snapshots_use_one_connection() {
    let mut handle = observe::connect().unwrap();
    let first = observe::observe(&mut handle).await.unwrap();
    let second = observe::observe(&mut handle).await.unwrap();
    assert_eq!(
        first.links.keys().collect::<Vec<_>>(),
        second.links.keys().collect::<Vec<_>>()
    );
}
