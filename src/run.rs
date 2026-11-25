//! The reconciliation loop behind `gre-controller run`.
//!
//! Each pass reads the configuration, observes the kernel, resolves endpoints, plans,
//! and applies the plan. A pass that cannot read a valid configuration or a complete
//! kernel snapshot changes nothing. Passes run one after another; the next one starts
//! [`INTERVAL`] after the previous one finished.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use rtnetlink::Handle;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};

use crate::apply;
use crate::config::{self, Config, ConfigError, InterfaceName};
use crate::observe::{self, ObserveError, Snapshot};
use crate::plan::{self, Change, Conflict, Decision, DesiredTunnel, ObservedLink, TunnelSpec};
use crate::resolve::{self, SystemResolver, Unresolved};

/// Time between the end of one pass and the start of the next.
pub const INTERVAL: Duration = Duration::from_secs(180);

/// Runs passes until `SIGTERM` or `SIGINT`.
///
/// A signal that arrives during a pass takes effect when the pass is complete, so an
/// interface is never left half-created by the controller's own shutdown. Managed
/// interfaces are left in place.
///
/// # Errors
///
/// Returns an error if the netlink socket or the signal handlers cannot be set up.
/// Failures during a pass are logged, not returned.
pub async fn run(config_path: &Path) -> io::Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut handle = observe::connect()?;
    info!(
        config = %config_path.display(),
        interval_secs = INTERVAL.as_secs(),
        "started"
    );
    loop {
        let result = pass(config_path, &mut handle).await;
        if matches!(result, Err(PassError::ConnectionLost)) {
            match observe::connect() {
                Ok(new) => handle = new,
                Err(error) => error!("cannot reopen the netlink socket: {error}"),
            }
        }
        tokio::select! {
            () = tokio::time::sleep(INTERVAL) => {}
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    info!("stopped");
    Ok(())
}

enum PassError {
    /// The pass was skipped; the reason has been logged.
    Skipped,
    /// The netlink connection no longer accepts requests.
    ConnectionLost,
}

async fn pass(config_path: &Path, handle: &mut Handle) -> Result<(), PassError> {
    let config = config::load(config_path).map_err(|error| {
        log_config_error(&error);
        PassError::Skipped
    })?;
    let snapshot = observe::observe(handle).await.map_err(|error| {
        error!("cannot read the kernel state, skipping this pass: {error}");
        match error {
            ObserveError::Request(_) => PassError::ConnectionLost,
            _ => PassError::Skipped,
        }
    })?;
    let resolved = resolve_off_runtime(config, &snapshot).await?;
    let desired = desired(resolved);
    warn_unadopted_addresses(&desired, &snapshot.links);

    let decisions = plan::plan(&desired, &snapshot.links);
    for (name, decision) in &decisions {
        if let Decision::Conflict(conflict) = decision {
            warn!(interface = %name, "{}", conflict_message(conflict));
        }
    }
    let results = apply::apply(handle, &decisions, &snapshot).await;
    for (name, result) in results {
        match result {
            Ok(()) => info!(interface = %name, "{}", success_message(&decisions[&name])),
            Err(error) => error!(interface = %name, "{error}"),
        }
    }
    Ok(())
}

fn log_config_error(error: &ConfigError) {
    match error {
        // One entry per problem, so that each is a complete log line.
        ConfigError::Invalid(errors) => {
            for error in errors {
                error!("invalid configuration, skipping this pass: {error}");
            }
        }
        other => error!("{other}, skipping this pass"),
    }
}

/// Runs the blocking DNS lookups on Tokio's blocking thread pool.
async fn resolve_off_runtime(
    config: Config,
    snapshot: &Snapshot,
) -> Result<BTreeMap<InterfaceName, Result<TunnelSpec, Unresolved>>, PassError> {
    let links = snapshot.links.clone();
    let host_addresses = snapshot.host_addresses.clone();
    tokio::task::spawn_blocking(move || {
        resolve::resolve(&config, &links, &host_addresses, &SystemResolver)
    })
    .await
    .map_err(|error| {
        error!("endpoint resolution failed, skipping this pass: {error}");
        PassError::Skipped
    })
}

/// Turns resolution results into the planner's input, logging unresolved tunnels.
fn desired(
    resolved: BTreeMap<InterfaceName, Result<TunnelSpec, Unresolved>>,
) -> BTreeMap<InterfaceName, DesiredTunnel> {
    resolved
        .into_iter()
        .map(|(name, result)| {
            let tunnel = match result {
                Ok(spec) => DesiredTunnel::Resolved(spec),
                Err(unresolved) => {
                    warn!(interface = %name, "endpoints unresolved, leaving the tunnel as it is: {unresolved}");
                    DesiredTunnel::Unresolved
                }
            };
            (name, tunnel)
        })
        .collect()
}

/// Warns about declared addresses that already exist on an owned interface without the
/// controller's marker. They count as present but are not managed, so removing them
/// from the configuration will not remove them from the interface.
fn warn_unadopted_addresses(
    desired: &BTreeMap<InterfaceName, DesiredTunnel>,
    observed: &BTreeMap<InterfaceName, ObservedLink>,
) {
    for (name, tunnel) in desired {
        let (DesiredTunnel::Resolved(spec), Some(link)) = (tunnel, observed.get(name)) else {
            continue;
        };
        if !link.is_owned() {
            continue;
        }
        for address in &link.addresses {
            if !address.is_owned() && spec.addresses.contains(&address.net) {
                warn!(
                    interface = %name,
                    address = %address.net,
                    "declared address was not added by gre-controller; it is kept, but will not be removed if it is undeclared"
                );
            }
        }
    }
}

fn conflict_message(conflict: &Conflict) -> String {
    match conflict {
        Conflict::NotMarked => {
            "an interface with this name exists but was not created by gre-controller; leaving it unchanged".to_owned()
        }
        Conflict::UnexpectedKind(kind) => format!(
            "the interface carries the gre-controller alias but is of kind {kind:?}; leaving it unchanged"
        ),
    }
}

fn success_message(decision: &Decision) -> String {
    match decision {
        Decision::Create(spec) => format!(
            "created ({} {} -> {})",
            spec.family, spec.endpoints.local, spec.endpoints.remote
        ),
        Decision::Update(changes) => {
            let changes: Vec<String> = changes.iter().map(change_message).collect();
            format!("updated: {}", changes.join(", "))
        }
        Decision::Replace(spec) => format!(
            "replaced for the family change ({} {} -> {})",
            spec.family, spec.endpoints.local, spec.endpoints.remote
        ),
        Decision::Delete => "deleted (no longer declared)".to_owned(),
        // `apply` reports no result for these.
        Decision::Conflict(_) | Decision::Defer => String::new(),
    }
}

fn change_message(change: &Change) -> String {
    match change {
        Change::SetEndpoints(endpoints) => {
            format!("endpoints {} -> {}", endpoints.local, endpoints.remote)
        }
        Change::RemoveAddress(address) => format!("removed {address}"),
        Change::AddAddress(address) => format!("added {address}"),
        Change::SetUp => "set up".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Family;
    use crate::plan::Endpoints;

    use super::*;

    #[test]
    fn describes_applied_decisions() {
        let endpoints = Endpoints {
            local: "192.0.2.1".parse().unwrap(),
            remote: "198.51.100.1".parse().unwrap(),
        };
        let spec = TunnelSpec {
            family: Family::Ipv4,
            endpoints,
            addresses: vec!["10.0.0.1/31".parse().unwrap()],
        };
        assert_eq!(
            success_message(&Decision::Create(spec)),
            "created (ipv4 192.0.2.1 -> 198.51.100.1)"
        );
        assert_eq!(
            success_message(&Decision::Update(vec![
                Change::SetEndpoints(endpoints),
                Change::RemoveAddress("10.0.0.1/31".parse().unwrap()),
                Change::AddAddress("10.0.1.1/31".parse().unwrap()),
                Change::SetUp,
            ])),
            "updated: endpoints 192.0.2.1 -> 198.51.100.1, removed 10.0.0.1/31, \
             added 10.0.1.1/31, set up"
        );
        assert_eq!(
            success_message(&Decision::Delete),
            "deleted (no longer declared)"
        );
    }
}
