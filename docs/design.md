# Design and reconciliation

> [!NOTE]
> This document describes the intended public behavior of gre-controller. It is a design document, not a claim of implemented or tested behavior. Currently only configuration parsing and offline validation are implemented.

## Management boundary

| Component | Responsibility |
| --- | --- |
| gre-controller | GRE interface lifecycle, local and remote endpoints, configured overlay addresses, administrative UP state |
| Linux kernel | GRE encapsulation/decapsulation, forwarding, and kernel-generated network state |
| NetworkManager / systemd-networkd / other host tooling | Underlay interfaces and addresses, unrelated interfaces |
| FRR or another routing daemon | Routing protocols, route advertisement and selection |
| DDNS client | Publishing and updating DNS records |
| systemd | Controller process lifecycle and log collection |

The controller does not manage routes explicitly, BGP configuration, forwarding policy, firewall rules, physical NICs, or DDNS registration. Connected routes created by the kernel as a consequence of assigning overlay addresses are expected. GRE TAP (Ethernet tunneling) is outside the scope.

The implementation uses Rust and Linux Netlink (rtnetlink) instead of invoking `ip` commands. The underlay `family` maps to the Linux `gre` or `ip6gre` interface kind. The overlay address family is independent of the underlay family.

## Configuration model

A single TOML file is the source of truth for managed tunnel definitions. The default path is `/etc/gre-controller/config.toml`. Interface names are the keys in the `tunnels` table; ordering is not significant.

Each tunnel has exactly these public configuration fields:

- `family`: `ipv4` or `ipv6` (underlay).
- `local`: IP literal or DNS name.
- `remote`: IP literal or DNS name.
- `addresses`: array of local overlay addresses in CIDR notation.

Reject invalid TOML, unknown fields, missing required fields, invalid interface names, invalid endpoint values, literal endpoint addresses that do not match the declared family, and invalid CIDRs before mutating kernel state. Preserve the host portion of overlay addresses; they are interface addresses, not just network prefixes.

Interface names, endpoints, and addresses are also subject to the following rules:

- Interface names follow the Linux kernel's naming rules: 1 to 15 bytes, not `.` or `..`, and without `/`, `:`, or whitespace. `%` is also rejected because the kernel treats such names as templates. These rules are provisional; additional restrictions may be added after testing.
- `addresses` must contain at least one address. Each address must be unique within a tunnel; the same IP address with a different prefix length is a duplicate. Unspecified and multicast addresses are rejected.
- Literal endpoint addresses must not be unspecified (`0.0.0.0` or `::`).
- DNS names consist of letters, digits, and hyphens, with labels of at most 63 characters and a total length of at most 253 characters; a trailing dot is allowed and underscores are not. A name whose last label is entirely numeric (for example, `10.0.1`) is rejected because resolvers may interpret it as a legacy IPv4 literal.

The schema is intentionally small. Reconciliation timing, MTU, GRE keys, TTL/hop limit, defaults, enable/disable flags, and deletion protection are not public configuration fields. MTU and other unmanaged attributes are not forcibly reset during reconciliation. Schema-version fields are not part of the current design; application releases and future schema compatibility are separate concerns.

An explicit empty `[tunnels]` table is valid and declares that no managed tunnels should remain. A missing `tunnels` table, including a blank or comment-only file, is invalid.

## Reconciliation model

The controller runs an immediate reconciliation on startup, followed by periodic reconciliation. Each pass reads a fresh snapshot of the configuration. A pass does not overlap another pass from the same process.

```text
Read configuration -> Validate entire configuration
                              |
                         valid only
                              v
                      Observe kernel state
                              |
                Resolve endpoints and validate
                              |
                 Compare desired / actual state
                              |
                   Apply necessary changes
                              |
                      Report and repeat
```

Configuration validation is global: an invalid snapshot must not cause any kernel changes in that pass. Runtime failures, such as DNS failures, are isolated to the affected tunnel where possible. If a reliable kernel snapshot cannot be obtained, do not perform destructive operations based on incomplete information. The interface and address dumps are used only if each one completes (ends with `NLMSG_DONE`) and the kernel does not mark it as interrupted by a concurrent change (`NLM_F_DUMP_INTR`); otherwise the pass makes no changes.

| Desired definition | Actual interface | Action |
| --- | --- | --- |
| Present | Absent | Create and configure |
| Present | Owned, matching | No operation |
| Present | Owned, different | Reconcile managed attributes |
| Present | Unowned, same name | Report a conflict; do not adopt or modify |
| Absent | Owned | Delete |
| Absent | Unowned | Ignore |

An unchanged configuration and unchanged resolved addresses must not cause redundant writes or interface recreation. An administratively DOWN managed interface is brought UP. Missing managed interfaces are recreated when the desired endpoints are valid.

## Endpoint resolution

Both endpoints accept literal addresses or DNS names. Literal addresses are used without DNS resolution. Names are resolved using the host's name resolution facilities. Only results matching the declared underlay family are eligible; duplicate results are treated as a single address. Unspecified addresses in the results are ignored. Each name is looked up once per pass, even if several tunnels use it.

The local endpoint must be assigned to the host. Addresses on controller-owned interfaces do not count, nor do IPv6 addresses that are still tentative or failed duplicate address detection. When multiple eligible addresses are returned, retain the currently configured endpoint if it is still eligible. Otherwise, select a candidate only if it is unique. Do not switch arbitrarily between multiple candidates. An unresolved or ambiguous endpoint prevents changes to the affected tunnel for that pass; an existing tunnel is retained and a missing tunnel is not created.

Resolution is retried periodically, including for tunnels whose configuration has not changed. DNS changes are therefore detected subject to resolver caching and the reconciliation interval. Retaining a previous endpoint does not guarantee connectivity. The controller does not register its own DNS records, perform peer health checks, or guarantee seamless endpoint changes.

## Updates and ownership

The controller identifies its own GRE interfaces using an explicit Linux interface alias (`gre-controller`) and checks the interface kind (`gre` or `ip6gre`). A matching name alone is not ownership. Pre-existing interfaces without the controller's ownership marker are never adopted automatically. The marker is an ownership convention, not an access-control boundary.

Linux does not apply the alias when it creates an interface, so a new interface is created DOWN and marked in a second request. If marking fails, the controller deletes the new interface again. If the process stops between the two requests, an unmarked interface with the tunnel's name remains; later passes report it as a conflict, and it has to be deleted manually.

| Change | Expected behavior |
| --- | --- |
| Local or remote endpoint | Update the existing interface in place where supported |
| Overlay address set | Add missing declared addresses; remove undeclared addresses the controller added |
| Underlay family | Requires an intentional interface replacement |
| Interface name | A new definition and removal of the old definition |
| Removed definition | Delete the owned interface |
| MTU or other unmanaged attributes | Do not intentionally reconcile them |

Endpoint updates should preserve interface identity (ifindex) and overlay addresses. They must also not change settings the controller does not manage, such as the MTU, TTL or hop limit, and GRE keys: an endpoint change sends the current MTU and every writable tunnel parameter as the kernel reports it, with only the local and remote addresses replaced. If the current settings cannot be read, the endpoints are not changed. If an in-place operation fails, do not silently fall back to deleting and recreating the interface. A deliberate family change is different: validate the new definition and resolve its endpoints before attempting replacement, and report any failure. Network interruption is possible during replacement or endpoint changes.

The controller marks every address it adds with the address protocol (`IFA_PROTO`) value `47`, chosen after the GRE IP protocol number. On a controller-managed interface, an address is removed only if it carries this value and is no longer declared. Addresses without it are left alone: kernel-generated addresses such as automatically configured IPv6 link-local addresses (`IFAPROT_KERNEL_LL`), and addresses added by other tools. They are also never adopted: a declared address that already exists without the marker counts as present, keeps its protocol, and is not removed when it is later undeclared. Addresses are added with `NLM_F_EXCL`, never replaced, so that an existing address is not re-marked. Replacing a controller address with other tools (for example `ip address replace`) clears its marker, and the controller stops managing it. Do not modify addresses on unrelated interfaces.

Kernel operations are not a multi-operation transaction. Validate inputs before making changes, verify operation results, report partial failures, and retry convergence. Do not promise atomic updates, rollback, or uninterrupted traffic.

## Failure behavior

| Failure | Expected behavior |
| --- | --- |
| Missing, unreadable, or invalid configuration | No kernel changes for that pass; retry |
| DNS lookup failure or ambiguity | Preserve affected tunnel; retry |
| Local endpoint not assigned | Preserve affected tunnel; retry |
| Unowned interface with matching name | No changes to that interface; report conflict |
| Netlink failure | Report failure; retry without unnecessary destructive recovery |
| Process failure | Existing kernel state remains unless an operation was already in progress; systemd restarts the process |

A single tunnel's runtime failure should not prevent reconciliation of unrelated, valid tunnels. The controller must never interpret a failed configuration read or failed kernel query as an empty desired or actual state.

## CLI and process lifecycle

`run` starts the controller in the foreground. `validate` performs offline configuration validation and exits successfully only for a valid configuration. Both accept `--config <PATH>`, with the system configuration path as the default. Standard help and version flags are provided. Invoking the executable without a subcommand must not change kernel state.

The process is managed by systemd in a packaged installation. It does not daemonize itself or maintain a PID file. Termination stops reconciliation without tearing down managed interfaces. Restarting the controller observes and reconciles the existing interfaces. An enabled service recreates them after a host reboot.

Transient runtime failures are logged and retried. The service must not require network readiness at startup to remain alive. Logs are emitted to standard output/error and collected by journald under systemd. State changes and failures are logged; unchanged reconciliations need not produce informational logs.

Only one controller should manage a network namespace. Run with the privileges necessary for Netlink configuration (typically `CAP_NET_ADMIN`) and restrict unrelated privileges where practical. Other network managers must not configure the same interfaces. The controller must not rewrite their configuration automatically.

## Distribution and upgrades

GitHub Releases is the intended distribution channel. DEB and RPM packages include a systemd service and configuration; binary archives support manual installation. Package upgrades preserve user configuration and should not unnecessarily recreate existing tunnels. Initial installation does not start the controller before the user configures it. No private package repository is required.
