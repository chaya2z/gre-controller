# gre-controller

A declarative GRE tunnel controller for Linux, written in Rust.

> [!NOTE]
> **Project status:** Release candidate (`0.1.0-rc.1`). `validate`, `run`, the systemd unit, and the DEB and RPM packages are implemented and tested in CI, but not yet proven in production. Behavior and file formats may still change before 0.1.0.

## Overview

`gre-controller` manages GRE interfaces on a Linux host from a single TOML configuration file. It periodically resolves tunnel endpoints and reconciles the kernel's network state with the declared configuration. This allows GRE tunnels to follow changes in DNS records, including dynamic DNS (DDNS), without requiring manual endpoint updates.

The controller manages GRE interfaces and their overlay IP addresses. It does not manage BGP, physical interfaces, firewall rules, or DDNS registration. Linux handles packet forwarding; the controller only manages the configuration.

## Features

- Declarative creation, update, and deletion of GRE interfaces.
- IPv4 and IPv6 underlays, with IPv4 and/or IPv6 overlay addresses.
- IP addresses and DNS names for both local and remote endpoints.
- Periodic reconciliation and automatic tracking of DNS address changes.
- Ownership checks to avoid modifying unrelated interfaces.
- A foreground process that can be managed by systemd.

## Requirements

- Linux 5.18 or later, with kernel support for GRE and/or IPv6 GRE. The controller relies on the address protocol attribute (`IFA_PROTO`) added in 5.18 to recognize its own addresses.
- Ubuntu or Fedora. Supported release versions are not fixed yet: the packages are built on Ubuntu 22.04 and tested on Ubuntu 22.04 (x86-64 and ARM64) and Fedora 44. Whatever the distribution, check that the running kernel is 5.18 or later (`uname -r`).
- Network administration privileges for running the controller.
- Reachable underlay endpoints and working name resolution when DNS names are used.

Other network management software must not manage the same GRE interfaces. Configure underlay connectivity, forwarding where needed, and firewall rules separately. GRE does not provide encryption or peer authentication by itself.

## Installation

Download the package or archive for your distribution and architecture (x86-64 or ARM64) from [GitHub Releases](https://github.com/chaya2z/gre-controller/releases), together with `SHA256SUMS`, and check it:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

The examples below use the first release candidate, `0.1.0-rc.1`. Package versions write the prerelease part with `~` (`0.1.0~rc.1`), so that package managers order it before the final `0.1.0`.

### Ubuntu

```sh
sudo apt install ./gre-controller_0.1.0~rc.1_amd64.deb
```

### Fedora

```sh
sudo dnf install ./gre-controller-0.1.0~rc.1-1.x86_64.rpm
```

The packages install the executable, a systemd unit, and an initial configuration file. The service is not started automatically on first installation. An APT or DNF repository is not required; install newer release packages using the same package manager. Upgrading restarts a running service; existing tunnels stay up. Removing the package stops and disables the service but leaves the managed GRE interfaces in place; delete them with `ip link delete` if they are no longer needed.

### Binary archive

The archive `gre-controller-0.1.0-rc.1-x86_64-linux-gnu.tar.gz` (or `-aarch64-`) contains the executable, the systemd unit, the initial configuration, and the license files. The executable links glibc dynamically. Install it manually:

```sh
tar -xzf gre-controller-0.1.0-rc.1-x86_64-linux-gnu.tar.gz
cd gre-controller-0.1.0-rc.1
sudo install -m 0755 gre-controller /usr/bin/
sudo install -m 0644 gre-controller.service /etc/systemd/system/
sudo install -D -m 0644 config.toml /etc/gre-controller/config.toml
sudo systemctl daemon-reload
```


## Configuration

Edit `/etc/gre-controller/config.toml`:

```toml
[tunnels.gre-peer01]
family = "ipv6"
local = "my-gateway.example.com"
remote = "peer-gateway.example.com"
addresses = ["10.0.1.1/31"]
```

| Field | Description |
| --- | --- |
| `tunnels.<name>` | Linux interface name. Each table declares one tunnel. |
| `family` | Underlay address family: `ipv4` or `ipv6`. |
| `local` | Local underlay IP address or DNS name. |
| `remote` | Remote underlay IP address or DNS name. |
| `addresses` | Local overlay IP addresses in CIDR notation. Both IPv4 and IPv6 can be specified. |

All four fields are required for each tunnel. The local underlay address must be assigned to the host. Configure the remote gateway separately, using the corresponding endpoints and overlay addresses. The example DNS names are placeholders.

Additional tunnels can be declared in the same file. The following example adds a dual-stack overlay over an IPv6 underlay:

```toml
[tunnels.gre-peer02]
family = "ipv6"
local = "my-gateway.example.com"
remote = "2001:db8:2::1"
addresses = ["10.0.2.0/31", "fd00:2::1/127"]
```

The controller re-reads the configuration during reconciliation. To remove a tunnel, delete or comment out its entire table, including all of its fields. To explicitly remove every managed tunnel, use:

```toml
[tunnels]
```

**Warning:** Removing a tunnel definition deletes its managed GRE interface and can interrupt dependent traffic or BGP sessions. A missing, blank, or invalid configuration file does not trigger deletion. Replace configuration files atomically when updating a running service.

## Usage

Validate the configuration before starting the service:

```sh
gre-controller validate
sudo systemctl enable --now gre-controller.service
```

`validate` checks the configuration without modifying the kernel, performing DNS lookups, or requiring network administration privileges.

Run the controller in the foreground (instead of the systemd service):

```sh
sudo gre-controller run
```

Do not run multiple controller instances against the same network namespace. A different configuration path can be specified for either command:

```sh
gre-controller --config ./config.toml validate
```

Use `gre-controller --help` and `gre-controller --version` for command help and version information.

### Service management

```sh
systemctl status gre-controller.service
journalctl -u gre-controller.service -f
sudo systemctl restart gre-controller.service
sudo systemctl stop gre-controller.service
```

Stopping or restarting the controller does not remove existing GRE interfaces. However, the controller cannot follow DNS or configuration changes while it is stopped. After a host reboot, an enabled service recreates its tunnels.

Inspect the actual kernel state using existing Linux tools (iproute2 is useful for troubleshooting, not intended as a runtime dependency of the controller):

```sh
ip -d link show dev gre-peer01
ip addr show dev gre-peer01
```

An existing GRE interface does not imply that the remote endpoint is reachable or that traffic is flowing.

## Design

See [Design and reconciliation](docs/design.md) for the management model, DNS behavior, ownership, failure handling, and service lifecycle.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
