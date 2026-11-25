# Testing

## Normal tests

```sh
cargo test --locked
```

These tests need no privileges and do not change the system. Some of them read the network state of the current namespace.

## Privileged integration tests

`tests/netns.rs` creates and changes network interfaces. Its tests are `#[ignore]`d, so `cargo test` skips them. Run them with:

```sh
scripts/netns-test.sh
```

The script:

1. Builds the tests as the current user.
2. Creates a new network namespace with `ip netns add` (through `sudo` unless already root).
3. Runs the tests inside it as root, one at a time, through Cargo's target runner.
4. Deletes the namespace on exit, including on failure.

Each test checks that it runs in the namespace the script created and fails otherwise, so `cargo test -- --ignored` on its own cannot change the host's network. Extra arguments go to the test binary, for example a test name filter: `scripts/netns-test.sh observes_owned_gre`.

Requirements: iproute2 with support for `ip address add ... proto`, `sudo`, and Linux 5.18 or later with GRE, IPv6 GRE, and veth support. CI runs the same script on a GitHub-hosted Ubuntu runner.

Failures that are hard to trigger on a real kernel, such as an interrupted dump (`NLM_F_DUMP_INTR`), an overrun, or a netlink error, are covered by unit tests with hand-built netlink messages instead.

## systemd unit

```sh
scripts/systemd-test.sh
```

Installs the debug build and `packaging/gre-controller.service` into `/usr/bin` and `/etc`, moves the service into a new network namespace with a drop-in (`NetworkNamespacePath=`), starts it under the real systemd, and checks that it creates the declared tunnels, logs to the journal with priorities and without warnings, and keeps the tunnels when stopped. Everything is removed on exit.

Run it only on a disposable machine: it refuses to run if gre-controller is already installed, but it still starts a system service. CI runs it in its own job, so that the GRE kernel modules are loaded on demand under the unit's sandboxing (`ProtectKernelModules=yes`) rather than by earlier tests.

## Packages

```sh
scripts/install-nfpm.sh    # needs cosign; verifies nfpm's signed checksums
scripts/build-packages.sh  # release binary, archive, DEB, and RPM in dist/
scripts/package-test.sh    # installs, upgrades, and removes them
```

`package-test.sh` installs the DEB on the machine itself and checks that the service is neither enabled nor started on first installation, that an upgrade keeps a modified configuration and restarts a running service, and that removal stops the service while purge removes the configuration. It installs the RPM in a `fedora:44` container, where systemd is not running, to check the same file handling and that the maintainer scripts tolerate the missing systemd. Run it only on a disposable Ubuntu machine with Docker; CI runs it on x86-64 and ARM64 runners.
