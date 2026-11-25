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
