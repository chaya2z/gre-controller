#!/usr/bin/env bash
# Runs the privileged integration tests (tests/netns.rs) inside a new,
# dedicated network namespace that is deleted afterwards.
#
# Needs root for `ip netns`; uses sudo unless already root. Extra arguments
# are passed to the test binary, for example a test name filter.
set -euo pipefail

sudo=()
if [[ $(id -u) -ne 0 ]]; then
    sudo=(sudo)
fi

ns="gre-controller-test-$$"

# Build first, so that a compile error does not leave a namespace behind.
cargo test --locked --test netns --no-run

"${sudo[@]}" ip netns add "$ns"
trap '"${sudo[@]}" ip netns delete "$ns"' EXIT
"${sudo[@]}" ip -n "$ns" link set lo up

# Cargo runs the test binary through this command. The variable lets the
# tests check that they really are inside the namespace.
host=$(rustc -vV | sed -n 's/^host: //p')
runner_var="CARGO_TARGET_$(tr 'a-z-' 'A-Z_' <<<"$host")_RUNNER"
export "$runner_var=${sudo[*]} ip netns exec $ns env GRE_CONTROLLER_TEST_NETNS=$ns"

# One thread: the tests share the namespace, and concurrent changes would
# make dumps fail with NLM_F_DUMP_INTR.
cargo test --locked --test netns -- --ignored --test-threads=1 "$@"
