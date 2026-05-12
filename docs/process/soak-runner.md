# Self-hosted soak runner — provisioning + operations

> Status: required configuration — operator action.
> Anchors: ENG-073, Sprint 68 task #687.

`.github/workflows/soak.yml` runs the 24-hour soak suite weekly (Sunday
02:00 UTC) and on `workflow_dispatch`. The workflow targets
`runs-on: [self-hosted, soak]` — a runner pool that does NOT yet exist
until the operator provisions it. This document captures the runner
requirements and the once-only provisioning procedure.

## Why a self-hosted runner

GitHub-hosted runners are capped at 6 hours per job (Ubuntu-latest);
the soak workflow needs 24+ hours. They are also throttled and noisy —
the soak gate needs a deterministic environment where:

- RSS plateau is observable (no co-tenant memory pressure)
- FD count is stable (no co-tenant socket churn)
- p99 latency drift can be attributed to the build under test, not the
  underlying host
- The runner can be physically isolated on its own NIC so 1 Gb/s+
  sustained traffic does not degrade other CI

## Hardware requirements

| Property | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 32 GiB | 64 GiB |
| CPU cores | 8 physical (16 logical) | 16 physical (32 logical) |
| Disk | 256 GiB SSD | 1 TiB NVMe |
| NIC | 1 Gb/s | 10 Gb/s |
| Network isolation | Dedicated VLAN OR baremetal on a dedicated switch port | Baremetal on a dedicated rack |
| OS | Ubuntu 22.04 LTS or 24.04 LTS | Ubuntu 24.04 LTS |
| Kernel | ≥ 6.1 | ≥ 6.6 |
| Disk encryption | LUKS at rest | LUKS + key sealed in TPM |

NOT acceptable: shared cloud VM with co-tenant burst credit (AWS T-series,
Azure B-series, GCP E2). The RSS/CPU isolation is essential.

## Software prerequisites

The runner host needs:

```sh
# Build toolchain.
sudo apt install -y build-essential pkg-config libssl-dev curl ca-certificates

# Rust (managed by rustup so the toolchain pinning in rust-toolchain.toml is honoured).
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"

# Tooling.
sudo apt install -y htop dstat lsof strace numactl

# A dedicated `heimdall-soak` user (the runner runs as this user, not root).
sudo useradd -r -s /usr/sbin/nologin -m -d /var/lib/heimdall-soak heimdall-soak
sudo install -d -o heimdall-soak -g heimdall-soak /var/lib/heimdall-soak/actions-runner
```

## Register the GitHub Actions runner

1. In the GitHub UI: `Settings → Actions → Runners → New self-hosted runner`.
2. Choose `Linux` / `x64`.
3. Copy the download URL and the registration token.
4. As the `heimdall-soak` user:

   ```sh
   cd /var/lib/heimdall-soak/actions-runner
   curl -fsSL -o actions-runner.tgz "${RUNNER_TARBALL_URL}"
   tar xzf actions-runner.tgz
   # The labels MUST include `soak` (and `self-hosted` is automatic).
   ./config.sh --url https://github.com/<owner>/Heimdall \
               --token <REGISTRATION_TOKEN> \
               --labels soak,self-hosted,linux,x64 \
               --name heimdall-soak-runner-01 \
               --unattended
   ```

5. Install the systemd service so the runner survives reboots:

   ```sh
   sudo ./svc.sh install heimdall-soak
   sudo ./svc.sh start
   sudo systemctl enable actions.runner.<owner>-Heimdall.heimdall-soak-runner-01.service
   ```

6. Verify the runner is online: GitHub `Settings → Actions → Runners` should
   show it as `Idle`. The `soak` label MUST be present.

## Host-level isolation

Apply the following sysctl tuning so the soak run is reproducible:

```sh
sudo tee /etc/sysctl.d/99-heimdall-soak.conf <<SYSCTL
# Network tuning for the soak workload (UDP-heavy, many short-lived TCP).
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.netdev_max_backlog = 65536
net.ipv4.udp_mem = 1048576 16777216 33554432
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
# Disable swap so RSS plateau is honest.
vm.swappiness = 0
# CPU governor: performance (set separately via cpupower).
SYSCTL
sudo sysctl --system
sudo cpupower frequency-set -g performance
# Disable transparent hugepages (some Rust allocator paths regress with it).
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
# Confirm no swap.
sudo swapoff -a
```

Persist the THP and swap settings via `/etc/fstab` and a systemd-rc.local
oneshot — examples in the upstream Ubuntu performance-tuning guide.

## Triggering a soak run

After the runner is online:

1. Operator picks the commit to soak. Typically a release-candidate tag.
2. `gh workflow run soak.yml --ref <tag-or-branch> -f duration_hours=24`
3. Watch progress in the Actions UI; the workflow uploads metrics
   artefacts every step on `if: always()`.
4. On success, download the `soak-artefacts-<sha>` artefact, extract,
   commit the report under `docs/bench/soak/<sha>/` (the workflow does NOT
   auto-commit because the host runner does not have a push token; the
   commit is operator action via `gh release upload` or a follow-up PR).
5. Inspect `target/soak/` for the per-scenario summary. Look for: RSS
   plateau, FD count returning to baseline, p99 < 1.20 × p99-baseline,
   no error spikes.

## Failure triage

The workflow's "Notify on failure" step prints the typical causes. On a
real failure:

1. Pull the artefact, open `target/soak/<scenario>/report.json`.
2. RSS growth → look for `Vec::push` in a hot loop without bound;
   check `cache::eviction` metrics; check `heimdall-runtime`'s
   `pending_queries` counter.
3. FD growth → look for `tokio::spawn` without `JoinSet` or `tokio::net`
   sockets dropped without a graceful close.
4. p99 drift → look for lock contention (`RwLock`) on the hot path; check
   the loom tests for race-free witnesses.

Open a SEV2 incident if the failure persists across reruns.

## Decommissioning

If the runner needs to be replaced:

```sh
cd /var/lib/heimdall-soak/actions-runner
sudo ./svc.sh stop
sudo ./svc.sh uninstall
./config.sh remove --token <REMOVAL_TOKEN>
```

Then provision the new runner per the steps above. The label `soak` MUST
be on exactly one active runner; multiple `soak` runners would cause the
weekly cron to fire once per runner, multiplying CI minutes.
