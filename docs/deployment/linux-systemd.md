# Heimdall — Linux / systemd Deployment Runbook

**Target**: Linux x86_64 or aarch64, systemd ≥ 240.

**See also**: [Operator Manual](../operator-manual.md),
[Configuration Reference](../configuration-reference.md).

---

## 1. Prerequisites

- Linux x86_64 or aarch64 (ENV-006 through ENV-008).
- systemd ≥ 240 (required for `RuntimeDirectory`, `StateDirectory`,
  `AmbientCapabilities`).
- `CAP_NET_BIND_SERVICE` capability available on the system (to bind port 53
  and port 853).

---

## 2. Create the dedicated user

The Heimdall process must run as a dedicated unprivileged user (THREAT-022).
Package installs (`.deb`, `.rpm`) create the user automatically. For manual
installs:

```sh
sudo useradd \
    --system \
    --home-dir /var/lib/heimdall \
    --create-home \
    --shell /sbin/nologin \
    --comment "Heimdall DNS server" \
    heimdall
```

---

## 3. Install from package

### 3.1 Debian / Ubuntu (`.deb`)

```sh
# Download the release package
curl -LO https://github.com/FlavioCFOliveira/Heimdall/releases/latest/download/heimdall_<version>_amd64.deb

# Verify the signature
cosign verify-blob \
    --certificate heimdall_<version>_amd64.deb.pem \
    --signature heimdall_<version>_amd64.deb.sig \
    heimdall_<version>_amd64.deb

# Install
sudo dpkg -i heimdall_<version>_amd64.deb
```

The package installs:
- Binary: `/usr/bin/heimdall`
- systemd unit: `/lib/systemd/system/heimdall.service`
- Example config: `/etc/heimdall/heimdall.toml` (if not already present)
- User/group: `heimdall`

### 3.2 RHEL / Fedora / CentOS (`.rpm`)

```sh
# Download and verify
curl -LO https://github.com/FlavioCFOliveira/Heimdall/releases/latest/download/heimdall-<version>.x86_64.rpm

cosign verify-blob \
    --certificate heimdall-<version>.x86_64.rpm.pem \
    --signature heimdall-<version>.x86_64.rpm.sig \
    heimdall-<version>.x86_64.rpm

# Install
sudo rpm -i heimdall-<version>.x86_64.rpm
```

---

## 4. Install from tar.gz (generic)

```sh
# Extract
tar xzf heimdall-<version>-x86_64-linux-musl.tar.gz

# Install binary
sudo install -m 755 heimdall/bin/heimdall /usr/bin/heimdall

# Install systemd unit
sudo install -m 644 heimdall/contrib/systemd/heimdall.service \
    /etc/systemd/system/heimdall.service

# Install example configuration
sudo mkdir -p /etc/heimdall
sudo install -m 640 -o root -g heimdall \
    heimdall/contrib/heimdall.toml.example \
    /etc/heimdall/heimdall.toml
```

---

## 5. Configure

Edit `/etc/heimdall/heimdall.toml`. The minimum viable recursive resolver:

```toml
[network]
listen = ["0.0.0.0:53", "[::]:53"]

[role]
mode = "recursive"

[log]
level = "info"
format = "json"
```

The configuration file must be owned by `root` and readable by the `heimdall`
group (`chmod 640 /etc/heimdall/heimdall.toml`).

For DoT/DoH/DoQ, add TLS configuration:

```toml
[network]
listen_dot = ["0.0.0.0:853"]

[tls]
certificate = "/etc/heimdall/tls/cert.pem"
private_key = "/etc/heimdall/tls/key.pem"
```

Place the TLS files in `/etc/heimdall/tls/` with mode `640`, group `heimdall`.

---

## 6. Enable and start

```sh
sudo systemctl daemon-reload
sudo systemctl enable heimdall
sudo systemctl start heimdall
```

Verify the service is active and systemd received the `sd_notify READY=1`
signal (OPS-032):

```sh
sudo systemctl status heimdall
```

Verify readiness via the observability endpoint:

```sh
curl http://127.0.0.1:8080/readyz
```

Verify DNS is being served:

```sh
dig @127.0.0.1 example.com A +short
```

---

## 7. Health check

The reference unit file does not include a `ExecStartPost` health check. For
environments that require one, add a drop-in:

```sh
sudo mkdir -p /etc/systemd/system/heimdall.service.d/
sudo tee /etc/systemd/system/heimdall.service.d/health.conf <<'EOF'
[Service]
ExecStartPost=/usr/bin/curl -sf http://127.0.0.1:8080/readyz
EOF
sudo systemctl daemon-reload
```

For Kubernetes or Docker, use the `/healthz` (liveness) and `/readyz`
(readiness) endpoints as HTTP probes.

---

## 8. Log rotation

If using the journal (default):

```sh
# Limit journal size for Heimdall
sudo mkdir -p /etc/systemd/journald.conf.d/
sudo tee /etc/systemd/journald.conf.d/heimdall.conf <<'EOF'
[Journal]
Storage=persistent
MaxRetentionSec=7day
EOF
sudo systemctl restart systemd-journald
```

If directing logs to a file via `StandardOutput=file:/var/log/heimdall.log`,
add a logrotate rule:

```
/var/log/heimdall.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload heimdall
    endscript
}
```

SIGHUP (sent by `systemctl reload`) re-opens log files. In-flight queries
are not affected (OPS-001 through OPS-004).

---

## 9. Upgrade

```sh
# Stop the service
sudo systemctl stop heimdall

# Install the new binary (package or tar.gz)
sudo dpkg -i heimdall_<new-version>_amd64.deb
# or
sudo install -m 755 heimdall-new/bin/heimdall /usr/bin/heimdall

# Reload the systemd unit if it changed
sudo systemctl daemon-reload

# Start the new version
sudo systemctl start heimdall

# Verify
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/version
```

For rolling upgrades in load-balanced deployments:
1. Remove the instance from the load balancer upstream pool.
2. Drain: `echo '{"cmd":"drain"}' | nc -U /run/heimdall/admin.sock`.
3. Wait for the drain to complete (`systemctl is-active heimdall` returns
   `inactive` when the process has exited).
4. Install the new binary and restart.
5. Verify `/readyz` returns 200.
6. Re-add the instance to the load balancer pool.
