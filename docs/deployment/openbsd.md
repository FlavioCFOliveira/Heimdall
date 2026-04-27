# Heimdall — OpenBSD Deployment Runbook

**Target**: OpenBSD x86_64 (amd64), current release.

**See also**: [Operator Manual](../operator-manual.md),
[Configuration Reference](../configuration-reference.md).

---

## 1. Prerequisites

- OpenBSD x86_64 (amd64), current stable release.
- `pledge(2)` and `unveil(2)` are applied by the Heimdall binary itself at
  startup (THREAT-029, THREAT-100 through THREAT-102). No external setup is
  required for sandbox confinement.
- To bind port 53 or 853, Heimdall must initially run as root and drop
  privileges after socket binding (THREAT-022). The rc.d script handles this.

---

## 2. Create the dedicated user

```sh
# Create the _heimdall system user (no home directory, no shell)
useradd -d /var/empty -s /sbin/nologin _heimdall
```

Package installs (when available from a port) create this user automatically.

---

## 3. Install the binary

```sh
# Download the release binary
ftp https://github.com/FlavioCFOliveira/Heimdall/releases/latest/download/heimdall-openbsd-amd64

# Verify the signature
signify -V -p heimdall-release.pub \
    -m heimdall-openbsd-amd64 \
    -x heimdall-openbsd-amd64.sig

# Install to /usr/local/bin
install -m 755 -o root -g bin heimdall-openbsd-amd64 /usr/local/bin/heimdall
```

---

## 4. Configure

```sh
# Create the configuration directory
mkdir -p /etc/heimdall
chmod 755 /etc/heimdall

# Install example configuration
cp contrib/heimdall.toml.example /etc/heimdall/heimdall.toml
chmod 640 /etc/heimdall/heimdall.toml
chown root:_heimdall /etc/heimdall/heimdall.toml
```

Edit `/etc/heimdall/heimdall.toml` for your deployment.

For the recursive role:

```toml
[network]
listen = ["0.0.0.0:53", "[::]:53"]

[role]
mode = "recursive"

[log]
level = "info"
format = "json"
```

---

## 5. Install the rc.d script

```sh
install -m 755 contrib/openbsd/heimdall.rc /etc/rc.d/heimdall
```

The rc.d script (THREAT-031):
- Sets `daemon_user="_heimdall"`.
- Creates `/var/run/heimdall/` and `/var/heimdall/` with mode `0750` in `rc_pre`.
- Sends `SIGHUP` for reload in `rc_reload`.

---

## 6. Enable and start

```sh
# Enable the daemon at boot
rcctl enable heimdall

# Start the daemon
rcctl start heimdall

# Check status
rcctl check heimdall
```

Verify DNS is being served:

```sh
dig @127.0.0.1 example.com A +short
```

---

## 7. Reload configuration

Configuration reload is triggered by SIGHUP (OPS-001 through OPS-006):

```sh
rcctl reload heimdall
```

**Important**: On OpenBSD, the `unveil(2)` set is fixed at process startup and
cannot be extended by a reload (THREAT-103). To grant access to a path that
was not in the initial unveil set (for example a new TLS certificate directory),
you must stop and restart the daemon:

```sh
rcctl stop heimdall
rcctl start heimdall
```

---

## 8. Upgrade

```sh
# Stop the daemon
rcctl stop heimdall

# Install the new binary
install -m 755 -o root -g bin heimdall-new /usr/local/bin/heimdall

# Start the new daemon
rcctl start heimdall

# Verify
dig @127.0.0.1 example.com A +short
```

Review the `CHANGELOG.md` before upgrading for any configuration file format
changes that require editing `/etc/heimdall/heimdall.toml`.

---

## 9. pledge / unveil scope

Heimdall applies `pledge(2)` and `unveil(2)` at startup. The scope is
determined by the active role set:

| Role | unveil paths (read) | unveil paths (read-write) |
|------|---------------------|--------------------------|
| All | `/etc/heimdall` | `/var/run/heimdall` |
| Recursive | `/etc/heimdall`, root hints path | `/var/heimdall` (trust anchor) |
| Authoritative | `/etc/heimdall`, zone dir | — |
| Forwarder | `/etc/heimdall` | — |

If Heimdall fails to start with `pledge: Operation not permitted` or
`unveil: No such file or directory`, verify that all referenced paths exist
and are accessible before the binary applies `unveil`.
