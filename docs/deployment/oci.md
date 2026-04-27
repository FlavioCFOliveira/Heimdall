# Heimdall — OCI / Docker Deployment Runbook

**Target**: Linux x86_64 or aarch64 with Docker, Podman, or any OCI-compliant
container runtime. Kubernetes-compatible.

The official Heimdall image is based on `gcr.io/distroless/static-debian12`
(ENV-026, ENV-033): a non-root, shell-less image containing only the static
Heimdall binary and CA certificates (required for DoT/DoH upstream connections).

**See also**: [Operator Manual](../operator-manual.md),
[Configuration Reference](../configuration-reference.md).

---

## 1. Prerequisites

- Docker ≥ 24.0 or Podman ≥ 4.0, or any OCI-compatible runtime.
- Sufficient privilege to run containers (or use rootless Podman/Docker).
- Outbound internet access for `gcr.io` (to pull the base image) or an
  internal registry mirror.

---

## 2. Build the image locally

```sh
git clone https://github.com/FlavioCFOliveira/Heimdall.git
cd Heimdall

# Build for the local platform
docker buildx build -t heimdall:local .

# Build multi-platform (requires buildx with a QEMU-capable builder)
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -t heimdall:local \
    --load \
    .
```

The build uses a two-stage Dockerfile: a `rust:slim-bookworm` builder stage
compiles with musl for static linking, then copies only the stripped binary
into the distroless final stage.

---

## 3. Prepare the configuration

Create a configuration directory on the host:

```sh
mkdir -p /etc/heimdall
cp contrib/heimdall.toml.example /etc/heimdall/heimdall.toml
# Edit as needed:
$EDITOR /etc/heimdall/heimdall.toml
```

For DoT/DoH/DoQ, create a TLS directory:

```sh
mkdir -p /etc/heimdall/tls
# Copy your certificate and private key:
cp cert.pem /etc/heimdall/tls/cert.pem
cp key.pem  /etc/heimdall/tls/key.pem
```

---

## 4. Run the container

### 4.1 Minimal recursive resolver (plain DNS only)

```sh
docker run \
    --rm \
    --name heimdall \
    -p 53:53/udp \
    -p 53:53/tcp \
    -v /etc/heimdall:/etc/heimdall:ro \
    --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    --read-only \
    heimdall:local
```

Notes:
- `--cap-add NET_BIND_SERVICE` is required to bind port 53 inside the container
  (THREAT-023).
- `--security-opt no-new-privileges` enforces `NoNewPrivileges` (THREAT-022).
- `--read-only` mounts the root filesystem read-only for the container;
  runtime state is handled by the process in the runtime directory.
- The container image runs as `nonroot:nonroot` (uid/gid 65532) by default.

### 4.2 With DoT and DoH

```sh
docker run \
    --rm \
    --name heimdall \
    -p 53:53/udp \
    -p 53:53/tcp \
    -p 853:853/tcp \
    -p 443:443/tcp \
    -v /etc/heimdall:/etc/heimdall:ro \
    -v /etc/heimdall/tls:/etc/heimdall/tls:ro \
    --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    --read-only \
    heimdall:local
```

### 4.3 With a writable runtime directory (admin-RPC, trust anchors)

```sh
mkdir -p /run/heimdall
chown 65532:65532 /run/heimdall

docker run \
    --rm \
    --name heimdall \
    -p 53:53/udp \
    -p 53:53/tcp \
    -v /etc/heimdall:/etc/heimdall:ro \
    -v /run/heimdall:/run/heimdall:rw \
    --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /tmp \
    heimdall:local
```

---

## 5. Health check

Docker supports HTTP health checks. Add to a `Dockerfile` overlay or via
`docker run`:

```sh
docker run \
    --health-cmd "curl -sf http://127.0.0.1:8080/healthz || exit 1" \
    --health-interval 10s \
    --health-timeout 5s \
    --health-retries 3 \
    --health-start-period 5s \
    ... \
    heimdall:local
```

Or add to `HEALTHCHECK` in a derived Dockerfile:

```dockerfile
FROM heimdall:local
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
    CMD ["/usr/bin/curl", "-sf", "http://127.0.0.1:8080/healthz"]
```

Note: the distroless base image does not include `curl`. Either use a derived
image that adds it, or use a TCP-probe health check:

```sh
--health-cmd "echo > /dev/tcp/127.0.0.1/53 2>/dev/null || exit 1"
```

---

## 6. Docker Compose example

```yaml
services:
  heimdall:
    image: heimdall:local
    container_name: heimdall
    restart: unless-stopped
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges
    read_only: true
    tmpfs:
      - /tmp
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"
    volumes:
      - type: bind
        source: /etc/heimdall
        target: /etc/heimdall
        read_only: true
      - type: bind
        source: /run/heimdall
        target: /run/heimdall
    environment:
      - RUST_LOG=info
    healthcheck:
      test: ["CMD-SHELL", "echo > /dev/tcp/127.0.0.1/53 2>/dev/null"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
```

---

## 7. Kubernetes deployment (example)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: heimdall
  namespace: dns
spec:
  replicas: 2
  selector:
    matchLabels:
      app: heimdall
  template:
    metadata:
      labels:
        app: heimdall
    spec:
      containers:
        - name: heimdall
          image: heimdall:local
          args: ["--config", "/etc/heimdall/heimdall.toml"]
          ports:
            - containerPort: 53
              protocol: UDP
              name: dns-udp
            - containerPort: 53
              protocol: TCP
              name: dns-tcp
            - containerPort: 8080
              protocol: TCP
              name: observability
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
              add: ["NET_BIND_SERVICE"]
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          volumeMounts:
            - name: config
              mountPath: /etc/heimdall
              readOnly: true
            - name: runtime
              mountPath: /run/heimdall
      volumes:
        - name: config
          configMap:
            name: heimdall-config
        - name: runtime
          emptyDir: {}
```

---

## 8. Upgrade

```sh
# Pull the new image
docker pull heimdall:<new-version>

# Stop the old container
docker stop heimdall

# Remove the old container
docker rm heimdall

# Run the new container with the same arguments
docker run --name heimdall ... heimdall:<new-version>
```

For Kubernetes rolling upgrades, update the image tag in the `Deployment` spec
and apply; Kubernetes will perform the rolling update respecting readiness
probes.
