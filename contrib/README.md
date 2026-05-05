# Heimdall developer stack

One-command local environment that runs all three DNS roles plus observability.

## Prerequisites

- Docker with Compose V2 (`docker compose`)
- A local `heimdall:local` image — build it first:

```sh
docker buildx build -t heimdall:local .
```

## Quick start

```sh
docker compose -f contrib/docker-compose.yml up -d
docker compose -f contrib/docker-compose.yml ps   # all services should reach "healthy"
```

Allow ~10 s for health checks to pass, then exercise each role:

```sh
# Authoritative (example.com. served from tests/image/example.com.zone)
dig @127.0.0.1 -p 5353 example.com A

# Recursive
dig @127.0.0.1 -p 5354 example.com A

# Forwarder (forwards . to 1.1.1.1 / 8.8.8.8)
dig @127.0.0.1 -p 5355 example.com A
```

## Observability

| Service | URL |
|---|---|
| Grafana dashboard | <http://localhost:3000> (admin / admin) |
| Prometheus | <http://localhost:9191> |
| heimdall-auth metrics | <http://localhost:9081/metrics> (inside network only) |
| heimdall-recursive metrics | <http://localhost:9082/metrics> (inside network only) |
| heimdall-forwarder metrics | <http://localhost:9083/metrics> (inside network only) |

## Teardown

```sh
docker compose -f contrib/docker-compose.yml down
```
