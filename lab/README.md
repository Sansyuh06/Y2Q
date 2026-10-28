# Y2Q Lab Harness

Controlled local TLS 1.3 endpoints for testing classical and hybrid key exchange.

## Certificate Generation
Private keys are strictly excluded from version control. Generate temporary lab certificates before starting the containers:

```bash
mkdir -p lab/certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout lab/certs/server.key \
  -out lab/certs/server.crt \
  -days 365 \
  -subj "/CN=localhost"
```

## Running the Lab
Requires Docker and Docker Compose with OpenSSL 3.5+ inside the container:

```bash
docker compose -f lab/docker-compose.yml up -d
```

Classical endpoint listens on port 8443 (`X25519:prime256v1`).
Hybrid endpoint listens on port 9443 (`X25519MLKEM768:X25519:prime256v1`).
