# Y2Q

## What It Does
Y2Q is a read-only command-line scanner that inspects TLS 1.3 key-exchange negotiation. For a given target, it performs a default handshake, a forced hybrid handshake offering X25519MLKEM768, and a forced classical control handshake offering X25519. It reports the observed key-exchange group and whether hybrid post-quantum negotiation succeeded.

## What It Does NOT Do
- Does not assess certificate chains, signature algorithms, or cipher suites.
- Does not claim an endpoint is quantum-safe or generate a CBOM.
- Does not evaluate server entropy, randomness, or key storage.
- Does not probe multiple vantage points or non-TLS services.

## Install and Usage
```sh
pip install .
y2q scan example.com
y2q scan --file targets.txt --json
```

Observed run against example.com (Windows 11, OpenSSL 3.5.7, Python 3.12.0):
```
Y2Q  example.com:443
scanner : OpenSSL 3.5.7
default          X25519MLKEM768   hybrid negotiated
forced_hybrid    X25519MLKEM768   accepted
forced_classical X25519           accepted
tls      TLSv1.3  TLS_AES_256_GCM_SHA384
verdict  HYBRID_NEGOTIATED
```

## Lab Harness
```sh
docker compose -f lab/docker-compose.yml up -d
y2q scan localhost -p 8443
y2q scan localhost -p 9443
```
Note: Requires an nginx build linked against OpenSSL 3.5+ with Docker running.

## Limitations
Single vantage point, key exchange only, single OpenSSL client build, no certificate or cipher-suite assessment, not a CBOM, no entropy visibility.

## Exit Codes and Output Formats
- Exit 0: All scanned targets yielded a conclusive verdict (HYBRID_NEGOTIATED or CLASSICAL_ONLY).
- Exit 2: Any target produced INCONCLUSIVE or had invalid input.
- Formats: Single target emits text or single JSON object with `--json`. Batch (`--file`) emits CSV by default or JSON Lines (one JSON object per line) with `--json`.
