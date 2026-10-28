# Y2Q

## What It Does
Y2Q inspects TLS 1.3 key-exchange negotiation and evaluates a controlled
HNDL discrete-logarithm experiment. For TLS scanning, it runs a default handshake,
a forced hybrid handshake offering X25519MLKEM768, and a forced classical control
handshake offering X25519.

## Controlled HNDL Experiment
Module B implements a Shor-style discrete-log circuit over a cyclic group of
order 32, encoded as integers, not an elliptic-curve implementation (arXiv:2507.10592).
It evaluates synthetic key recovery in Z_32 without breaking real cryptography.

## Install and Usage
Scanner has zero runtime dependencies: `pip install .`
Optional quantum and cryptographic extras: `pip install .[hndl]`

```sh
y2q scan example.com
y2q scan --file data/targets.txt > data/scan.csv
y2q hndl --prepare --out artifacts/hndl/case_01
y2q hndl --challenge artifacts/hndl/case_01/challenge.json --backend simulator
y2q report --scan data/scan.csv --hndl artifacts/hndl/case_01/run_01.json
```

## Survey Dataset Provenance
Captured 2026-10-28 between 00:15:26Z and 00:16:14Z in a single batch run from one
scanner host vantage point using OpenSSL 3.5.7.
Results across 35 endpoints: 22 of 35 endpoints negotiated HYBRID_NEGOTIATED,
9 of 35 endpoints negotiated CLASSICAL_ONLY, and 4 of 35 endpoints were INCONCLUSIVE.

## Lab Harness
Docker Compose configurations are in `lab/`. Docker daemon was unreachable in this
environment, so containerized endpoints could not be live-validated.

## Limitations
- Toy discrete-log circuit operates on Z_32 integers and cannot decrypt real X25519.
- Breaking classical key exchange does not reveal the ML-KEM lattice shared secret.
- No hardware quantum execution exists; simulator execution only.
- Survey dataset reflects a single vantage point, not global adoption.

## Exit Codes
- Exit 0: All scanned targets conclusive, or HNDL attack successfully verified.
- Exit 2: Any inconclusive scan target, invalid argument, or HNDL recovery failure.
