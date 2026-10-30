# TLS Retry Test

Measures whether and how often a client retries a failed TLS handshake with a fresh PreMasterSecret. Each retry yields an independent ciphertext usable for the trimmer phase.

## Run

```bash
pip install scapy cryptography selenium
python3 server.py --domain lvh.me --fail-mode reset
```

A self-signed CA + server cert are generated on first run (`ca.pem`, `ca-key.pem`).

Trust the CA (macOS):

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
```

Open `http://localhost:8080/` in the target browser, or use the Selenium driver:

```bash
python3 test_browsers.py --modes reset
```

## How it works

1. Frontend on `:8080` captures User-Agent, returns a page with an `<img>` to a unique subdomain.
2. Backend on `:8443` parses the ClientHello, sends ServerHello + Certificate + ServerHelloDone, receives ClientKeyExchange, extracts the encrypted PMS, then fails the handshake (`--fail-mode`).
3. Each connection is logged with a ciphertext hash and small-prime divisibility.

`--fail-mode` choices: `reset`, `close`, `alert`, `bad_mac`, `decode_error`, `internal_error`, `close_notify`, `garbage`.
