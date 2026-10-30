# ROBOT/Bleichenbacher Scan Pipeline

Docker Compose pipeline used for the Tranco Top 1M scan in Section 6. Discovers TLS hosts, filters those advertising RSA key exchange, and runs two independent ROBOT scanners (`robot-detect` and SSLyze) in parallel.

```
ZMap or input file -> input-targets -> job-manager -> zgrab2 -> RSA-only -> scanner queues -> ROBOT scanners -> robot-results
```

## Run

```bash
pip install -r requirements.txt
./scan.py reset
./scan.py start
./scan.py inject domains.txt          # or: ./scan.py zmap 192.168.1.0/24
./scan.py status
./scan.py results
./scan.py stop
```

## Configuration

Edit `config/default.yaml`. Toggle scanners under `bleichenbacher-scanners`. The `network.enabled` block puts scanner containers on a dedicated macvlan interface; auto-detect works on most Linux hosts.

## Tranco Top 1M

```bash
wget https://tranco-list.eu/top-1m.csv.zip
unzip top-1m.csv.zip
cut -d',' -f2 top-1m.csv > domains.txt
./scan.py start
./scan.py inject domains.txt
```

## Adding a scanner

Drop a service under `services/robot-scanner-<name>/` that reads from `<name>-batches` and writes results to `robot-results`. Required env vars: `REDIS_HOST`, `BATCH_QUEUE`, `RESULTS_QUEUE`, `RESULTS_FILE`, `CONCURRENCY`, `TIMEOUT`. Add a stanza to `docker-compose-pipeline.yml` and to `bleichenbacher-scanners` in the config.

Result format:

```json
{"ip": "1.2.3.4", "port": 443, "vulnerable": true, "vulnerability_level": "strong", "scanner": "robot-mytest", "scanned_at": "...", "error": null}
```
