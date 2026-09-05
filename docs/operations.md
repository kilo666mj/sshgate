# Operations and fingerprint reference

Fingerprint management, Gatehub configuration, correlation, flood limits, and fingerprint construction.

## Manage Fingerprints

```bash
# List known fingerprints
sshgate list --db ./sshgate.db

# Include client version and raw fingerprint material
sshgate list -v --db ./sshgate.db

# Approve a fingerprint
sshgate approve --db ./sshgate.db --label "Alice laptop" <fingerprint>

# Block a fingerprint
sshgate block --db ./sshgate.db <fingerprint>

# Mark a fingerprint pending again
sshgate pending --db ./sshgate.db <fingerprint>

# Change a label
sshgate label --db ./sshgate.db <fingerprint> "Alice laptop"

# Delete an entry
sshgate delete --db ./sshgate.db <fingerprint>
```

The default database path is `/var/lib/sshgate/sshgate.db`.
The default config path is `/etc/sshgate/config.json`.

The Ansible deployment uses the same database default, so management commands
can use the default path:

```bash
sudo sshgate list
sudo sshgate approve --label "Alice laptop" <fingerprint>
```

Put flags before the fingerprint argument.

## Config

`serve` reads optional JSON config:

```json
{
  "max_fingerprints": 100000,
  "control_plane": {
    "url": "https://gatehub.example.com",
    "instance_id": "public-ssh",
    "token": "replace-with-node-token",
    "sync_interval": "30s"
  }
}
```

Configuration fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `max_fingerprints` | No | Stored-entry cap. `0` uses 100000; `-1` is unlimited. |
| `control_plane.url` | Enables sync | Gatehub base URL. Omitting it disables sync. |
| `control_plane.instance_id` | With URL | Stable name for this SSHGate instance. |
| `control_plane.token` | One auth method | Bearer token used to authenticate to Gatehub. |
| `control_plane.client_cert` | For mTLS | Client certificate path. |
| `control_plane.client_key` | For mTLS | Client private-key path. |
| `control_plane.ca` | For mTLS | CA bundle used to verify Gatehub. |
| `control_plane.server_name` | No | TLS name override when URL host and certificate differ. |
| `control_plane.sync_interval` | No | Go duration such as `30s`; defaults to 30 seconds. |

The control-plane URL must use HTTPS. HTTP URLs and redirects are rejected,
including redirects to another HTTPS endpoint. Configure the final URL directly.

Bearer authentication requires `token`. mTLS instead requires all three of
`client_cert`, `client_key`, and `ca`. Do not commit tokens or private keys.

Use `doctor` to validate and summarize startup inputs without opening the
database, connecting to the backend, or binding a port:

```bash
sshgate doctor \
  --db ./sshgate.db \
  --config ./config.json \
  --route '[::]:2222=127.0.0.1:22' \
  --allow-unknown
```

`max_fingerprints` caps stored fingerprint entries. `0` (the default when unset)
applies a built-in cap of 100000; set `-1` for unlimited fingerprint count.
New observations enforce the cap in the same transaction; periodic pruning also
handles rows added by policy synchronization. The oldest non-approved entries
are pruned first; approved fingerprints are never pruned.

The initial SSH packet is limited to 32 KiB, and encoded fingerprint metadata to
64 KiB. Each fingerprint retains at most 128 IPs, 128 ports, and the 128 most
recent IP/port sightings. The compatibility IP and port sets retain the first
128 values in sorted order. On opening an older database, excess history and
oversized metadata are removed while verdicts, labels, and counts are preserved.
SQLite can reuse freed pages; the file does not necessarily shrink.

Control-plane uploads use pages of 16 fingerprints instead of loading the entire
database into memory. Limits apply even to blocked clients. `-1` only disables
the fingerprint-count cap; metadata and history remain bounded.

When `control_plane.url` is set, `sshgate` syncs observed fingerprints to
`gatehub` and pulls approval decisions. Set `token` for bearer-token auth, or
set `client_cert`, `client_key`, and `ca` for mTLS auth. If the block is
omitted, sync is disabled and local CLI/database behavior is unchanged. The
optional `server_name` field overrides TLS server-name verification when the URL
host does not match the server certificate.

## Correlate

`correlate` matches a fingerprint's known source IPs against `sshd` log lines
near the fingerprint's first/last seen timestamps:

```bash
sshgate correlate --db ./sshgate.db --log /var/log/auth.log <fingerprint>
```

Use `--log /var/log/secure` on distributions that write SSH authentication
events there. Use `--window 5m` to widen the matching window.

## Troubleshooting

- **Permission denied opening the database:** the service user needs write
  access to the database directory, not only the database file.
- **Backend identification changed:** after an `sshd` upgrade changes its banner,
  the first allowed connection refreshes the cache and closes before forwarding
  KEXINIT. Retry the connection; this preserves SSH exchange-hash verification.
- **`BACKEND ... connection refused`:** verify `sshd` is listening on the
  backend address and port from `--route`.
- **A client sees the banner but cannot log in:** unknown, pending, and blocked
  clients stop before key exchange. Check `sshgate list`; use
  `--allow-unknown` only during deliberate enrollment.
- **An approved client changes fingerprint:** SSH client upgrades and algorithm
  policy changes can alter KEXINIT. Inspect `sshgate list -v` before approval.
- **The service is unreachable:** check its listener and firewall, then inspect
  `journalctl -u sshgate`.
- **Ansible cannot find `ansible.posix.firewalld`:** run
  `ansible-galaxy collection install ansible.posix`.


## Flood Limits

Rejected clients receive a cached backend identification and never open a backend
connection. Each route probes its backend once during startup, with a ten-second
timeout. Allowed connections verify the actual backend identification matches the
cached value before forwarding KEXINIT. Backend dialing and handshake reads/writes
are also bounded by timeouts.

Two connection limits protect the proxy:

- Per source IP: about 1 connection per second sustained, with a burst of 120.
  Connections over budget are dropped with a `RATELIMIT` log line.
- Global: at most 1024 connections are processed at once across all listeners.
  Connections above the cap are dropped with an `OVERLOAD` log line.

## What Is Fingerprinted

SSH exposes the client version string and initial key exchange algorithm lists
before encryption starts. `sshgate` records:

- client identification string, such as `SSH-2.0-OpenSSH_9.7`
- key exchange algorithms
- server host key algorithms
- client-to-server ciphers
- client-to-server MACs
- client-to-server compression algorithms

The fingerprint hash is the first 16 bytes of SHA-256 over this stable KEXINIT
material, encoded as 32 hex characters:

```text
kex_algorithms;server_host_key_algorithms;encryption_algorithms_client_to_server;encryption_algorithms_server_to_client;mac_algorithms_client_to_server;mac_algorithms_server_to_client;compression_algorithms_client_to_server;compression_algorithms_server_to_client;first_kex_packet_follows
```

Because those values are client-controlled, a determined client can spoof them.
Treat this as a policy and logging signal, not an identity proof.
