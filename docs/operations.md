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

`max_fingerprints` caps stored fingerprint entries. `0` (the default when unset)
applies a built-in cap of 100000, which bounds disk growth from randomized
KEXINIT material; set `-1` for unlimited storage. When the store exceeds the
cap, the oldest non-approved entries are pruned first; approved fingerprints are
never pruned.

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


## Flood Limits

Two built-in limits protect the proxy and fingerprint store:

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

