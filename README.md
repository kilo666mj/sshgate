# sshgate

> **Written with AI.** This project was developed with the help of an AI
> assistant (Anthropic's Claude, via Claude Code). The code has been reviewed
> and tested, but treat it accordingly: read it before you run it, and see the
> security model below for what it does and does not protect.

`sshgate` is a small TCP proxy for SSH that passively fingerprints the
client's plaintext SSH handshake before forwarding traffic to a real `sshd`.
It records HASSH-style fingerprints from `SSH_MSG_KEXINIT`, then lets you
approve or block fingerprints before they reach the backend.

This is not authentication. SSH client fingerprints are spoofable, just like
TLS JA3/JA4 fingerprints. `sshgate` is intended as a friction layer against
generic scanners and unexpected client stacks; `sshd` still performs the real
user and key authentication.

## Build

Use Go 1.26.3 or newer.

```bash
go build -o sshgate .
go test ./...
```

## Run

Run your real SSH server on an internal-only port, then put `sshgate` on the
public port:

```bash
sshgate serve \
  --route [::]:22=127.0.0.1:2222 \
  --db ./sshgate.db \
  --config ./config.json
```

By default, new fingerprints are recorded as blocked and are not forwarded.
During enrollment, add `--allow-unknown` to record new fingerprints as pending
while still forwarding them. After approving known clients, remove
`--allow-unknown` to block pending and blocked fingerprints.

`sshgate` reads the client identification string and `SSH_MSG_KEXINIT` and
applies the verdict *before* it dials the backend, so a blocked or pending
client never opens a connection to your real `sshd` and never sees its banner.
This relies on the client sending its KEXINIT immediately after its banner (RFC
4253; OpenSSH does). A client that withholds KEXINIT until it receives the
server's identification will time out at the proxy.

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
  "max_fingerprints": 100000
}
```

`max_fingerprints` caps stored fingerprint entries. `0` (the default when unset)
applies a built-in cap of 100000, which bounds disk growth from randomized
KEXINIT material; set `-1` for unlimited storage. When the store exceeds the
cap, the oldest non-approved entries are pruned first; approved fingerprints are
never pruned.

## Correlate

`correlate` matches a fingerprint's known source IPs against `sshd` log lines
near the fingerprint's first/last seen timestamps:

```bash
sshgate correlate --db ./sshgate.db --log /var/log/auth.log <fingerprint>
```

Use `--log /var/log/secure` on distributions that write SSH authentication
events there. Use `--window 5m` to widen the matching window.

## Ansible Deployment

The repo includes an Ansible playbook that builds `sshgate` locally, installs it
under `/usr/local/bin`, creates a dedicated `sshgate` system user, and manages a
systemd service:

```bash
cd ansible
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

Edit `ansible/inventory` for the target host. Override these variables in the
inventory or with `-e` as needed:

```yaml
sshgate_binary: /usr/local/bin/sshgate
sshgate_data_dir: /var/lib/sshgate
sshgate_config_dir: /etc/sshgate
sshgate_routes:
  - "[::]:2222=127.0.0.1:22"
sshgate_allow_unknown: false
sshgate_max_fingerprints: 100000
sshgate_approved_fingerprints: []
sshgate_goarch: amd64
```

The playbook installs the binary at `/usr/local/bin/sshgate`, stores runtime state
under `/var/lib/sshgate`, and installs config at `/etc/sshgate/config.json`.
Only the data directory is writable by the `sshgate` user. The default route
listens on port `2222`, so the service does not need privileged bind
capabilities. It forwards to `127.0.0.1:22`; adjust the backend if your real
`sshd` listens somewhere else. The playbook cross-compiles a Linux binary
locally with `CGO_ENABLED=0`, deriving `GOARCH` from the target host's
architecture unless `sshgate_goarch` is overridden.

The Ansible default is deny-first: unknown fingerprints are recorded as blocked
and are not forwarded. Set `sshgate_allow_unknown: true` temporarily during
enrollment if you want new clients to pass through before approval.

You can also seed approved fingerprints during deployment:

```yaml
sshgate_approved_fingerprints:
  - fingerprint: "0123456789abcdef0123456789abcdef"
    label: "Alice laptop"
  - fingerprint: "fedcba9876543210fedcba9876543210"
    label: "CI deploy key"
```

Seeding is additive. The playbook approves the listed fingerprints with
`--register`, preserving existing database entries and leaving fingerprints not
listed in inventory unchanged.

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

## License

MIT. See [LICENSE](LICENSE).
