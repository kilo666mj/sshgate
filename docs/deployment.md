# Deployment and graceful upgrades

Ansible deployment, configuration, fingerprint seeding, and zero-downtime process upgrades.

## Installation

Download static Linux binaries from the
[GitHub releases page](https://github.com/kilo666mj/sshgate/releases), build
from source with Go 1.26.5 or newer, or use the container image published at
`ghcr.io/kilo666mj/sshgate`.

The container runs as UID 65532. A safe first run keeps the host's `sshd` on
port 22 and exposes SSHGate on port 2222:

```bash
mkdir -p sshgate-data
sudo chown 65532:65532 sshgate-data
docker run --rm --network host \
  -v "$PWD/sshgate-data:/var/lib/sshgate" \
  ghcr.io/kilo666mj/sshgate:latest \
  serve --allow-unknown --route '[::]:2222=127.0.0.1:22'
```

Host networking lets the container reach an `sshd` bound to the host's
loopback interface. With ordinary container networking, `127.0.0.1` means the
container itself.

## Ansible Deployment

The repo includes an Ansible playbook that builds `sshgate` locally, installs it
under `/usr/local/bin`, creates a dedicated `sshgate` system user, and manages a
systemd service:

```bash
cd ansible
cp inventory.example inventory
cp group_vars/sshgate.yml.example group_vars/sshgate.yml
# Edit inventory and group_vars/sshgate.yml for your deployment.
ansible-galaxy collection install ansible.posix
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

The real inventory and group variables files are ignored so deployment-specific
host names, fingerprints, and settings are not committed accidentally. Override
variables in `group_vars/sshgate.yml`, the inventory, or with `-e` as needed:

```yaml
sshgate_binary: /usr/local/bin/sshgate
sshgate_data_dir: /var/lib/sshgate
sshgate_config_dir: /etc/sshgate
sshgate_routes:
  - "[::]:2222=127.0.0.1:22"
sshgate_allow_unknown: false
sshgate_max_fingerprints: 100000
sshgate_control_plane: {}
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

## Graceful Upgrades

Because `sshgate` sits inline in the SSH data path, a plain process restart tears
down every live SSH session it is proxying — unlike restarting `sshd` itself,
whose existing sessions run in separate child processes and survive.

To get the same "restart without dropping connections" behavior, `sshgate` uses
[tableflip](https://github.com/cloudflare/tableflip). On `SIGHUP` it re-execs the
binary on disk (picking up a newly installed version), passes the listening
sockets to the new process, and keeps the old process alive to finish serving
its existing connections. New connections go to the new process immediately, so
none are refused during the handoff.

```bash
# Trigger a zero-downtime upgrade of a running instance
kill -HUP <pid>
# or, under systemd:
systemctl reload sshgate
```

The old process stops accepting, stops its background database writers, and waits
for its remaining sessions to close before exiting. `--drain-timeout` bounds that
wait (default `1h`, `0` waits indefinitely) so departing processes cannot pile up
after repeated upgrades while a long-lived session stays open — analogous to
nginx's `worker_shutdown_timeout`. During the drain window you may briefly see two
`sshgate` processes, which is expected.

The systemd unit is `Type=notify` with `NotifyAccess=all`: after an upgrade the
new server reports its PID to systemd via `sd_notify`, so `systemctl` keeps
tracking the process that is actually serving. The Ansible deployment reloads
(rather than restarts) on binary and config changes, so a deploy does not drop
active sessions — including Ansible's own connection when it runs through
`sshgate`.

Note that fingerprint approve/block changes never require a restart at all: each
new connection reads its verdict from the database live. Only binary upgrades and
`--route`/config changes need the process to reload.

## Site-specific migration scripts

The scripts under `scripts/` migrate the original author's randomized-port SSH
setup. They are examples, not the general installation path. They contain
firewall, service, `sshd`, and path assumptions; review them and use `--dry-run`
first. A migration refuses to proceed unless at least one
`--approve 'HASH|LABEL'` is supplied or enrollment is explicitly enabled with
`--allow-unknown`. Always keep a recovery SSH session open.
