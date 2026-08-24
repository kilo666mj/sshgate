# sshgate

<p align="center">
  <img src="docs/art/sshgate-mark.png" alt="sshgate mark" width="260">
  <br>
  <a href="https://github.com/kilo666mj/gatehub"><img src="docs/art/porter-mascot.png" alt="Porter mascot for the gate tools" width="320"></a>
</p>

> **Written with AI.** This project was developed with the help of an AI
> assistant (Anthropic's Claude, via Claude Code). The code has been reviewed
> and tested, but treat it accordingly: read it before you run it.

`sshgate` is a small TCP proxy that passively fingerprints the client's
plaintext SSH handshake before forwarding traffic to a real `sshd`. It records
HASSH-style fingerprints from `SSH_MSG_KEXINIT`, then allows operators to
approve or block those fingerprints before key exchange reaches the backend.

It can run standalone or synchronize observations and decisions with
[Gatehub](https://github.com/kilo666mj/gatehub).

## Security boundary

SSH client fingerprints are spoofable. **This is not authentication.**

`sshgate` is a friction and logging layer against generic scanners and
unexpected client stacks. The real `sshd` must still perform user and key
authentication, and its normal hardening must remain in place.

Blocked and pending clients may receive the SSH banner, but they do not complete
key exchange with the backend.

## Quick start

Build and test with Go 1.26.3 or newer:

```sh
go build -o sshgate .
go test ./...
```

Move the real SSH server to an internal-only port, then run `sshgate` on the
public port:

```sh
./sshgate serve \
  --route [::]:22=127.0.0.1:2222 \
  --db ./sshgate.db \
  --config ./config.json
```

Unknown fingerprints are blocked by default. During enrollment, add
`--allow-unknown` so new fingerprints are recorded as pending while still
being forwarded. Review and approve known clients, then remove the flag:

```sh
./sshgate list -v --db ./sshgate.db
./sshgate approve --db ./sshgate.db --label "Alice laptop" <fingerprint>
```

## Configuration

The optional JSON configuration controls store limits and Gatehub
synchronization:

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

The default database is `/var/lib/sshgate/sshgate.db`; the default
configuration is `/etc/sshgate/config.json`. Gatehub also supports mTLS node
authentication in place of a bearer token.

## Deployment

The included Ansible playbook installs the binary, dedicated service account,
configuration, systemd unit, and hardened writable paths:

```sh
cd ansible
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

Because `sshgate` is inline with live SSH sessions, deployments use a graceful
tableflip handoff instead of terminating established connections.

See [deployment and graceful upgrades](docs/deployment.md) for inventory
variables, fingerprint seeding, and reload behavior.

## Documentation

- [Deployment and graceful upgrades](docs/deployment.md)
- [Operations and fingerprint reference](docs/operations.md)
- [Gatehub control plane](https://github.com/kilo666mj/gatehub)

## License

MIT. See [LICENSE](LICENSE).
