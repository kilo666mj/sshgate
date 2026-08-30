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

Fingerprints describe an SSH client's advertised implementation and algorithm
set, not a unique device or user. Multiple machines may produce the same value.
Blocked and pending clients may receive the SSH banner, but they do not complete
key exchange with the backend.

## Safe quick start

Build and test with Go 1.26.5 or newer:

```sh
go build -o sshgate .
go test ./...
```

Keep `sshd` unchanged on port 22 and initially run `sshgate` on a second port:

```text
SSH client ──> sshgate :2222 ──> sshd 127.0.0.1:22
                    │
                    └──> SQLite fingerprint decisions
```

```sh
./sshgate serve \
  --allow-unknown \
  --route '[::]:2222=127.0.0.1:22' \
  --db ./sshgate.db \
  --config ./config.json
```

The config file is optional. From a second terminal, connect through port 2222,
inspect the new observation, and approve it:

```sh
ssh -p 2222 user@server.example.com
./sshgate list -v --db ./sshgate.db
./sshgate approve --db ./sshgate.db \
  --label "OpenSSH on my laptop" <fingerprint>
```

Restart without `--allow-unknown`, then verify the approved client can still
connect through port 2222. Keep an existing SSH session open while changing
firewall rules or moving `sshd` to an internal-only backend port.

For production, unknown fingerprints are blocked by default:

```sh
./sshgate serve \
  --route '[::]:22=127.0.0.1:2222' \
  --db ./sshgate.db \
  --config ./config.json
```

Validate the same inputs without opening the database or binding a port:

```sh
./sshgate doctor \
  --db ./sshgate.db \
  --config ./config.json \
  --route '[::]:2222=127.0.0.1:22'
```

## Deployment

The included Ansible playbook installs the binary, dedicated service account,
configuration, systemd unit, and hardened writable paths:

```sh
cd ansible
cp inventory.example inventory
cp group_vars/sshgate.yml.example group_vars/sshgate.yml
# Edit inventory and group_vars/sshgate.yml for your deployment.
ansible-galaxy collection install ansible.posix
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

The real inventory and group variables files are ignored so host names,
fingerprints, and deployment-specific settings are not committed accidentally.
Because `sshgate` is inline with live SSH sessions, deployments use a graceful
tableflip handoff instead of terminating established connections.

See [deployment and graceful upgrades](docs/deployment.md) for binaries,
containers, inventory variables, fingerprint seeding, and reload behavior.

## Documentation

- [Deployment and graceful upgrades](docs/deployment.md)
- [Operations, configuration, troubleshooting, and fingerprint reference](docs/operations.md)
- [Gatehub control plane](https://github.com/kilo666mj/gatehub)

## License

MIT. See [LICENSE](LICENSE).
