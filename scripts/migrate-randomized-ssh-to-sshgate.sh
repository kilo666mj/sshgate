#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

SSH_PORT=2222
SSHD_PORT=22
SSHD_LISTEN_ADDRESS=127.0.0.1
SSHGATE_BINARY_SRC=""
SSHGATE_BINARY=/usr/local/bin/sshgate
SSHGATE_USER=sshgate
SSHGATE_GROUP=sshgate
SSHGATE_DATA_DIR=/var/lib/sshgate
SSHGATE_CONFIG_DIR=/etc/sshgate
SSHGATE_CONFIG=/etc/sshgate/config.json
SSHGATE_DB=/var/lib/sshgate/sshgate.db
SSHD_CONFIG=/etc/ssh/sshd_config
SSHD_CONFIG_SRC=""
SSHD_BIN=""
RANDOMIZER_PATH=/root/code/ssh_port/ssh_server_port_randomizer.sh
DRY_RUN=0

APPROVED_FINGERPRINTS=(
	"aaf62b02afeaa8df0687aa49b07825f8|macbook"
	"da077e892bd3189b77ba40af5a9a807e|debian13-servers"
	"117974a5daef83386fe315f08177932a|desktop"
)

usage() {
	cat <<EOF
usage: $0 [options]

Migrates a host from ssh_server_port_randomizer.sh to sshgate.

Options:
  --sshgate-binary-src PATH  Install this local sshgate binary first.
  --sshgate-binary PATH      Installed sshgate path. Default: $SSHGATE_BINARY
  --randomizer-path PATH     Cron script path to disable. Default: $RANDOMIZER_PATH
  --sshd-config-src PATH     Install this sshd_config after validation.
  --sshgate-port PORT        External sshgate port. Default: $SSH_PORT
  --sshd-port PORT           Backend sshd port. Default: $SSHD_PORT
  --sshd-listen-address IP   Backend sshd listen address. Default: $SSHD_LISTEN_ADDRESS
  --dry-run                  Print actions without changing the host.
  -h, --help                 Show this help.

Run this as root from a persistent session such as tmux. Keep an existing SSH
session open until the final listener checks pass.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--sshgate-binary-src)
			SSHGATE_BINARY_SRC=${2:?missing path}
			shift 2
			;;
		--sshgate-binary)
			SSHGATE_BINARY=${2:?missing path}
			shift 2
			;;
		--randomizer-path)
			RANDOMIZER_PATH=${2:?missing path}
			shift 2
			;;
		--sshd-config-src)
			SSHD_CONFIG_SRC=${2:?missing path}
			shift 2
			;;
		--sshgate-port)
			SSH_PORT=${2:?missing port}
			shift 2
			;;
		--sshd-port)
			SSHD_PORT=${2:?missing port}
			shift 2
			;;
		--sshd-listen-address)
			SSHD_LISTEN_ADDRESS=${2:?missing address}
			shift 2
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

log() {
	printf '%s\n' "$*"
}

run() {
	log "+ $*"
	if [ "$DRY_RUN" -eq 0 ]; then
		"$@"
	fi
}

write_file() {
	local path=$1
	local mode=$2
	local owner=$3
	local group=$4
	local tmp

	log "+ install file $path"
	if [ "$DRY_RUN" -ne 0 ]; then
		sed 's/^/  /'
		return
	fi

	tmp=$(mktemp)
	cat > "$tmp"
	install -m "$mode" -o "$owner" -g "$group" "$tmp" "$path"
	rm -f "$tmp"
}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "must run as root" >&2
		exit 1
	fi
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

resolve_sshd() {
	local path

	if path=$(command -v sshd 2>/dev/null); then
		SSHD_BIN=$path
		return
	fi
	for path in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
		if [ -x "$path" ]; then
			SSHD_BIN=$path
			return
		fi
	done

	echo "missing required command: sshd" >&2
	exit 1
}

backup_file() {
	local path=$1
	local backup="${path}.sshgate-migration.$(date +%Y%m%d%H%M%S)"

	if [ -e "$path" ]; then
		run cp -a "$path" "$backup"
	fi
}

current_sshd_port() {
	local port

	port=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ { print $2; exit }' "$SSHD_CONFIG" 2>/dev/null || true)
	if [ -z "$port" ]; then
		port=22
	fi
	printf '%s\n' "$port"
}

disable_user_crontab() {
	local user=$1
	local before after

	before=$(mktemp)
	after=$(mktemp)
	if ! crontab -u "$user" -l > "$before" 2>/dev/null; then
		rm -f "$before" "$after"
		return
	fi
	if ! grep -Fq "$RANDOMIZER_PATH" "$before"; then
		rm -f "$before" "$after"
		return
	fi

	log "+ disable $RANDOMIZER_PATH in $user crontab"
	awk -v pat="$RANDOMIZER_PATH" '
		index($0, pat) && $0 !~ /^[[:space:]]*#/ {
			print "# disabled by sshgate migration: " $0
			next
		}
		{ print }
	' "$before" > "$after"
	if [ "$DRY_RUN" -eq 0 ]; then
		crontab -u "$user" "$after"
	fi
	rm -f "$before" "$after"
}

disable_cron_randomizer() {
	disable_user_crontab root
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		disable_user_crontab "$SUDO_USER"
	fi

	if [ -d /etc/cron.d ]; then
		while IFS= read -r file; do
			[ -f "$file" ] || continue
			if grep -Fq "$RANDOMIZER_PATH" "$file"; then
				backup_file "$file"
				log "+ disable $RANDOMIZER_PATH in $file"
				if [ "$DRY_RUN" -eq 0 ]; then
					sed -i "\|$RANDOMIZER_PATH| s|^[[:space:]]*|# disabled by sshgate migration: |" "$file"
				fi
			fi
		done < <(find /etc/cron.d -type f)
	fi
}

ensure_user() {
	if ! getent group "$SSHGATE_GROUP" >/dev/null; then
		run groupadd --system "$SSHGATE_GROUP"
	fi
	if ! id "$SSHGATE_USER" >/dev/null 2>&1; then
		local nologin=/usr/sbin/nologin
		if [ ! -x "$nologin" ]; then
			nologin=/sbin/nologin
		fi
		run useradd --system --gid "$SSHGATE_GROUP" --home-dir "$SSHGATE_DATA_DIR" --no-create-home --shell "$nologin" "$SSHGATE_USER"
	fi
}

install_sshgate_binary() {
	if [ -n "$SSHGATE_BINARY_SRC" ]; then
		if [ ! -f "$SSHGATE_BINARY_SRC" ]; then
			echo "sshgate binary source not found: $SSHGATE_BINARY_SRC" >&2
			exit 1
		fi
		run install -m 0755 -o root -g root "$SSHGATE_BINARY_SRC" "$SSHGATE_BINARY"
	fi
	if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$SSHGATE_BINARY" ]; then
		echo "sshgate binary is not executable: $SSHGATE_BINARY" >&2
		echo "pass --sshgate-binary-src /path/to/sshgate or install it first" >&2
		exit 1
	fi
}

install_sshgate_config() {
	run mkdir -p "$SSHGATE_DATA_DIR" "$SSHGATE_CONFIG_DIR"
	run chown "$SSHGATE_USER:$SSHGATE_GROUP" "$SSHGATE_DATA_DIR"
	run chmod 0750 "$SSHGATE_DATA_DIR"
	run chown "root:$SSHGATE_GROUP" "$SSHGATE_CONFIG_DIR"
	run chmod 0750 "$SSHGATE_CONFIG_DIR"

	printf '{\n  "max_fingerprints": 100000\n}\n' | write_file "$SSHGATE_CONFIG" 0640 root "$SSHGATE_GROUP"
}

install_sshgate_service() {
	cat <<EOF | write_file /etc/systemd/system/sshgate.service 0644 root root
[Unit]
Description=sshgate SSH fingerprinting proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SSHGATE_USER
Group=$SSHGATE_GROUP
ExecStart=$SSHGATE_BINARY serve --db $SSHGATE_DB --config $SSHGATE_CONFIG --route=[::]:$SSH_PORT=$SSHD_LISTEN_ADDRESS:$SSHD_PORT
Restart=on-failure
RestartSec=2s
StandardOutput=journal
StandardError=journal
LimitNOFILE=8192

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=$SSHGATE_DATA_DIR
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

	run systemctl daemon-reload
}

seed_approved_fingerprints() {
	local item fp label

	for item in "${APPROVED_FINGERPRINTS[@]}"; do
		fp=${item%%|*}
		label=${item#*|}
		run "$SSHGATE_BINARY" approve --db "$SSHGATE_DB" --register --label "$label" "$fp"
	done
	run chown -R "$SSHGATE_USER:$SSHGATE_GROUP" "$SSHGATE_DATA_DIR"
}

configure_sshd_backend() {
	local tmp

	if [ -n "$SSHD_CONFIG_SRC" ]; then
		if [ ! -f "$SSHD_CONFIG_SRC" ]; then
			echo "sshd_config source not found: $SSHD_CONFIG_SRC" >&2
			exit 1
		fi
		run "$SSHD_BIN" -t -f "$SSHD_CONFIG_SRC"
		backup_file "$SSHD_CONFIG"
		run install -m 0644 -o root -g root "$SSHD_CONFIG_SRC" "$SSHD_CONFIG"
		return
	fi

	backup_file "$SSHD_CONFIG"
	tmp=$(mktemp)
	awk -v port="$SSHD_PORT" -v listen="$SSHD_LISTEN_ADDRESS" '
		BEGIN { saw_port = 0; saw_listen = 0; emitted = 0 }
		function emit_backend() {
			if (emitted) {
				return
			}
			if (!saw_port) {
				print "Port " port
			}
			if (!saw_listen) {
				print "ListenAddress " listen
			}
			emitted = 1
		}
		/^[[:space:]]*Match[[:space:]]+/ {
			emit_backend()
			print
			next
		}
		/^[[:space:]]*#?[[:space:]]*Port[[:space:]]+/ {
			if (!saw_port) {
				print "Port " port
				saw_port = 1
			}
			next
		}
		/^[[:space:]]*#?[[:space:]]*ListenAddress[[:space:]]+/ {
			if (!saw_listen) {
				print "ListenAddress " listen
				saw_listen = 1
			}
			next
		}
		{ print }
		END {
			emit_backend()
		}
	' "$SSHD_CONFIG" > "$tmp"

	run "$SSHD_BIN" -t -f "$tmp"

	log "+ update $SSHD_CONFIG for sshd backend $SSHD_LISTEN_ADDRESS:$SSHD_PORT"
	if [ "$DRY_RUN" -eq 0 ]; then
		install -m 0644 -o root -g root "$tmp" "$SSHD_CONFIG"
	fi
	rm -f "$tmp"
}

restart_sshd() {
	local service=sshd

	if ! systemctl list-unit-files sshd.service >/dev/null 2>&1; then
		service=ssh
	fi
	run systemctl restart "$service"
}

update_firewalld() {
	local old_port=$1

	if ! systemctl is-active --quiet firewalld; then
		log "firewalld is not active; skipping firewall changes"
		return
	fi

	run firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
	if [ "$old_port" != "$SSH_PORT" ] && firewall-cmd --permanent --query-port="${old_port}/tcp" >/dev/null 2>&1; then
		run firewall-cmd --permanent --remove-port="${old_port}/tcp"
	fi
	run firewall-cmd --reload
}

start_sshgate() {
	run systemctl enable --now sshgate
}

verify_listener() {
	local address=$1
	local port=$2
	local label=$3

	if [ "$DRY_RUN" -ne 0 ]; then
		return
	fi
	if ! ss -ltn | awk -v port=":$port" -v address="$address" '$4 ~ port "$" && $4 ~ address { found = 1 } END { exit !found }'; then
		echo "$label is not listening on $address:$port" >&2
		exit 1
	fi
	log "$label is listening on $address:$port"
}

main() {
	local old_port

	require_root
	require_command awk
	require_command crontab
	require_command firewall-cmd
	require_command getent
	require_command install
	require_command ss
	require_command systemctl
	resolve_sshd

	old_port=$(current_sshd_port)
	log "current sshd port: $old_port"

	install_sshgate_binary
	ensure_user
	install_sshgate_config
	install_sshgate_service
	seed_approved_fingerprints
	start_sshgate
	configure_sshd_backend
	restart_sshd
	update_firewalld "$old_port"
	disable_cron_randomizer

	verify_listener "$SSHD_LISTEN_ADDRESS" "$SSHD_PORT" sshd
	verify_listener "" "$SSH_PORT" sshgate
	log "migration complete; test SSH through port $SSH_PORT before closing this session"
}

main "$@"
