#!/usr/bin/env bash
set -euo pipefail

RANDOMIZER_PATH="/root/bin/ssh_server_port_randomizer.sh"
REMOTE_DIR="/tmp/sshgate-migration"
KEEP_REMOTE_FILES=1
DRY_RUN=0
TARGET=""

usage() {
	cat <<EOF
usage: $0 [options] user@host

Builds sshgate for the target host, copies the binary and migration script, then
runs the migration over SSH. The remote SSH session stays open after the
migration command finishes.

Options:
  --randomizer-path PATH     Remote randomizer script path to disable.
                             Default: $RANDOMIZER_PATH
  --remote-dir PATH          Remote staging directory. Default: $REMOTE_DIR
  --keep-remote-files        Leave staged files on the remote host.
  --dry-run                  Pass --dry-run to the remote migration script.
  -h, --help                 Show this help.

Example:
  $0 myhost
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--randomizer-path)
			RANDOMIZER_PATH=${2:?missing path}
			shift 2
			;;
		--remote-dir)
			REMOTE_DIR=${2:?missing path}
			shift 2
			;;
		--keep-remote-files)
			KEEP_REMOTE_FILES=1
			shift
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		-*)
			echo "unknown option: $1" >&2
			usage >&2
			exit 2
			;;
		*)
			if [ -n "$TARGET" ]; then
				echo "multiple targets provided: $TARGET and $1" >&2
				exit 2
			fi
			TARGET=$1
			shift
			;;
	esac
done

if [ -z "$TARGET" ]; then
	usage >&2
	exit 2
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MIGRATION_SCRIPT="$ROOT_DIR/scripts/migrate-randomized-ssh-to-sshgate.sh"
SSHD_CONFIG_SRC="$ROOT_DIR/scripts/sshd_config"
BUILD_DIR="$ROOT_DIR/.build"

log() {
	printf '%s\n' "$*"
}

quote_remote() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

map_goarch() {
	case "$1" in
		x86_64|amd64)
			printf 'amd64\n'
			;;
		aarch64|arm64)
			printf 'arm64\n'
			;;
		armv7l|armv6l)
			printf 'arm\n'
			;;
		*)
			echo "unsupported target architecture: $1" >&2
			exit 1
			;;
	esac
}

remote_has_sudo() {
	ssh "$TARGET" 'id -u | grep -qx 0 || command -v sudo >/dev/null 2>&1'
}

main() {
	local arch goarch binary remote_binary remote_script remote_sshd_config remote_dir_q remote_binary_q remote_script_q remote_sshd_config_q randomizer_q cleanup_cmd sudo_prefix dry_run_arg remote_cmd

	require_command go
	require_command scp
	require_command sed
	require_command ssh

	if [ ! -f "$MIGRATION_SCRIPT" ]; then
		echo "migration script not found: $MIGRATION_SCRIPT" >&2
		exit 1
	fi
	if [ ! -f "$SSHD_CONFIG_SRC" ]; then
		echo "sshd_config source not found: $SSHD_CONFIG_SRC" >&2
		exit 1
	fi

	log "Detecting target architecture on $TARGET"
	arch=$(ssh "$TARGET" 'uname -m')
	goarch=$(map_goarch "$arch")
	log "Target architecture: $arch -> linux/$goarch"

	mkdir -p "$BUILD_DIR"
	binary="$BUILD_DIR/sshgate-linux-$goarch"
	log "Building $binary"
	(
		cd "$ROOT_DIR"
		CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$binary" .
	)

	remote_binary="$REMOTE_DIR/sshgate"
	remote_script="$REMOTE_DIR/migrate-randomized-ssh-to-sshgate.sh"
	remote_sshd_config="$REMOTE_DIR/sshd_config"
	remote_dir_q=$(quote_remote "$REMOTE_DIR")
	remote_binary_q=$(quote_remote "$remote_binary")
	remote_script_q=$(quote_remote "$remote_script")
	remote_sshd_config_q=$(quote_remote "$remote_sshd_config")
	randomizer_q=$(quote_remote "$RANDOMIZER_PATH")

	log "Creating remote staging directory $REMOTE_DIR"
	ssh "$TARGET" "mkdir -p $remote_dir_q"

	log "Copying sshgate binary and migration script"
	scp "$binary" "$TARGET:$remote_binary"
	scp "$MIGRATION_SCRIPT" "$TARGET:$remote_script"
	scp "$SSHD_CONFIG_SRC" "$TARGET:$remote_sshd_config"
	ssh "$TARGET" "chmod 0755 $remote_binary_q $remote_script_q && chmod 0644 $remote_sshd_config_q"

	sudo_prefix=""
	if ! ssh "$TARGET" 'test "$(id -u)" -eq 0'; then
		if ! remote_has_sudo; then
			echo "remote user is not root and sudo is unavailable" >&2
			exit 1
		fi
		sudo_prefix="sudo "
	fi

	dry_run_arg=""
	if [ "$DRY_RUN" -eq 1 ]; then
		dry_run_arg=" --dry-run"
	fi

	cleanup_cmd=":"
	if [ "$KEEP_REMOTE_FILES" -eq 0 ]; then
		cleanup_cmd="if [ \"\$status\" -eq 0 ]; then rm -rf $remote_dir_q; fi"
	fi

	remote_cmd="$sudo_prefix bash $remote_script_q --sshgate-binary-src $remote_binary_q --randomizer-path $randomizer_q --sshd-config-src $remote_sshd_config_q$dry_run_arg; status=\$?; echo; echo 'Migration command exited with status' \$status; echo 'Leaving this SSH session open on the original connection. Test sshgate from another terminal before exiting.'; $cleanup_cmd; exec \${SHELL:-/bin/bash} -l"

	log "Running migration on $TARGET; this SSH session will remain open afterward"
	ssh -tt "$TARGET" "$remote_cmd"
}

main "$@"
