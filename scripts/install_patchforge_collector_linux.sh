#!/usr/bin/env bash
set -euo pipefail

repo_path="${1:-}"
config_path="${2:-}"
service_name="${3:-patchforge-collector}"
node_path="${NODE_PATH:-/usr/bin/node}"
interval="${PATCHFORGE_COLLECTOR_INTERVAL:-4h}"

if [[ -z "$repo_path" || -z "$config_path" ]]; then
  echo "usage: $0 <repo-path> <config-path> [service-name]" >&2
  exit 2
fi

collector_path="$repo_path/collector/patchforge-collector.mjs"
if [[ ! -f "$collector_path" ]]; then
  echo "collector not found: $collector_path" >&2
  exit 1
fi
if [[ ! -f "$config_path" ]]; then
  echo "collector config not found: $config_path" >&2
  exit 1
fi

cat >"/etc/systemd/system/${service_name}.service" <<UNIT
[Unit]
Description=PatchForge outbound asset discovery collector
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${repo_path}
EnvironmentFile=-/etc/patchforge/collector.env
ExecStart=${node_path} ${collector_path} --config=${config_path}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/tmp
UNIT

cat >"/etc/systemd/system/${service_name}.timer" <<UNIT
[Unit]
Description=Run PatchForge collector on a schedule

[Timer]
OnBootSec=5m
OnUnitActiveSec=${interval}
Unit=${service_name}.service

[Install]
WantedBy=timers.target
UNIT

mkdir -p /etc/patchforge
if [[ ! -f /etc/patchforge/collector.env ]]; then
  cat >/etc/patchforge/collector.env <<ENVFILE
# Store runtime tokens here. Do not commit this file.
# PATCHFORGE_COLLECTOR_TOKEN=
# NMS_READONLY_TOKEN=
ENVFILE
  chmod 600 /etc/patchforge/collector.env
fi

systemctl daemon-reload
systemctl enable --now "${service_name}.timer"

echo "Installed ${service_name}.timer. Add PATCHFORGE_COLLECTOR_TOKEN to /etc/patchforge/collector.env before live use."
