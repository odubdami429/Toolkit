#!/bin/bash
# Run on the Jarvis host as root, from a copy of this directory. Idempotent. Installs the Hermes setup and the
# systemd units but does NOT start them: start once the secret has the Slack tokens and the Anthropic key.
#
# Needs two deployment files next to their .example templates (both gitignored):
#   managed/org.env  organisation, who may act, alert bot, providers (shared by both containers)
#   managed/.env     Hermes settings: Slack allowlist, workspace ID, bot channels, audit channel
# and optionally managed/host.env (JARVIS_SECRET_ID, AWS_REGION for jarvis-secrets).
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=nousresearch/hermes-agent@sha256:276d44685c65c0cb2a25f190b63c65c8906f9dc76486fb1c05ae71b5826bda08  # v0.23.1
H=/opt/jarvis/hermes

for f in managed/org.env managed/.env; do
  if [ ! -f "$f" ]; then
    echo "install.sh: $f is missing: copy $f.example to $f and fill it in" >&2
    exit 1
  fi
done

# Render SOUL.md: fill its {{NAME}} placeholders from org.env (and the channel IDs from managed/.env). Any unknown or
# empty placeholder is an error, so a typo or an unfilled setting never reaches the model. Values are taken literally,
# as docker --env-file does (no quotes, no expansion).
RENDERED=$(mktemp); trap 'rm -f "$RENDERED"' EXIT
python3 -I -c '
import re, sys

def load(path):
    out = {}
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            sys.exit(f"install.sh: {path}:{n}: not KEY=VALUE")
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out

org, hermes = load("managed/org.env"), load("managed/.env")
csv = lambda v: [x.strip() for x in v.split(",") if x.strip()]
emails = [d.lower().lstrip("@") for d in csv(org.get("ORG_EMAIL_DOMAINS", ""))]
domains = list(dict.fromkeys(emails + [d.lower() for d in csv(org.get("ORG_EXTRA_DOMAINS", ""))]))
values = {
    "ORG_NAME": org.get("ORG_NAME", ""),
    "ORG_EMAIL_DOMAIN": emails[0] if emails else "",
    "ORG_EMAIL_DOMAINS": ", ".join(emails),
    "ORG_DOMAINS": ", ".join(domains),
    "ORG_SECURITY_TEAM": org.get("ORG_SECURITY_TEAM", ""),
    "ALERT_BOT_NAME": org.get("JARVIS_ALERT_BOT_NAME", ""),
    "JARVIS_SECURITY_GROUP": org.get("JARVIS_SECURITY_GROUP", ""),
    "JARVIS_AUDIT_CHANNEL": hermes.get("JARVIS_AUDIT_CHANNEL", ""),
    "JARVIS_BOT_CHANNELS": ", ".join(csv(hermes.get("JARVIS_BOT_CHANNELS", ""))),
}
text = open(sys.argv[1], encoding="utf-8").read()
names = set(re.findall(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", text))
unknown = sorted(names - values.keys())
empty = sorted(n for n in names & values.keys() if not values[n])
problems = ([f"unknown placeholder(s) {unknown}"] if unknown else []) + (
    [f"empty setting(s) for {empty} (fill them in managed/org.env or managed/.env)"] if empty else [])
if problems:
    sys.exit("install.sh: cannot render SOUL.md: " + "; ".join(problems))
out = re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", lambda m: values[m.group(1)], text)
if "{{" in out or "}}" in out:
    sys.exit("install.sh: SOUL.md still has a {{ or }} after rendering (malformed placeholder?)")
open(sys.argv[2], "w", encoding="utf-8").write(out)
' SOUL.md "$RENDERED"

docker pull -q "$IMAGE" >/dev/null
docker network inspect jarvis >/dev/null 2>&1 || docker network create --driver bridge jarvis >/dev/null

install -d -m 0755 -o root -g root /opt/jarvis "$H" "$H/bin" "$H/managed" "$H/plugins" "$H/plugins/jarvis_guard" \
  "$H/skills" "$H/empty-bundled"
install -m 0644 -o root -g root config.yaml "$H/config.yaml"
install -m 0644 -o root -g root config.yaml "$H/managed/config.yaml"
install -m 0644 -o root -g root managed/.env "$H/managed/.env"
install -m 0644 -o root -g root managed/org.env "$H/managed/org.env"
if [ -f managed/host.env ]; then install -m 0644 -o root -g root managed/host.env "$H/managed/host.env"; fi
install -m 0644 -o root -g root "$RENDERED" "$H/SOUL.md"
install -m 0644 -o root -g root plugins/jarvis_guard/plugin.yaml plugins/jarvis_guard/__init__.py \
  plugins/jarvis_guard/slack_format.py plugins/jarvis_guard/slack_tools.py plugins/jarvis_guard/slack_write_tools.py "$H/plugins/jarvis_guard/"
install -m 0755 -o root -g root bin/jarvis-secrets bin/jarvis-preflight bin/jarvis-hermes-run bin/jarvis-hermes-config-dump bin/jarvis-guard-canary bin/jarvis-tools-run "$H/bin/"
: > "$H/empty.env"; chown root:root "$H/empty.env"; chmod 0644 "$H/empty.env"
echo "$IMAGE" > "$H/IMAGE"; chmod 0644 "$H/IMAGE"
find skills -mindepth 1 -maxdepth 1 -type d -exec cp -a {} "$H/skills/" \; 2>/dev/null || true
chown -R root:root "$H/skills"; chmod -R go-w "$H/skills"

# jarvis-tools: build the specialist MCP server image from ../tools (pinned base image and requirements.lock)
docker build -q -t jarvis-tools:local ../tools >/dev/null

install -m 0644 -o root -g root systemd/jarvis-hermes.service /etc/systemd/system/jarvis-hermes.service
install -m 0644 -o root -g root systemd/jarvis-tools.service /etc/systemd/system/jarvis-tools.service
systemctl daemon-reload

echo "installed: $H, units jarvis-tools + jarvis-hermes (not started), images $IMAGE and jarvis-tools:local"
