#!/bin/vbash
# Repair: flytta regelreferenser till temp-grupp, radera & återskapa original, flytta tillbaka.

set -Eeuo pipefail

# Wrapper-binärer
CFG=""; OP=""
for p in /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper /opt/vyatta/bin/vyatta-cfg-cmd-wrapper; do
  [[ -x "$p" ]] && CFG="$p" && break
done
for p in /opt/vyatta/sbin/vyatta-op-cmd-wrapper /opt/vyatta/bin/vyatta-op-cmd-wrapper; do
  [[ -x "$p" ]] && OP="$p" && break
done
[[ -z "$CFG" ]] && { echo "[repair] FEL: vyatta-cfg-cmd-wrapper saknas"; exit 1; }
[[ -z "$OP"  ]] && { echo "[repair] FEL: vyatta-op-cmd-wrapper saknas"; exit 1; }

GROUP_NET="blacklist_net"
GROUP_TMP="${GROUP_NET}_tmp"
STAMP="$(date -u +"%Y-%m-%d %H:%M:%SZ")"
WORK="/tmp/repair_${GROUP_NET}_$$"; mkdir -p "$WORK"

log() { printf '[repair] %s\n' "$*"; }

# 1) Skapa temp-grupp
$CFG begin
$CFG set firewall group network-group "${GROUP_TMP}" description "Temporary during repair (${STAMP})"
$CFG commit
$CFG save
$CFG end

# 2) Hämta alla set-rader som refererar original-gruppen
$OP show configuration commands \
  | grep -E "^set " \
  | grep -E " group network-group ${GROUP_NET}(\b|$)" \
  | sort -u > "${WORK}/refs.set" || true

# 3) Peka om referenser till temp-gruppen
if [[ -s "${WORK}/refs.set" ]]; then
  $CFG begin
  # Läs varje 'set ...' rad och byt endast 'network-group blacklist_net' -> 'network-group blacklist_net_tmp'
  while IFS= read -r line; do
    new="$(echo "$line" | sed "s/network-group ${GROUP_NET}\b/network-group ${GROUP_TMP}/")"
    # Kör via wrappern med korrekt argumentdelning (behåll citat i befintlig rad):
    eval "\"$CFG\" ${new}"
  done < "${WORK}/refs.set"
  $CFG commit
  $CFG save
  $CFG end
fi

# 4) Radera original-gruppen helt
$CFG begin
$CFG delete firewall group network-group "${GROUP_NET}"
$CFG commit
$CFG save
$CFG end

# 5) Skapa om original-gruppen (tom – fylls senare av blacklist.sh)
$CFG begin
$CFG set firewall group network-group "${GROUP_NET}" description "Recreated by repair (${STAMP})"
$CFG commit
$CFG save
$CFG end

# 6) Peka tillbaka referenser TMP -> original
if [[ -s "${WORK}/refs.set" ]]; then
  $CFG begin
  while IFS= read -r line; do
    back="$(echo "$line" | sed "s/network-group ${GROUP_NET}\b/network-group ${GROUP_TMP}/" \
                      | sed "s/network-group ${GROUP_TMP}\b/network-group ${GROUP_NET}/")"
    eval "\"$CFG\" ${back}"
  done < "${WORK}/refs.set"
  $CFG commit
  $CFG save
  $CFG end
fi

# 7) Ta bort temp-gruppen
$CFG begin
$CFG delete firewall group network-group "${GROUP_TMP}"
$CFG commit
$CFG save
$CFG end

log "Repair klar: '${GROUP_NET}' är återskapad och referenser återställda."
exit 0