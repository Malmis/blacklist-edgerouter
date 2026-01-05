
#!/bin/vbash
# EdgeRouter Blacklist (CIDR → network-group) – diff-uppdatering i två faser + dry-run + sammanfattning + historik
# Uppdaterar firewall network-group: blacklist_net
# Kör UTAN sudo.
set -Eeuo pipefail

# Slå av eventuella interaktiva alias så $CFG save inte frågar "mv: overwrite ...?"
unalias mv 2>/dev/null || true
unalias cp 2>/dev/null || true
unalias rm 2>/dev/null || true

# ======= Konfiguration =======
GROUP_NET="blacklist_net"
LOG_TAG="blacklist"
TMP_BASE="/tmp/blacklist_cidr"
MAX_NETS=0 # 0 = ingen begränsning; sätt t.ex. 5000

# ---- Dry-run & state/historik ----
DRY_RUN="${DRY_RUN:-0}"       # 1 = dry-run (ingen commit)
DRY_RUN_SHOW="${DRY_RUN_SHOW:-20}" # antal rader att visa i listor
KEEP_WORK="${KEEP_WORK:-0}"   # 1 = behåll tempkatalogen

# ---[ AD-BLOCK toggles ]---
ADBLOCK=${ADBLOCK:-1}  # sätt till 1 för att köra adblock automatiskt, eller använd --adblock

STATE_DIR="/config/scripts/.blacklist_state"
STATE_TSV="${STATE_DIR}/summary.tsv" # maskinläsbar historik (TSV)
STATE_LOG="${STATE_DIR}/runs.log"    # lättläst logg per körning
MAX_HISTORY="${MAX_HISTORY:-500}"    # max antal historikrader (0 = behåll allt)

# CLI-flagga
if [[ "${1-}" == "--dry-run" ]]; then DRY_RUN=1; fi

LIST_URLS=(
  "https://iplists.firehol.org/files/dshield.netset"
  "https://iplists.firehol.org/files/firehol_level1.netset"
)

WHITELIST_CIDR=(
  "203.0.113.0/24"
  "1.1.1.1/32" "1.0.0.1/32"
  "8.8.4.4/32" "8.8.8.8/32"
  "9.9.9.9/32"
)

log() { logger -t "$LOG_TAG" -- "$*"; printf '[%s] %s\n' "$LOG_TAG" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

umask 022
mkdir -p "$TMP_BASE" "$STATE_DIR"
WORK="$(mktemp -d "${TMP_BASE}.XXXXXX")"

# Rensa temp som standard; behåll om KEEP_WORK=1 eller DRY_RUN=1
trap 'rm -rf "$WORK"' EXIT
if (( KEEP_WORK == 1 || DRY_RUN == 1 )); then
  trap - EXIT
  log "Behåller tempkatalog för inspektion: ${WORK}"
fi

# ======= Wrapper-binärer =======
CFG=""; OP=""
for p in /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper /opt/vyatta/bin/vyatta-cfg-cmd-wrapper; do
  [[ -x "$p" ]] && CFG="$p" && break
done
for p in /opt/vyatta/sbin/vyatta-op-cmd-wrapper /opt/vyatta/bin/vyatta-op-cmd-wrapper; do
  [[ -x "$p" ]] && OP="$p" && break
done
[[ -z "$CFG" ]] && { echo "[blacklist] FEL: vyatta-cfg-cmd-wrapper saknas"; exit 1; }
[[ -z "$OP" ]] && { echo "[blacklist] FEL: vyatta-op-cmd-wrapper saknas"; exit 1; }

fetch() {
  local url="$1" out="$2"
  if have curl; then curl -fsSL --connect-timeout 15 --max-time 120 -o "$out" "$url"
  elif have wget; then wget -q -T 120 -O "$out" "$url"
  else log "FEL: varken curl eller wget finns"; exit 1; fi
}

# ======= Hämta & bygg CIDR =======
log "Hämtar källistor... (GROUP_NET=${GROUP_NET}, type=network-group)"
ALL_CIDR="$WORK/all_cidr.txt"; : > "$ALL_CIDR"
i=0
for url in "${LIST_URLS[@]}"; do
  f="$WORK/list_$((++i)).raw"
  if fetch "$url" "$f"; then log "OK: $url"; else log "FEL: kunde inte hämta $url"; continue; fi
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|1[0-9]|2[0-9]|3[0-2])' "$f" >> "$ALL_CIDR" || true
done

validate_cidr() {
  awk '
  function valid_oct(n){ return (n ~ /^[0-9]+$/ && n>=0 && n<=255) }
  function valid_pfx(p){ return (p ~ /^[0-9]+$/ && p>=0 && p<=32) }
  { split($0,a,"/"); ip=a[1]; p=a[2];
    split(ip,o,"."); if(length(o)!=4) next;
    if(!valid_oct(o[1])||!valid_oct(o[2])||!valid_oct(o[3])||!valid_oct(o[4])) next;
    if(!valid_pfx(p)) next; print ip"/"p }'
}

filter_reserved_cidr() {
  awk '
  function ip_to_num(ip){ split(ip,o,"."); return (o[1]*256*256*256)+(o[2]*256*256)+(o[3]*256)+o[4] }
  function in_range(h,s,e){ return (ip_to_num(h)>=ip_to_num(s)&&ip_to_num(h)<=ip_to_num(e)) }
  { split($0,a,"/"); ip=a[1];
    if (in_range(ip,"0.0.0.0","0.255.255.255"))    next
    if (in_range(ip,"10.0.0.0","10.255.255.255"))  next
    if (in_range(ip,"100.64.0.0","100.127.255.255")) next
    if (in_range(ip,"127.0.0.0","127.255.255.255")) next
    if (in_range(ip,"169.254.0.0","169.254.255.255")) next
    if (in_range(ip,"172.16.0.0","172.31.255.255")) next
    if (in_range(ip,"192.168.0.0","192.168.255.255")) next
    if (in_range(ip,"224.0.0.0","239.255.255.255")) next
    if (in_range(ip,"240.0.0.0","255.255.255.255")) next
    if (in_range(ip,"192.0.2.0","192.0.2.255")) next
    if (in_range(ip,"198.51.100.0","198.51.100.255")) next
    if (in_range(ip,"203.0.113.0","203.0.113.255")) next
    print $0 }'
}

FILTERED="$WORK/filtered_cidr.txt"
tr -d '\r' < "$ALL_CIDR" \
  | validate_cidr \
  | filter_reserved_cidr \
  | sort -u > "$FILTERED"

# Whitelist
if [[ "${#WHITELIST_CIDR[@]}" -gt 0 ]]; then
  WL="$WORK/whitelist_cidr.txt"
  printf "%s\n" "${WHITELIST_CIDR[@]}" \
    | tr -d '\r' \
    | validate_cidr \
    | sort -u > "$WL"
  if ! grep -Fv -f "$WL" "$FILTERED" > "$WORK/filtered_cidr_nowl.txt"; then
    cp "$FILTERED" "$WORK/filtered_cidr_nowl.txt"
  fi
  mv "$WORK/filtered_cidr_nowl.txt" "$FILTERED"
fi

COUNT=$(wc -l < "$FILTERED" 2>/dev/null || echo 0)
if (( MAX_NETS > 0 && COUNT > MAX_NETS )); then
  head -n "$MAX_NETS" "$FILTERED" > "$WORK/final_cidr.txt"
else
  cp "$FILTERED" "$WORK/final_cidr.txt"
fi

FINAL="$WORK/final_cidr.txt"
tr -d '\r' < "$FINAL" \
  | sed 's/[[:space:]]\+$//' \
  | awk 'length' \
  | sort -u > "$WORK/final_cidr.norm"
FINAL="$WORK/final_cidr.norm"
FINAL_COUNT=$(wc -l < "$FINAL" 2>/dev/null || echo 0)

log "Antal CIDR efter filtrering/begränsning: ${FINAL_COUNT}"
head -n 5 "$FINAL" | sed 's/^/[blacklist] sample CIDR: /' || true

# ======= Precheck: inte address-group med samma namn =======
if $OP show configuration commands | grep -q -E "group address-group ${GROUP_NET}\b"; then
  echo "[blacklist] FEL: det finns referenser till 'address-group ${GROUP_NET}'. Byt reglerna till 'network-group ${GROUP_NET}' och kör igen."
  exit 1
fi

# ======= Läs nuvarande medlemmar & diff =======
CUR_SET="$WORK/current.set"; : > "$CUR_SET"
$OP show configuration commands \
  | grep -F "set firewall group network-group ${GROUP_NET} network " \
  | awk '{ $1=$1; print }' \
  | sort -u > "$CUR_SET" || true

CUR_CIDR="$WORK/current_cidr.txt"; : > "$CUR_CIDR"
sed -E "s/^set firewall group network-group ${GROUP_NET} network //" "$CUR_SET" \
  | tr -d '\r' \
  | sed 's/[[:space:]]\+$//' \
  | awk 'length' \
  | sort -u > "$CUR_CIDR"

TO_ADD="$WORK/to_add.txt"; TO_DEL="$WORK/to_del.txt"
: > "$TO_ADD"; : > "$TO_DEL"

if [[ -s "$FINAL" && -s "$CUR_CIDR" ]]; then
  grep -F -x -v -f "$CUR_CIDR" "$FINAL" | sort -u > "$TO_ADD" || true
  grep -F -x -v -f "$FINAL" "$CUR_CIDR" | sort -u > "$TO_DEL" || true
elif [[ -s "$FINAL" ]]; then
  sort -u "$FINAL" > "$TO_ADD"
fi

ADDN=$(wc -l < "$TO_ADD" 2>/dev/null || echo 0)
DELN=$(wc -l < "$TO_DEL" 2>/dev/null || echo 0)

# ======= Historik: hämta föregående rad =======
PREV_TS=""; PREV_CUR=0; PREV_FIN=0; PREV_ADD=0; PREV_DEL=0; PREV_NET=0
if [[ -s "${STATE_TSV}" ]]; then
  IFS=$'\t' read -r PREV_TS PREV_CUR PREV_FIN PREV_ADD PREV_DEL PREV_NET < <(tail -n 1 "${STATE_TSV}") || true
fi
NET_CHANGE=$((ADDN - DELN))
NEW_CUR_PRED=$(( $(wc -l < "$CUR_CIDR" 2>/dev/null || echo 0) - DELN + ADDN ))
NOW_TS="$(date -u +"%Y-%m-%d %H:%M:%SZ")"

summary_block() {
  echo "Sammanfattning:"
  echo " Nuvarande (före): $(wc -l < "$CUR_CIDR" 2>/dev/null || echo 0)"
  echo " Önskade (efter): ${FINAL_COUNT}"
  echo " ADDs: ${ADDN} DELs: ${DELN} Netto: ${NET_CHANGE}"
  echo " Förväntat antal (efter commit): ${NEW_CUR_PRED}"
  if [[ -n "${PREV_TS}" ]]; then
    echo "Föregående körning (${PREV_TS}): current=${PREV_CUR}, final=${PREV_FIN}, adds=${PREV_ADD}, dels=${PREV_DEL}, netto=${PREV_NET}"
    echo "Skillnad sedan föregående:"
    echo " Δcurrent=$((NEW_CUR_PRED - PREV_CUR)), Δfinal=$((FINAL_COUNT - PREV_FIN)), Δadds=$((ADDN - PREV_ADD)), Δdels=$((DELN - PREV_DEL)), Δnetto=$((NET_CHANGE - PREV_NET))"
  else
    echo "Ingen tidigare körning registrerad."
  fi
}

append_history() {
  # 1) TSV (maskinläsbar historik) – append
  printf "%s\t%d\t%d\t%d\t%d\t%d\n" "${NOW_TS}" \
    "${NEW_CUR_PRED}" "${FINAL_COUNT}" "${ADDN}" "${DELN}" "${NET_CHANGE}" >> "${STATE_TSV}"
  # Trimma historik vid behov
  if (( MAX_HISTORY > 0 )); then
    local total
    total=$(wc -l < "${STATE_TSV}" 2>/dev/null || echo 0)
    if (( total > MAX_HISTORY )); then
      tail -n "${MAX_HISTORY}" "${STATE_TSV}" > "${STATE_TSV}.tmp" && mv "${STATE_TSV}.tmp" "${STATE_TSV}"
    fi
  fi
  # 2) Lättläst logg
  {
    echo "=== ${NOW_TS} ==="
    echo "group=${GROUP_NET}"
    echo "current_before=$(wc -l < "$CUR_CIDR" 2>/dev/null || echo 0)"
    echo "final=${FINAL_COUNT}"
    echo "adds=${ADDN} dels=${DELN} net=${NET_CHANGE}"
    echo "predicted_after=${NEW_CUR_PRED}"
    if [[ -n "${PREV_TS}" ]]; then
      echo "prev_ts=${PREV_TS} prev_current=${PREV_CUR} prev_final=${PREV_FIN} prev_adds=${PREV_ADD} prev_dels=${PREV_DEL} prev_net=${PREV_NET}"
      echo "delta_current=$((NEW_CUR_PRED - PREV_CUR)) delta_final=$((FINAL_COUNT - PREV_FIN)) delta_adds=$((ADDN - PREV_ADD)) delta_dels=$((DELN - PREV_DEL)) delta_net=$((NET_CHANGE - PREV_NET))"
    fi
    echo
  } >> "${STATE_LOG}"
}

# ======= DRY-RUN: rapportera utan ändringar =======
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "[dry-run] Skulle ta bort (DELs=${DELN}) och lägga till (ADDs=${ADDN}) i '${GROUP_NET}'."
  # Visa några rader för överblick
  if [[ "$DELN" -gt 0 ]]; then
    head -n "$DRY_RUN_SHOW" "$TO_DEL" | sed 's/^/[dry-run] DEL: /'
    [[ "$DELN" -gt "$DRY_RUN_SHOW" ]] && echo "[dry-run] … +$((DELN-DRY_RUN_SHOW)) fler DELs (visa alla i $TO_DEL)"
  fi
  if [[ "$ADDN" -gt 0 ]]; then
    head -n "$DRY_RUN_SHOW" "$TO_ADD" | sed 's/^/[dry-run] ADD: /'
    [[ "$ADDN" -gt "$DRY_RUN_SHOW" ]] && echo "[dry-run] … +$((ADDN-DRY_RUN_SHOW)) fler ADDs (visa alla i $TO_ADD)"
  fi
  # Sammanfattning + previous differences
  summary_block | sed 's/^/[dry-run] /' | while read -r line; do log "$line"; done
  # Spara historik (dry-run) – så nästa körning kan jämföra
  append_history
  echo "[dry-run] Tempkatalog: ${WORK}"
  exit 0
fi

# ======= Fas 1: DELs i egen commit =======
if [[ "$DELN" -gt 0 ]]; then
  $CFG begin
  while IFS= read -r cidr; do
    [[ -n "$cidr" ]] || continue
    if $OP show configuration commands | grep -F -x "set firewall group network-group ${GROUP_NET} network ${cidr}" >/dev/null; then
      $CFG delete firewall group network-group "${GROUP_NET}" network "${cidr}"
    else
      echo "[blacklist] Skippar delete, medlem saknas: ${cidr}" >&2
    fi
  done < "$TO_DEL"

  echo "[blacklist] Kommittar borttagningar (DELs=${DELN}) ..."
  if ! $CFG commit; then
    echo "[blacklist] DEL-commit misslyckades – kör /config/scripts/repair-blacklist.sh och kör sedan detta skript igen."
    $CFG save
    $CFG end
    exit 1
  fi
  $CFG save
  $CFG end
fi

# ======= Fas 2: ADDs i egen commit =======
$CFG begin
$CFG set firewall group network-group "${GROUP_NET}" description "Combined blacklist CIDRs (${NOW_TS})"
if [[ "$ADDN" -gt 0 ]]; then
  while IFS= read -r cidr; do
    [[ -n "$cidr" ]] || continue
    $CFG set firewall group network-group "${GROUP_NET}" network "${cidr}"
  done < "$TO_ADD"
fi

echo "[blacklist] Kommittar uppdatering av '${GROUP_NET}' (ADDs=${ADDN}, DELs=${DELN}) ..."
$CFG commit
$CFG save
$CFG end

# ======= Verifiera efter commit & skriv sammanfattning =======
POST_SET="$WORK/post.set"; : > "$POST_SET"
$OP show configuration commands \
  | grep -F "set firewall group network-group ${GROUP_NET} network " \
  | awk '{ $1=$1; print }' \
  | sort -u > "$POST_SET" || true

POST_COUNT=$(sed -E "s/^set firewall group network-group ${GROUP_NET} network //" "$POST_SET" | awk 'length' | wc -l)

# Logga sammanfattning med deltor
{
  echo "Sammanfattning:"
  echo " Före (current): $(wc -l < "$CUR_CIDR" 2>/dev/null || echo 0)"
  echo " Efter (current): ${POST_COUNT}"
  echo " Önskade (final): ${FINAL_COUNT}"
  echo " ADDs: ${ADDN} DELs: ${DELN} Netto: ${NET_CHANGE}"
  if [[ -n "${PREV_TS}" ]]; then
    echo "Föregående körning (${PREV_TS}): current=${PREV_CUR}, final=${PREV_FIN}, adds=${PREV_ADD}, dels=${PREV_DEL}, netto=${PREV_NET}"
    echo "Skillnad sedan föregående:"
    echo " Δcurrent=$((POST_COUNT - PREV_CUR)), Δfinal=$((FINAL_COUNT - PREV_FIN)), Δadds=$((ADDN - PREV_ADD)), Δdels=$((DELN - PREV_DEL)), Δnetto=$((NET_CHANGE - PREV_NET))"
  else
    echo "Ingen tidigare körning registrerad."
  fi
} | while read -r line; do log "$line"; done

# Spara historik (post-commit) + trim
NEW_CUR_PRED="${POST_COUNT}"
append_history
log "Klart: '${GROUP_NET}' uppdaterad (ADDs=${ADDN}, DELs=${DELN})."

# -----------------------------------------------------------------------------
# ---[ AD-BLOCK (dnsmasq) – valfritt tillägg, befintlig logik oförändrad ]-----
# Körs endast på begäran (flaggan --adblock eller ADBLOCK=1).
# Standardkälla: OISD small i dnsmasq2-format (dnsmasq ≥ 2.86).
# Faller automatiskt tillbaka till OISD 'dnsmasq' (äldre syntax) om testet inte passerar.
# Se: OISD dnsmasq/dnsmasq2 och oznu-guide för EdgeRouter.  # refs

ensure_dnsmasq_dirs() {
  [ -d "/etc/dnsmasq.d" ] || mkdir -p "/etc/dnsmasq.d"
}

update_adblock_dnsmasq() {
  ensure_dnsmasq_dirs
  local tmp="/tmp/adblock.$$"
  local primary_url="${ADBLOCK_URL:-https://small.oisd.nl/dnsmasq2}"  # ny syntax (kräver >=2.86)
  local fallback_url="https://small.oisd.nl/dnsmasq"                  # äldre syntax (passar 2.85)

  echo "[adblock] Hämtar lista från: $primary_url"
  if ! curl -fsSL --retry 3 --retry-delay 5 --max-time 240 "$primary_url" -o "$tmp"; then
    echo "[adblock] VARNING: Nedladdning misslyckades (dnsmasq2)."; return 1
  fi

  # Testa den nedladdade filen
  if ! dnsmasq --test --conf-file="$tmp" >/dev/null 2>&1; then
    echo "[adblock] Validering misslyckades för dnsmasq2 (du kör $(dnsmasq -v | head -n1)). Försöker fallback..."
    # Fallback: hämta OISD 'dnsmasq' (äldre syntax) och testa igen
    if ! curl -fsSL --retry 3 --retry-delay 5 --max-time 240 "$fallback_url" -o "$tmp"; then
      echo "[adblock] VARNING: Fallback-nedladdning misslyckades."; rm -f "$tmp"; return 2
    fi
    if ! dnsmasq --test --conf-file="$tmp" >/dev/null 2>&1; then
      echo "[adblock] FEL: Validering misslyckades även med fallback. Aktiverar inte."
      rm -f "$tmp"; return 2
    fi
    echo "[adblock] Fallback giltig – använder 'dnsmasq' format (kompatibelt med 2.85)."
  fi

  # Atomiskt byte och restart
  mv "$tmp" "/etc/dnsmasq.d/adblock.conf"
  if /etc/init.d/dnsmasq restart; then
    echo "[adblock] Aktiverad via /etc/dnsmasq.d/adblock.conf"
  else
    echo "[adblock] VARNING: dnsmasq restart misslyckades – kontrollera loggar"; return 3
  fi
}

# Flagga/trigger: --adblock (i första eller andra argumentet) eller ADBLOCK=1
if [ "${ADBLOCK:-0}" = "1" ] || [ "${1:-}" = "--adblock" ] || [ "${2:-}" = "--adblock" ]; then
  update_adblock_dnsmasq
fi

exit 0
