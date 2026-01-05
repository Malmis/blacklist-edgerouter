#!/bin/vbash
# =============================================================================
# EdgeRouter Blacklist (CIDR → firewall network-group) + Adblock (dnsmasq)
# -----------------------------------------------------------------------------
# SYFTE:
#   - Uppdatera en firewall network-group (standard: "blacklist_net") med
#     kuraterade IPv4-CIDR-blocklistor, i två commits (DEL → ADD) för stabilitet.
#   - Hantera dnsmasq-baserad adblock med flera källor + domän-whitelist.
#   - Bygga och applicera en dynamisk CDN-CIDR-whitelist (Cloudflare, Fastly,
#     CloudFront, Google, Azure, CDN77, StackPath, Edgecast) så legit trafik
#     (streaming/CDN) inte blockeras av IP-listor.
#
# DESIGN:
#   - Två-stegs commit (DEL först, ADD sedan) för EdgeOS/Vyatta-quirks.
#   - Tydliga loggar + historik (runs.log, summary.tsv, adblock.log).
#   - Dry-run-stöd med tempkatalog som kan inspekteras.
#
# KÄLLOR (CIDR/CDN):
#   - Cloudflare IP ranges (officiellt): https://www.cloudflare.com/ips/   [IPv4: /ips-v4, IPv6: /ips-v6]
#   - Fastly public IP list (API):      https://api.fastly.com/public-ip-list
#   - AWS CloudFront IP ranges:         https://ip-ranges.amazonaws.com/ip-ranges.json
#                                       https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips
#   - Google Cloud ip ranges (cloud.json): https://www.gstatic.com/ipranges/cloud.json
#   - Azure CDN Edge Nodes (REST-API, kräver auth) – community spegel: https://raw.githubusercontent.com/Gelob/azure-cdn-ips/master/edgenodes-ipv4.txt
#
# VIKTIG NOTERING:
#   - Akamai har enormt många prefix. Undvik generisk CIDR-whitelist för Akamai.
#
# PATCHER I DENNA VERSION:
#   - CIDR-whitelist-räknare: loggar total, cdn, static.
#   - Adblock-whitelist-räknare: loggar regler före/efter + hur många tas bort.
#   - CDN-diagnostik: OK/FAIL per källa + sammanfattning i syslog och runs.log.
#
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Inaktivera interaktiva alias som kan störa flytten/sparandet
# -----------------------------------------------------------------------------
unalias mv 2>/dev/null || true
unalias cp 2>/dev/null || true
unalias rm 2>/dev/null || true

# =============================================================================
# KONFIGURATION
# =============================================================================
GROUP_NET="blacklist_net"                 # Firewall network-group som uppdateras
LOG_TAG="blacklist"                       # Syslog-tag
TMP_BASE="/tmp/blacklist_cidr"            # Bas för tempkataloger
MAX_NETS=0                                # 0 = obegränsat; sätt t.ex. 5000

# ---- Dry-run & historik
DRY_RUN="${DRY_RUN:-0}"                   # 1 = dry-run (ingen commit)
DRY_RUN_SHOW="${DRY_RUN_SHOW:-20}"        # hur många rader av ADD/DEL som visas
KEEP_WORK="${KEEP_WORK:-0}"               # 1 = behåll tempkatalog
STATE_DIR="/config/scripts/.blacklist_state"
STATE_TSV="${STATE_DIR}/summary.tsv"      # maskinläsbar historik (TSV)
STATE_LOG="${STATE_DIR}/runs.log"         # läsbar logg
MAX_HISTORY="${MAX_HISTORY:-500}"         # trimma historik till X rader (0 = behåll allt)

# ---- Adblock (dnsmasq)
ADBLOCK=${ADBLOCK:-1}                     # 1 = kör adblock vid varje körning
DO_ADBLOCK_STATS=1                        # skriv adblock-statistik
ADBLOCK_URL="${ADBLOCK_URL:-}"            # primär källa (override)
ADBLOCK_WHITELIST="/config/blacklist/adblock-whitelist.txt"  # en domän per rad
ADBLOCK_CONF="/etc/dnsmasq.d/adblock.conf"
ADBLOCK_LOG="${STATE_DIR}/adblock.log"

# ---- CDN-CIDR auto-whitelist
FETCH_CDN_WHITELIST="${FETCH_CDN_WHITELIST:-1}"  # 1 = hämta CDN-ranges
CDN_PROVIDERS="${CDN_PROVIDERS:-cloudflare fastly cloudfront google azure cdn77 stackpath edgecast}"
CDN_FETCH_TIMEOUT="${CDN_FETCH_TIMEOUT:-240}"     # sekunder per hämtning
CDN_ALLOW_IPV6="${CDN_ALLOW_IPV6:-0}"            # (framtida) IPv6

WHITELIST_CIDR=(
  "203.0.113.0/24"
  "1.1.1.1/32"
  "1.0.0.1/32"
  "8.8.4.4/32"
  "8.8.8.8/32"
  "9.9.9.9/32"
)

# ---- Adblock stats flag via CLI
if [ "${1:-}" = "--adblock-stats" ] || [ "${2:-}" = "--adblock-stats" ]; then
  DO_ADBLOCK_STATS=1
fi

# =============================================================================
# Hjälpfunktioner (loggning, root-utförande, wrapper-binärer)
# =============================================================================
log() { logger -t "$LOG_TAG" -- "$*"; printf '[%s] %s\n' "$LOG_TAG" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
as_root() { if [ "${EUID:-$(id -u)}" -ne 0 ]; then sudo "$@"; else "$@"; fi; }

umask 022
mkdir -p "$TMP_BASE" "$STATE_DIR"
WORK="$(mktemp -d "${TMP_BASE}.XXXXXX")"

# Rensa temp som standard; behåll vid KEEP_WORK=1 eller DRY_RUN=1
trap 'rm -rf "$WORK"' EXIT
if (( KEEP_WORK == 1 || DRY_RUN == 1 )); then
  trap - EXIT
  log "Behåller tempkatalog för inspektion: ${WORK}"
fi

# ---- Vyatta wrapperkommandon (config/op)
CFG=""; OP=""
for p in /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper /opt/vyatta/bin/vyatta-cfg-cmd-wrapper; do
  [[ -x "$p" ]] && CFG="$p" && break
done
for p in /opt/vyatta/sbin/vyatta-op-cmd-wrapper /opt/vyatta/bin/vyatta-op-cmd-wrapper; do
  [[ -x "$p" ]] && OP="$p" && break
done
[[ -z "$CFG" ]] && { echo "[blacklist] FEL: vyatta-cfg-cmd-wrapper saknas"; exit 1; }
[[ -z "$OP" ]] && { echo "[blacklist] FEL: vyatta-op-cmd-wrapper saknas"; exit 1; }

# ---- Robust fetch med curl/wget
fetch() {
  local url="$1" out="$2"
  if have curl; then curl -fsSL --connect-timeout 15 --max-time "$CDN_FETCH_TIMEOUT" -o "$out" "$url"
  elif have wget; then wget -q -T "$CDN_FETCH_TIMEOUT" -O "$out" "$url"
  else log "FEL: varken curl eller wget finns"; exit 1; fi
}

# =============================================================================
# STEG 1: Hämta råa CIDR från källistor, validera, filtrera reserverade
# =============================================================================
log "Hämtar källistor... (GROUP_NET=${GROUP_NET}, type=network-group)"
ALL_CIDR="$WORK/all_cidr.txt"; : > "$ALL_CIDR"
i=0
for url in \
  "https://iplists.firehol.org/files/dshield.netset" \
  "https://iplists.firehol.org/files/firehol_level1.netset" \
  "https://iplists.firehol.org/files/firehol_level2.netset" \
  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
do
  f="$WORK/list_$((++i)).raw"
  if fetch "$url" "$f"; then log "OK: $url"; else log "FEL: kunde inte hämta $url"; continue; fi
  # extrahera IPv4 CIDR
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|1[0-9]|2[0-9]|3[0-2])' "$f" >> "$ALL_CIDR" || true
done

# ---- Validera CIDR (0–32) och IP oktetter (0–255)
validate_cidr() {
  awk '
  function valid_oct(n){ return (n ~ /^[0-9]+$/ && n>=0 && n<=255) }
  function valid_pfx(p){ return (p ~ /^[0-9]+$/ && p>=0 && p<=32) }
  { split($0,a,"/"); ip=a[1]; p=a[2];
    split(ip,o,"."); if(length(o)!=4) next;
    if(!valid_oct(o[1])||!valid_oct(o[2])||!valid_oct(o[3])||!valid_oct(o[4])) next;
    if(!valid_pfx(p)) next; print ip"/"p }'
}

# ---- Filtrera reserverade/privata/multicast etc.
filter_reserved_cidr() {
  awk '
  function ip_to_num(ip){ split(ip,o,"."); return (o[1]*256*256*256)+(o[2]*256*256)+(o[3]*256)+o[4] }
  function in_range(h,s,e){ return (ip_to_num(h)>=ip_to_num(s)&&ip_to_num(h)<=ip_to_num(e)) }
  { split($0,a,"/"); ip=a[1];
    if (in_range(ip,"0.0.0.0","0.255.255.255")) next
    if (in_range(ip,"10.0.0.0","10.255.255.255")) next
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

# =============================================================================
# STEG 2: Bygg CDN-CIDR-whitelist + statisk WHITELIST_CIDR och applicera
# =============================================================================
# DOC: Skapar dynamisk fil med CDN CIDR, markerar OK/FAIL per källa och
#      skriver en sammanfattning. Returnerar sökväg till den deduplicerade
#      CDN-whitelistfilen.
build_dynamic_cdn_whitelist_v4() {
  local out_raw="$WORK/cdn_whitelist_v4.raw"
  local out="$WORK/cdn_whitelist_v4.txt"
  : > "$out_raw"

  # --- Statuslista över källor (name\tOK/FAIL)
  local status_file="$WORK/cdn_sources.status"
  : > "$status_file"
  _mark_status() {
    printf "%s\t%s\n" "$1" "$2" >> "$status_file"
    case "$2" in
      OK)   log "[cdn] OK: $1" ;;
      FAIL) log "[cdn] FAIL: $1" ;;
    esac
  }

  # --- Cloudflare
  if echo "$CDN_PROVIDERS" | grep -qw "cloudflare"; then
    local cf="$WORK/cloudflare_v4.txt"
    if fetch "https://www.cloudflare.com/ips-v4" "$cf"; then
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$cf" >> "$out_raw" || true
      _mark_status "cloudflare" "OK"
    else
      _mark_status "cloudflare" "FAIL"
    fi
  fi

  # --- Fastly
  if echo "$CDN_PROVIDERS" | grep -qw "fastly"; then
    local fa="$WORK/fastly.json"
    if fetch "https://api.fastly.com/public-ip-list" "$fa"; then
      grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$fa" >> "$out_raw" || true
      _mark_status "fastly" "OK"
    else
      _mark_status "fastly" "FAIL"
    fi
  fi

  # --- CloudFront (tools-list → fallback JSON)
  if echo "$CDN_PROVIDERS" | grep -qw "cloudfront"; then
    local got_cf=0
    local cfv="$WORK/cloudfront_v4.txt"
    if fetch "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips" "$cfv"; then
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$cfv" >> "$out_raw" || true
      got_cf=1
    else
      local aws="$WORK/ip-ranges.json"
      if fetch "https://ip-ranges.amazonaws.com/ip-ranges.json" "$aws"; then
        awk '
          BEGIN{ s=0 }
          /"service"[[:space:]]*:[[:space:]]*"CLOUDFRONT"/{ s=1 }
          /"service"[[:space:]]*:[[:space:]]*"/ && $0 !~ /CLOUDFRONT/{ s=0 }
          s && /"ip_prefix"/{
            match($0,/"ip_prefix"[[:space:]]*:[[:space:]]*"[0-9.\/]+"/,m)
            if(m[0]!=""){
              gsub(/"ip_prefix"[[:space:]]*:[[:space:]]*"/,"",m[0])
              gsub(/"/,"",m[0]); print m[0]
            }
          }' "$aws" >> "$out_raw" || true
        got_cf=1
      fi
    fi
    if [ "$got_cf" -eq 1 ]; then _mark_status "cloudfront" "OK"; else _mark_status "cloudfront" "FAIL"; fi
  fi

  # --- Google Cloud
  if echo "$CDN_PROVIDERS" | grep -qw "google"; then
    local ggl="$WORK/google-cloud.json"
    if fetch "https://www.gstatic.com/ipranges/cloud.json" "$ggl"; then
      grep -Eo '"ipv4Prefix":[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)"' "$ggl" \
        | sed -E 's/.*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+)".*/\1/' >> "$out_raw" || true
      _mark_status "google" "OK"
    else
      _mark_status "google" "FAIL"
    fi
  fi

  # --- Azure CDN edge (mirror)
  if echo "$CDN_PROVIDERS" | grep -qw "azure"; then
    local az="$WORK/azure-cdn-v4.txt"
    if fetch "https://raw.githubusercontent.com/Gelob/azure-cdn-ips/master/edgenodes-ipv4.txt" "$az"; then
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$az" >> "$out_raw" || true
      _mark_status "azure" "OK"
    else
      _mark_status "azure" "FAIL"
    fi
  fi

  # --- CDN77
  if echo "$CDN_PROVIDERS" | grep -qw "cdn77"; then
    local c77="$WORK/cdn77.json"
    if fetch "https://prefixlists.tools.cdn77.com/public_lmax_prefixes.json" "$c77"; then
      grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$c77" >> "$out_raw" || true
      _mark_status "cdn77" "OK"
    else
      _mark_status "cdn77" "FAIL"
    fi
  fi

  # --- StackPath (statisk)
  if echo "$CDN_PROVIDERS" | grep -qw "stackpath"; then
    cat <<'EOF' >> "$out_raw"
67.14.160.0/21
67.14.168.0/22
EOF
    _mark_status "stackpath" "OK"
  fi

  # --- Edgecast (statisk)
  if echo "$CDN_PROVIDERS" | grep -qw "edgecast"; then
    cat <<'EOF' >> "$out_raw"
93.184.212.0/22
93.184.220.0/22
72.21.80.0/24
192.16.32.0/24
192.229.129.0/24
192.229.150.0/24
192.229.168.0/24
192.229.186.0/24
192.229.211.0/24
198.7.16.0/24
EOF
    _mark_status "edgecast" "OK"
  fi

  # --- Normalisera & deduplicera
  tr -d '\r' < "$out_raw" | validate_cidr | sort -u > "$out"
  local cnt; cnt=$(wc -l < "$out" 2>/dev/null || echo 0)
  log "[cdn] Dynamisk CDN-whitelist (IPv4) innehåller ${cnt} prefix"

  # --- Sammanfattning för runs.log + syslog (vilka OK/FAIL)
  local failed ok
  failed=$(awk -F'\t' '$2=="FAIL"{print $1}' "$status_file" | xargs echo || true)
  ok=$(awk -F'\t' '$2=="OK"{print $1}' "$status_file" | xargs echo || true)
  if [ -n "$failed" ]; then log "[cdn-summary] FAILED: $failed"; else log "[cdn-summary] FAILED: none"; fi
  log "[cdn-summary] OK: $ok"
  {
    echo "[cdn-summary] ok_count=$(awk '$2==\"OK\"'  \"$status_file\" | wc -l | tr -d ' ') fail_count=$(awk '$2==\"FAIL\"' \"$status_file\" | wc -l | tr -d ' ')"
    echo "[cdn-summary] ok: $ok"
    echo "[cdn-summary] failed: ${failed:-none}"
  } >> "${STATE_LOG}"

  echo "$out"
}

# ---- WHITELIST_CIDR array (initiera om saknad)
if [ -z "${WHITELIST_CIDR+x}" ]; then WHITELIST_CIDR=(); fi

# ---- Bygg & applicera whitelist (CDN + statisk)
CDN_WL_FILE=""
if (( FETCH_CDN_WHITELIST == 1 )); then
  CDN_WL_FILE="$(build_dynamic_cdn_whitelist_v4)"
fi

if [[ -n "$CDN_WL_FILE" || ${#WHITELIST_CIDR[@]} > 0 ]]; then
  WL="$WORK/whitelist_cidr.txt"; : > "$WL"
  if (( ${#WHITELIST_CIDR[@]} > 0 )); then
    printf "%s\n" "${WHITELIST_CIDR[@]}" | tr -d '\r' | validate_cidr >> "$WL"
  fi
  if [[ -n "$CDN_WL_FILE" && -s "$CDN_WL_FILE" ]]; then
    cat "$CDN_WL_FILE" >> "$WL"
  fi
  sort -u -o "$WL" "$WL"
  # Ta bort whitelistade prefix från FILTERED
  if ! grep -Fv -f "$WL" "$FILTERED" > "$WORK/filtered_cidr_nowl.txt"; then
    cp "$FILTERED" "$WORK/filtered_cidr_nowl.txt"
  fi
  mv "$WORK/filtered_cidr_nowl.txt" "$FILTERED"

  # ---- Logga antal whitelistade nät (total/cdn/static)
  CIDR_WL_TOTAL=0; CIDR_WL_CDN=0; CIDR_WL_STATIC=0
  if [[ -n "$CDN_WL_FILE" && -s "$CDN_WL_FILE" ]]; then
    CIDR_WL_CDN=$(wc -l < "$CDN_WL_FILE" 2>/dev/null || echo 0)
  fi
  if (( ${#WHITELIST_CIDR[@]} > 0 )) && [[ -f "$WL" ]]; then
    CIDR_WL_STATIC=$(( $(wc -l < "$WL" 2>/dev/null || echo 0) - CIDR_WL_CDN ))
    [[ $CIDR_WL_STATIC -lt 0 ]] && CIDR_WL_STATIC=0
  fi
  CIDR_WL_TOTAL=$(( CIDR_WL_CDN + CIDR_WL_STATIC ))
  log "[cidr-whitelist] total=${CIDR_WL_TOTAL} cdn=${CIDR_WL_CDN} static=${CIDR_WL_STATIC}"
  echo "[cidr-whitelist] total=${CIDR_WL_TOTAL} cdn=${CIDR_WL_CDN} static=${CIDR_WL_STATIC}" >> "${STATE_LOG}"
fi

# =============================================================================
# STEG 3: Tillämpa MAX_NETS och normalisera final lista
# =============================================================================
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

# =============================================================================
# STEG 4: Säkerhetskontroll av group-typ (address-group vs network-group)
# =============================================================================
if $OP show configuration commands | grep -q -E "group address-group ${GROUP_NET}\b"; then
  echo "[blacklist] FEL: det finns referenser till 'address-group ${GROUP_NET}'. Byt reglerna till 'network-group ${GROUP_NET}' och kör igen."
  exit 1
fi

# =============================================================================
# STEG 5: Läs nuvarande medlemmar, diff:a DEL/ADD
# =============================================================================
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

# =============================================================================
# STEG 6: Historik, sammanfattning (pre-commit), dry-run-handling
# =============================================================================
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
  echo " CIDR-whitelist: total=${CIDR_WL_TOTAL} (cdn=${CIDR_WL_CDN}, static=${CIDR_WL_STATIC})"
  if [[ -n "${PREV_TS}" ]]; then
    echo "Föregående (${PREV_TS}): current=${PREV_CUR}, final=${PREV_FIN}, adds=${PREV_ADD}, dels=${PREV_DEL}, netto=${PREV_NET}"
    echo "Δcurrent=$((NEW_CUR_PRED - PREV_CUR)), Δfinal=$((FINAL_COUNT - PREV_FIN)), Δadds=$((ADDN - PREV_ADD)), Δdels=$((DELN - PREV_DEL)), Δnetto=$((NET_CHANGE - PREV_NET))"
  else
    echo "Ingen tidigare körning registrerad."
  fi
}

append_history() {
  printf "%s\t%d\t%d\t%d\t%d\t%d\n" "${NOW_TS}" \
    "${NEW_CUR_PRED}" "${FINAL_COUNT}" "${ADDN}" "${DELN}" "${NET_CHANGE}" >> "${STATE_TSV}"
  if (( MAX_HISTORY > 0 )); then
    local total; total=$(wc -l < "${STATE_TSV}" 2>/dev/null || echo 0)
    if (( total > MAX_HISTORY )); then
      tail -n "${MAX_HISTORY}" "${STATE_TSV}" > "${STATE_TSV}.tmp" && mv "${STATE_TSV}.tmp" "${STATE_TSV}"
    fi
  fi
  {
    echo "=== ${NOW_TS} ==="
    echo "group=${GROUP_NET}"
    echo "current_before=$(wc -l < "$CUR_CIDR" 2>/dev/null || echo 0)"
    echo "final=${FINAL_COUNT}"
    echo "adds=${ADDN} dels=${DELN} net=${NET_CHANGE}"
    echo "predicted_after=${NEW_CUR_PRED}"
    echo "cidr_whitelist_total=${CIDR_WL_TOTAL} cdn=${CIDR_WL_CDN} static=${CIDR_WL_STATIC}"
    if [[ -n "${PREV_TS}" ]]; then
      echo "prev_ts=${PREV_TS} prev_current=${PREV_CUR} prev_final=${PREV_FIN} prev_adds=${PREV_ADD} prev_dels=${PREV_DEL} prev_net=${PREV_NET}"
      echo "delta_current=$((NEW_CUR_PRED - PREV_CUR)) delta_final=$((FINAL_COUNT - PREV_FIN)) delta_adds=$((ADDN - PREV_ADD)) delta_dels=$((DELN - PREV_DEL)) delta_net=$((NET_CHANGE - PREV_NET))"
    fi
    echo
  } >> "${STATE_LOG}"
}

# ---- DRY-RUN: rapportera utan commit, visa sample ADD/DEL
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "[dry-run] Skulle ta bort (DELs=${DELN}) och lägga till (ADDs=${ADDN}) i '${GROUP_NET}'."
  if [[ "$DELN" -gt 0 ]]; then
    head -n "$DRY_RUN_SHOW" "$TO_DEL" | sed 's/^/[dry-run] DEL: /'
    [[ "$DELN" -gt "$DRY_RUN_SHOW" ]] && echo "[dry-run] … +$((DELN-DRY_RUN_SHOW)) fler DELs (visa alla i $TO_DEL)"
  fi
  if [[ "$ADDN" -gt 0 ]]; then
    head -n "$DRY_RUN_SHOW" "$TO_ADD" | sed 's/^/[dry-run] ADD: /'
    [[ "$ADDN" -gt "$DRY_RUN_SHOW" ]] && echo "[dry-run] … +$((ADDN-DRY_RUN_SHOW)) fler ADDs (visa alla i $TO_ADD)"
  fi
  summary_block | sed 's/^/[dry-run] /' | while read -r line; do log "$line"; done
  append_history
  echo "[dry-run] Tempkatalog: ${WORK}"
  exit 0
fi

# =============================================================================
# STEG 7: Commit DEL → ADD
# =============================================================================
# ---- Fas 1: DEL i egen session
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
    $CFG save; $CFG end; exit 1
  fi
  $CFG save; $CFG end
fi

# ---- Fas 2: ADD i egen session
$CFG begin
$CFG set firewall group network-group "${GROUP_NET}" description "Combined blacklist CIDRs (${NOW_TS})"
if [[ "$ADDN" -gt 0 ]]; then
  while IFS= read -r cidr; do
    [[ -n "$cidr" ]] || continue
    $CFG set firewall group network-group "${GROUP_NET}" network "${cidr}"
  done < "$TO_ADD"
fi
echo "[blacklist] Kommittar uppdatering av '${GROUP_NET}' (ADDs=${ADDN}, DELs=${DELN}) ..."
$CFG commit; $CFG save; $CFG end

# =============================================================================
# STEG 8: Post-verifiering & slutlig sammanfattning
# =============================================================================
POST_SET="$WORK/post.set"; : > "$POST_SET"
$OP show configuration commands \
  | grep -F "set firewall group network-group ${GROUP_NET} network " \
  | awk '{ $1=$1; print }' \
  | sort -u > "$POST_SET" || true
POST_COUNT=$(sed -E "s/^set firewall group network-group ${GROUP_NET} network //" "$POST_SET" | awk 'length' | wc -l)

{
  echo "Sammanfattning:"
  echo " Före (current): $(wc -l < "$CUR_CIDR" 2>/dev/null || echo 0)"
  echo " Efter (current): ${POST_COUNT}"
  echo " Önskade (final): ${FINAL_COUNT}"
  echo " ADDs: ${ADDN} DELs: ${DELN} Netto: ${NET_CHANGE}"
  echo " CIDR-whitelist: total=${CIDR_WL_TOTAL} (cdn=${CIDR_WL_CDN}, static=${CIDR_WL_STATIC})"
  if [[ -n "${PREV_TS}" ]]; then
    echo "Föregående (${PREV_TS}): current=${PREV_CUR}, final=${PREV_FIN}, adds=${PREV_ADD}, dels=${PREV_DEL}, netto=${PREV_NET}"
    echo "Δcurrent=$((POST_COUNT - PREV_CUR)), Δfinal=$((FINAL_COUNT - PREV_FIN)), Δadds=$((ADDN - PREV_ADD)), Δdels=$((DELN - PREV_DEL)), Δnetto=$((NET_CHANGE - PREV_NET))"
  else
    echo "Ingen tidigare körning registrerad."
  fi
} | while read -r line; do log "$line"; done

NEW_CUR_PRED="${POST_COUNT}"
append_history
log "Klart: '${GROUP_NET}' uppdaterad (ADDs=${ADDN}, DELs=${DELN})."

# =============================================================================
# AD-BLOCK (dnsmasq): källor, whitelist, validering, aktivering + loggning
# =============================================================================

ensure_dnsmasq_dirs() { as_root mkdir -p "/etc/dnsmasq.d"; }

# ---- Heuristisk räknare: blockeringar senaste 24h (kräver log-queries)
count_adblock_events() {
  local logf="/var/log/messages" today count=0
  if [ -f "$logf" ]; then
    today="$(date '+%b %e')"
    count=$(tail -n 20000 "$logf" | grep -F "$today" | grep -E 'dnsmasq' | grep -E 'reply .* is 0\.0\.0\.0' | wc -l | tr -d ' ' || true)
  fi
  echo "${count}"
}

# ---- Normalisera adblock-whitelist (ta bort kommentarer/tomrader, trimma .prefix)
normalize_whitelist() {
  local out="$1"; : > "$out"
  if [ -f "$ADBLOCK_WHITELIST" ]; then
    sed -e 's/\#.*$//' -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//' "$ADBLOCK_WHITELIST" \
      | awk 'length' | sed -e 's/^\.\(.*\)$/\1/' | sort -u > "$out"
  fi
}

# ---- Konvertera till dnsmasq address=/domain/0.0.0.0 (stöder hosts/domänlistor)
to_dnsmasq_rules() {
  local in="$1" out="$2"
  awk '
    function is_comment(line){ return (line ~ /^[[:space:]]*(#|;|\/\/)/) }
    function trim(s){ sub(/^[[:space:]]+/,"",s); sub(/[[:space:]]+$/,"",s); return s }
    function add(d){ if (d ~ /^[A-Za-z0-9.-]+$/ && d !~ /^(\.|-)/ && d ~ /\./) print "address=/" d "/0.0.0.0" }
    { raw=$0
      if (raw ~ /^[[:space:]]*address=\/[A-Za-z0-9.-]+\/0\.0\.0\.0[[:space:]]*$/) { print trim(raw); next }
      if (is_comment(raw) || raw ~ /^[[:space:]]*$/) next
      line=trim(raw)
      if (line ~ /^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]+/) { sub(/^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]+/,"",line); split(line,a,/[[:space:]]+/); d=a[1]; gsub(/^\.*/,"",d); add(d); next }
      gsub(/^\.*/,"",line); add(line)
    }' "$in" > "$out"
}

# ---- Applicera whitelist på dnsmasq-regler + logga hur många togs bort
apply_adblock_whitelist() {
  local file="$1"; local wl_norm="$WORK/adblock-wl.norm"
  normalize_whitelist "$wl_norm"
  [[ -s "$wl_norm" ]] || return 0

  local before after removed wl_domains
  before=$(grep -E '^[[:space:]]*address=/[A-Za-z0-9.-]+/0\.0\.0\.0[[:space:]]*$' "$file" | wc -l | tr -d ' ' || echo 0)
  wl_domains=$(wc -l < "$wl_norm" 2>/dev/null || echo 0)

  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    local d_esc; d_esc="$(printf '%s' "$d" | sed 's/\./\\./g')"
    sed -i -E "/^address\/(${d_esc}|([^.\/]*\.)*${d_esc})\/0\.0\.0\.0$/d" "$file"   # äldre syntax
    sed -i -E "/^address=\/(${d_esc}|([^.\/]*\.)*${d_esc})\/0\.0\.0\.0$/d" "$file"  # modern syntax
  done < "$wl_norm"

  after=$(grep -E '^[[:space:]]*address=/[A-Za-z0-9.-]+/0\.0\.0\.0[[:space:]]*$' "$file" | wc -l | tr -d ' ' || echo 0)
  removed=$(( before - after ))
  (( removed < 0 )) && removed=0

  {
    echo "=== $(date -u +'%Y-%m-%d %H:%M:%SZ') ==="
    echo "wl_domains=${wl_domains}"
    echo "rules_before=${before}"
    echo "rules_after=${after}"
    echo "rules_removed_by_whitelist=${removed}"
    echo "conf_path=${ADBLOCK_CONF}"
    echo
  } >> "$ADBLOCK_LOG"

  echo "[adblock-wl] wl_domains=${wl_domains} removed=${removed} before=${before} after=${after}" >> "${STATE_LOG}"
  log "[adblock-wl] removed=${removed} (before=${before}, after=${after}, wl_domains=${wl_domains})"
}

# ---- Källval för adblock (kan exkluderas via ADBLOCK_EXCLUDE_SOURCES)
ADBLOCK_EXTRA_URLS="${ADBLOCK_EXTRA_URLS:-}"
ADBLOCK_EXCLUDE_SOURCES="${ADBLOCK_EXCLUDE_SOURCES:-}"

should_include() { case " $ADBLOCK_EXCLUDE_SOURCES " in *" $1 "*) return 1 ;; *) return 0 ;; esac; }

build_adblock_sources() {
  local list_file="$1"; : > "$list_file"
  # Primär override
  [ -n "$ADBLOCK_URL" ] && printf "%s\tprimary\n" "$ADBLOCK_URL" >> "$list_file"
  # OISD
  if should_include "oisd"; then
    printf "%s\toisd2\n" "https://small.oisd.nl/dnsmasq2" >> "$list_file"
    printf "%s\toisd\n"  "https://small.oisd.nl/dnsmasq"  >> "$list_file"
  fi
  # StevenBlack
  should_include "stevenblack" && printf "%s\tstevenblack\n" "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" >> "$list_file"
  # 1Hosts Lite (dnsmasq)
  should_include "1hosts-lite" && printf "%s\t1hosts-lite\n" "https://badmojr.github.io/1Hosts/Lite/dnsmasq.conf" >> "$list_file"
  # AdGuard SDNS
  should_include "adguard" && printf "%s\tadguard\n" "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt" >> "$list_file"
  # Malmis DNS filter
  should_include "Malmis" && printf "%s\tMalmis\n" "https://raw.githubusercontent.com/Malmis/blacklist-edgerouter/refs/heads/main/swedish_and_more.txt" >> "$list_file"
  # Extra
  if [ -n "$ADBLOCK_EXTRA_URLS" ]; then
    for u in $ADBLOCK_EXTRA_URLS; do printf "%s\textra\n" "$u" >> "$list_file"; done
  fi
}

dnsmasq_test_conf() { local file="$1"; local DQSM="/usr/sbin/dnsmasq"; "$DQSM" --test --conf-file="$file" >/dev/null 2>&1; }
wrap_as_conf() { local rules="$1" out="$2"; cp "$rules" "$out"; }

# ---- Hämta källor, konvertera, whitelista, validera och aktivera dnsmasq
update_adblock_dnsmasq() {
  ensure_dnsmasq_dirs
  local tmp_rules="$WORK/adblock.rules" tmp_rules2="$WORK/adblock.rules2" tmp_conf="$WORK/adblock.conf.test"
  : > "$tmp_rules"

  local DQSM="/usr/sbin/dnsmasq"
  if [ ! -x "$DQSM" ]; then echo "[adblock] FEL: $DQSM saknas eller ej körbar."; return 9; fi

  local srcs="$WORK/sources.tsv"; build_adblock_sources "$srcs"

  local got_any=0
  while IFS=$'\t' read -r url tag; do
    [ -n "$url" ] || continue
    local f="$WORK/src.$tag.$RANDOM"
    echo "[adblock] Hämtar ($tag): $url"
    if ! curl -fsSL --retry 3 --retry-delay 5 --max-time "$CDN_FETCH_TIMEOUT" "$url" -o "$f"; then
      echo "[adblock] VARNING: misslyckades att hämta ($tag): $url"; continue
    fi
    local conv="$WORK/conv.$tag.$RANDOM"; to_dnsmasq_rules "$f" "$conv"; cat "$conv" >> "$tmp_rules"; got_any=1
  done < "$srcs"

  if [ "$got_any" -ne 1 ]; then echo "[adblock] FEL: Inga källor kunde hämtas."; return 2; fi

  sed -i -e 's/\r$//' -e 's/[[:space:]]\+$//' "$tmp_rules"
  grep -E '^address=/[A-Za-z0-9.-]+/0\.0\.0\.0$' "$tmp_rules" | sort -u > "$tmp_rules2" || true
  mv "$tmp_rules2" "$tmp_rules"

  apply_adblock_whitelist "$tmp_rules"

  local domains_count; domains_count=$(wc -l < "$tmp_rules" 2>/dev/null | tr -d ' ' || echo 0)
  if [ "${domains_count}" -eq 0 ]; then echo "[adblock] VARNING: 0 regler efter whitelist – aktiverar inte."; return 3; fi

  wrap_as_conf "$tmp_rules" "$tmp_conf"
  if ! dnsmasq_test_conf "$tmp_conf"; then
    echo "[adblock] VARNING: Validering misslyckades. Försöker OISD-fallback..."
    local oisd_fallback="$WORK/oisd.fb"
    if fetch "https://small.oisd.nl/dnsmasq" "$oisd_fallback"; then
      to_dnsmasq_rules "$oisd_fallback" "$tmp_rules"; apply_adblock_whitelist "$tmp_rules"; wrap_as_conf "$tmp_rules" "$tmp_conf"
      if ! dnsmasq_test_conf "$tmp_conf"; then echo "[adblock] FEL: Validering misslyckades även med OISD-fallback."; return 4; fi
    else
      echo "[adblock] FEL: kunde inte hämta OISD-fallback."; return 5;
    fi
  fi

  as_root mv "$tmp_conf" "$ADBLOCK_CONF"
  if as_root /etc/init.d/dnsmasq restart; then echo "[adblock] Aktiverad via $ADBLOCK_CONF (domäner=${domains_count})"
  else echo "[adblock] VARNING: dnsmasq restart misslyckades."; return 6; fi

  local blocked_24h; blocked_24h=$(count_adblock_events)
  {
    echo "=== $(date -u +'%Y-%m-%d %H:%M:%SZ') ==="
    echo "multi_source=1"
    echo "domains_after_whitelist=${domains_count}"
    echo "blocked_replies_24h=${blocked_24h}"
    echo "conf_path=${ADBLOCK_CONF}"
    echo
  } >> "$ADBLOCK_LOG"
  echo "[adblock] multi=1 domains=${domains_count} blocked_24h=${blocked_24h}" >> "${STATE_LOG}"
}

# ---- Endast statistik (utan fetch) – valfritt
adblock_stats() {
  local conf="$ADBLOCK_CONF" domains_conf=0 blocked_24h=0
  if [ -f "$conf" ]; then
    domains_conf=$(grep -E '^(address=|server=|local=|domain=)' "$conf" | grep -vE '^\s*\#' | wc -l | tr -d ' ' || true)
  fi
  blocked_24h=$(count_adblock_events)
  echo "[adblock-stats] conf_path=${conf}"
  echo "[adblock-stats] domains_in_conf=${domains_conf}"
  echo "[adblock-stats] blocked_replies_24h=${blocked_24h}"
  {
    echo "=== $(date -u +'%Y-%m-%d %H:%M:%SZ') ==="
    echo "stats_only=1"
    echo "domains_in_conf=${domains_conf}"
    echo "blocked_replies_24h=${blocked_24h}"
    echo "conf_path=${conf}"
    echo
  } >> "$ADBLOCK_LOG"
  echo "[adblock-stats] domains=${domains_conf} blocked_24h=${blocked_24h}" >> "${STATE_LOG}"
}

# ---- Trigger adblock vid körning (ADBLOCK=1 eller flagga)
if [ "${ADBLOCK:-0}" = "1" ] || [ "${1:-}" = "--adblock" ] || [ "${2:-}" = "--adblock" ]; then
  update_adblock_dnsmasq
fi

# ---- Skriv statistik (oavsett om adblock uppdaterades)
[ "$DO_ADBLOCK_STATS" -eq 1 ] && adblock_stats

exit 0