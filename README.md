
# EdgeRouter Dynamic Blacklist (network‑group)

En robust, EdgeOS‑vänlig lösning för att hålla en firewall **network‑group** (standard: `blacklist_net`) synkad mot kuraterade IPv4‑CIDR‑blocklistor. Uppdateringen sker i **två commit‑faser** (DEL → ADD) via Vyatta‑wrapperkommandon för att undvika vanliga EdgeOS‑problem som:

- `unexpected member not found [x.x.x.x/nn]`
- `validateSetPath() without config session`

✅ Testad på EdgeRouter PoE  
✅ Använder **endast** `vyatta-cfg-cmd-wrapper` / `vyatta-op-cmd-wrapper` för konfig‑ändringar (stabila från `vbash`)

---

## Innehåll

- Funktioner
- Filer
- Krav
- Installation
- Användning
  - Dry‑run (ingen ändring)
  - Skarp körning (tillämpa ändringar)
  - Schemaläggning (automatiskt)
- Repair‑skript
- Konfiguration
- Loggar & historik
- Exempel
- Felsökning
- Design‑noteringar

---

## Funktioner

- Hämtar IPv4‑CIDR från **FireHOL** (DShield + Level 1).
- Filtrerar reserverade/privata/multicast/dokumentations‑nät.
- Valfri **whitelist** för nät som aldrig ska blockas.
- Idempotent **diff‑uppdatering:**
  - **Fas 1:** säkra **DELETE** av endast verkligt existerande medlemmar.
  - **Fas 2:** **ADD** av saknade medlemmar + uppdaterad beskrivning.
- **Dry‑run** (`--dry-run` eller `DRY_RUN=1`) för att förhandsgranska ändringar utan commit.
- Beständig **sammanfattning & historik**:
  - TSV: `/config/scripts/.blacklist_state/summary.tsv` (maskinläsbar)
  - Logg: `/config/scripts/.blacklist_state/runs.log` (lättläst)
  - Retention via `MAX_HISTORY`.

---

## Filer

- **`/config/scripts/blacklist.sh`** – Uppdaterare (två fasers commit + dry‑run + sammanfattning/historik).
- **`/config/scripts/repair-blacklist.sh`** – Reparationsskript som återskapar gruppen om EdgeOS fastnar.

Ytterligare:
- **`/config/scripts/.blacklist_state/summary.tsv`** – historik (timestamp, current_after, final, adds, dels, net).
- **`/config/scripts/.blacklist_state/runs.log`** – läsbar körlogg med deltor mot föregående körning.

> Wrapper‑binärer som används:
> - `/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper` (config‑ändringar)
> - `/opt/vyatta/sbin/vyatta-op-cmd-wrapper` (show/read)

---

## Krav

- EdgeRouter med EdgeOS (PoE‑modeller fungerar).
- Utgående HTTPS‑åtkomst (för att hämta listor).
- `curl` **eller** `wget` installerat på routern.
- Kör som router‑admin (inte via `sudo`).

---

## Installation

1) Kopiera in skripten och gör dem körbara:
```bash
sudo mkdir -p /config/scripts
sudo vi /config/scripts/blacklist.sh
sudo vi /config/scripts/repair-blacklist.sh
sudo chmod +x /config/scripts/blacklist.sh /config/scripts/repair-blacklist.sh
```
## (Valfritt) Skapa gruppen första gången:
```bash
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group network-group blacklist_net description "Dynamic blacklist"
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
```

## Användning
### Dry‑run (ingen ändring)
#### Förhandsgranska vad som **skulle** tas bort/läggas till (visar 20 rader som standard):
```bash
/config/scripts/blacklist.sh --dry-run
# eller:
DRY_RUN=1 /config/scripts/blacklist.sh
```
#### Val
```bash

# Visa fler rader (ex 50) i ADD/DEL-listor
DRY_RUN=1 DRY_RUN_SHOW=50 /config/scripts/blacklist.sh

# Behåll tempkatalogen för inspektion
DRY_RUN=1 KEEP_WORK=1 /config/scripts/blacklist.sh

# Begränsa historik till senaste 365 körningarna
DRY_RUN=1 MAX_HISTORY=365 /config/scripts/blacklist.sh
```
### Skarp körning (tillämpa ändringar)
#### Kör två commits: först DELs, sedan ADDs + beskrivning. Sammanfattning och historik uppdateras.
```bash
/config/scripts/blacklist.sh
```

## Schemaläggning (automatiskt)

### Kör var 12:e timme via EdgeOS task‑scheduler:
```bash
configure
set system task-scheduler task update-blacklist executable path /config/scripts/blacklist.sh
set system task-scheduler task update-blacklist interval 12h
commit; save; exit
```

## Repair‑skript (vid låsningar / fel)
### Om du ser upprepade fel som:
#### unexpected member not found [x.x.x.x/nn]
#### group [blacklist_net] still in use
### …kör repair en gång:
```bash
/config/scripts/repair-blacklist.sh
```
### Vad det gör:
* Skapar temporär grupp blacklist_net_tmp.
* Flyttar alla firewall‑regelreferenser från blacklist_net → blacklist_net_tmp.
* Raderar blacklist_net.
* Skapar om en ren blacklist_net.
* Flyttar tillbaka referenserna.
*Tar bort blacklist_net_tmp.

### Kör sedan uppdateraren igen:
```bash
/config/scripts/blacklist.sh
```

## Konfiguration
### I blacklist.sh
#### Gruppnamn
GROUP_NET="blacklist_net"
#### Källor (FireHOL-standard)
```bash
LIST_URLS=(
  "https://iplists.firehol.org/files/dshield.netset"
  "https://iplists.firehol.org/files/firehol_level1.netset"
)
```
#### Whitelist (lägg in dina admin/jumphosts m.m.)
```bash

WHITELIST_CIDR=(
  "203.0.113.0/24"
  "1.1.1.1/32" "1.0.0.1/32"
  "8.8.4.4/32" "8.8.8.8/32"
  "9.9.9.9/32"
)
```
#### Begränsa storlek på slutlistan (valfritt)
```bash
MAX_NETS=0   # 0 = obegränsat; ex sätt 5000 för att kapa väldigt stora listor
```
#### Dry-run / logg / historik
```bash
DRY_RUN=0
DRY_RUN_SHOW=20
KEEP_WORK=0
MAX_HISTORY=500
```
### Loggar & historik
* **Syslog**: alla meddelanden taggade med blacklist → /var/log/messages.

* **Läsbar per‑körningslogg**:
```bash
/config/scripts/.blacklist_state/runs.log
```

#### Innehåller timestamp, current före/efter, adds/dels/netto, och **deltor** vs föregående körning.
* **TSV-historik (maskinläsbar):
```bash
/config/scripts/.blacklist_state/summary.tsv
```
#### Format: 
```bash
timestamp<TAB>current_after<TAB>final<TAB>adds<TAB>dels<TAB>netto
```
#### Trimmad till MAX_HISTORY om satt.


## Exempel
### Dry‑run med 50 rader och behåll temp:
```bash
DRY_RUN=1 DRY_RUN_SHOW=50 KEEP_WORK=1 /config/scripts/blacklist.sh
ls -la /tmp/blacklist_cidr.*
sed -n '1,120p' /tmp/blacklist_cidr.XXXXXX/to_del.txt
sed -n '1,120p' /tmp/blacklist_cidr.XXXXXX/to_add.txt
```
### Skarp körning:
```bash
/config/scripts/blacklist.sh
```

### Kontrollera exakt om en CIDR finns:
```bash
/opt/vyatta/sbin/vyatta-op-cmd-wrapper show configuration commands \
  | grep -F -x "set firewall group network-group blacklist_net network 199.45.154.0/24" \
  && echo "Finns" || echo "Saknas"
```
### Visa senaste historik
```bash
tail -n 10 /config/scripts/.blacklist_state/summary.tsv
tail -n 30 /config/scripts/.blacklist_state/runs.log
```
### Schemalägg (12h):
```bash
configure
set system task-scheduler task update-blacklist executable path /config/scripts/blacklist.sh
set system task-scheduler task update-blacklist interval 12h
commit; save; exit
```
### Repair + uppdatering
```bash
/config/scripts/repair-blacklist.sh
/config/scripts/blacklist.sh
```

## Felsökning
* **unexpected member not found […] vid commit**
 unexpected member not found […] vid commit
*** Kör repair-blacklist.sh
*** Kör blacklist.sh igen.
* **validateSetPath() without config session / sessionsfel**
Kommer av config‑kommandon utanför giltig session. Dessa skript använder endast wrapper‑binärerna, vilket undviker session‑mismatch.

* Inspektera tempdata
Kör med KEEP_WORK=1 och titta i /tmp/blacklist_cidr.*:
** to_del.txt — vilka medlemmar tas bort
** to_add.txt — vilka läggs till
** current_cidr.txt — vad som fanns före
** final_cidr.norm — önskat efter filtrering

## Design‑noteringar

* **Exakt strängmatchning** (grep -F -x) för att undvika regex‑fallgropar med CIDR‑punkter.
* **Tvåstegs commit** (DEL → ADD) för att undvika EdgeOS diff‑quirks när operationer blandas.
* Ingen script-template för config‑steg; **wrapper‑binärer** är robustare från vbash.
* Källor: FireHOL‑listor (DShield/Level1):
** https://iplists.firehol.org/files/dshield.netset
** https://iplists.firehol.org/files/firehol_level1.netset
Säkerhetstips: Whitelista dina administrativa IP‑områden (jump hosts, monitorering etc.) för att undvika oavsiktliga avstängningar.
