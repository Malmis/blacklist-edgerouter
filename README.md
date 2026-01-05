# EdgeRouter Dynamic Blacklist (network‑group) och adblock (dnsmasq)
Detta är ett kombinerat skript för firewall-blacklist (network-group) och adblock (dnsmasq)

En robust, EdgeOS‑vänlig lösning för att hålla en firewall **network‑group** (standard: `blacklist_net`) synkad mot kuraterade IPv4‑CIDR‑blocklistor. Uppdateringen sker i **två commit‑faser** (DEL → ADD) via Vyatta‑wrapperkommandon för att undvika vanliga EdgeOS‑problem som:

- `unexpected member not found [x.x.x.x/nn]`
- `validateSetPath() without config session`

✅ Testad på EdgeRouter PoE  
✅ Använder **endast** `vyatta-cfg-cmd-wrapper` / `vyatta-op-cmd-wrapper` för konfig‑ändringar (stabila från `vbash`)

---

## Innehåll

- [Funktioner](#funktioner)
- [Filer](#filer)
- [Krav](#krav)
- [Installation](#installation)
- [Användning](#användning)
- [Schemaläggning](#schemaläggning-automatiskt)
- [Repair‑skript](#repair-skript-vid-låsningar--fel)
- [Konfiguration](#konfiguration)
- [Loggar & historik](#loggar--historik)
- [Exempel](#exempel)
- [Felsökning](#felsökning)
- [Design‑noteringar](#design-noteringar)

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

**Ytterligare:**
- **`/config/scripts/.blacklist_state/summary.tsv`** – historik (timestamp, current_after, final, adds, dels, net).
- **`/config/scripts/.blacklist_state/runs.log`** – läsbar körlogg med deltor mot föregående körning.

> **Wrapper‑binärer som används:**
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

1. **Kopiera in skripten och gör dem körbara:**
   ```bash
   sudo mkdir -p /config/scripts
   sudo vi /config/scripts/blacklist.sh
   sudo vi /config/scripts/repair-blacklist.sh
   sudo chmod +x /config/scripts/blacklist.sh /config/scripts/repair-blacklist.sh
   ```

2. **(Valfritt) Skapa gruppen första gången:**
   ```bash
   /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
   /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group network-group blacklist_net description "Dynamic blacklist"
   /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
   /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save
   /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
   ```

---

## Användning

### Dry‑run (ingen ändring)
Förhandsgranska vad som **skulle** tas bort/läggas till (visar 20 rader som standard):
```bash
/config/scripts/blacklist.sh --dry-run
# eller:
DRY_RUN=1 /config/scripts/blacklist.sh
```

**Val för Dry-run:**
```bash
# Visa fler rader (ex 50) i ADD/DEL-listor
DRY_RUN=1 DRY_RUN_SHOW=50 /config/scripts/blacklist.sh

# Behåll tempkatalogen för inspektion
DRY_RUN=1 KEEP_WORK=1 /config/scripts/blacklist.sh

# Begränsa historik till senaste 365 körningarna
DRY_RUN=1 MAX_HISTORY=365 /config/scripts/blacklist.sh
```

### Skarp körning (tillämpa ändringar)
Kör två commits: först DELs, sedan ADDs + beskrivning. Sammanfattning och historik uppdateras.
```bash
/config/scripts/blacklist.sh
```

---

## Schemaläggning (automatiskt)

Kör var 12:e timme via EdgeOS task‑scheduler:
```bash
configure
set system task-scheduler task update-blacklist executable path /config/scripts/blacklist.sh
set system task-scheduler task update-blacklist interval 12h
commit; save; exit
```

---

## Repair‑skript (vid låsningar / fel)



Om du ser upprepade fel som `unexpected member not found [x.x.x.x/nn]` eller `group [blacklist_net] still in use`, kör repair en gång:
```bash
/config/scripts/repair-blacklist.sh
```

**Vad det gör:**
* Skapar temporär grupp `blacklist_net_tmp`.
* Flyttar alla firewall‑regelreferenser från `blacklist_net` → `blacklist_net_tmp`.
* Raderar `blacklist_net`.
* Skapar om en ren `blacklist_net`.
* Flyttar tillbaka referenserna.
* Tar bort `blacklist_net_tmp`.

---

## Konfiguration

Inställningar görs direkt i början av `blacklist.sh`:

**Gruppnamn:**
```bash
GROUP_NET="blacklist_net"
```

**Källor (FireHOL-standard):**
```bash
LIST_URLS=(
  "https://iplists.firehol.org/files/dshield.netset"
  "https://iplists.firehol.org/files/firehol_level1.netset"
)
```

**Whitelist (viktigt för att inte låsa ute sig själv):**
```bash
WHITELIST_CIDR=(
  "203.0.113.0/24"
  "1.1.1.1/32" "1.0.0.1/32"
  "8.8.4.4/32" "8.8.8.8/32"
  "9.9.9.9/32"
)
```

**Övriga parametrar:**
```bash
MAX_NETS=0      # 0 = obegränsat; ex sätt 5000 för att begränsa storlek
DRY_RUN=0
DRY_RUN_SHOW=20
KEEP_WORK=0
MAX_HISTORY=500
```

---

## Loggar & historik

* **Syslog**: Alla meddelanden taggade med `blacklist` skickas till `/var/log/messages`.
* **Läsbar körlogg**: `/config/scripts/.blacklist_state/runs.log`
  * Innehåller timestamp, status före/efter, och deltor mot föregående körning.
* **TSV-historik**: `/config/scripts/.blacklist_state/summary.tsv`
  * Format: `timestamp <TAB> current_after <TAB> final <TAB> adds <TAB> dels <TAB> netto`

---

## Exempel

**Dry‑run med 50 rader och behåll temp:**
```bash
DRY_RUN=1 DRY_RUN_SHOW=50 KEEP_WORK=1 /config/scripts/blacklist.sh
ls -la /tmp/blacklist_cidr.*
```

**Kontrollera om en specifik CIDR finns i konfigurationen:**
```bash
/opt/vyatta/sbin/vyatta-op-cmd-wrapper show configuration commands \
  | grep -F -x "set firewall group network-group blacklist_net network 199.45.154.0/24" \
  && echo "Finns" || echo "Saknas"
```

---

## Felsökning

* **`unexpected member not found […]` vid commit**
    * Kör `repair-blacklist.sh`
    * Kör `blacklist.sh` igen.

* **`validateSetPath() without config session` / sessionsfel**
    * Kontrollera att skriptet körs via `vbash`. Skriptet använder wrapper‑binärer vilket normalt undviker session‑mismatch.

* **Inspektera tempdata**
    * Kör med `KEEP_WORK=1` och titta i `/tmp/blacklist_cidr.*`:
        * `to_del.txt` — vilka medlemmar tas bort
        * `to_add.txt` — vilka läggs till
        * `current_cidr.txt` — vad som fanns före

---

## Design‑noteringar

* **Exakt strängmatchning** (`grep -F -x`) används för att undvika regex‑fallgropar med CIDR‑punkter.
* **Tvåstegs commit** (DEL → ADD) hanterar EdgeOS diff‑quirks mer stabilt än enstaka commits.
* **Wrapper‑binärer** används istället för script-templates då de är robustare direkt från `vbash`.
* **Källor:** FireHOL-listor ([DShield](https://iplists.firehol.org/files/dshield.netset) / [Level 1](https://iplists.firehol.org/files/firehol_level1.netset)).

> **Säkerhetstips:** Whitelista alltid dina administrativa IP‑områden (jump hosts, monitorering etc.) för att undvika oavsiktliga avstängningar.


## Whitelist-exempel för Adblock

För att undanta vissa domäner från blockering:

1. Skapa whitelist-fil (om den inte finns):
```bash
sudo mkdir -p /config/blacklist
sudo touch /config/blacklist/adblock-whitelist.txt
```

2. Lägg till domäner i whitelist:
- Exakt domän: `example.com`
- Alla underdomäner: `.example.com`

Exempel:
```bash
echo "example.com" >> /config/blacklist/adblock-whitelist.txt
echo ".sub.example.net" >> /config/blacklist/adblock-whitelist.txt
echo "cdn.example.org" >> /config/blacklist/adblock-whitelist.txt
```

3. Kör skriptet:
```bash
sudo vbash /config/scripts/blacklist.sh
```

Skriptet kommer att:
- Hämta OISD-listan.
- Ta bort alla domäner som matchar whitelist.
- Aktivera adblock.
- Logga antal domäner efter whitelist och blockeringar senaste 24h.

**Kontrollera loggar:**
```bash
tail -n 50 /config/scripts/.blacklist_state/adblock.log
tail -n 50 /config/scripts/.blacklist_state/runs.log
```

---

## Hantera adblock-whitelist

För att undanta vissa domäner från adblock:

1. **Skapa whitelist-fil om den inte finns:**
```bash
sudo mkdir -p /config/blacklist
sudo touch /config/blacklist/adblock-whitelist.txt
```

2. **Lägg till domäner i filen:**
- Exakt domän: `example.com`
- Alla underdomäner: `.example.com`

Exempel:
```bash
echo "netflix.com" >> /config/blacklist/adblock-whitelist.txt
echo ".spotify.com" >> /config/blacklist/adblock-whitelist.txt
echo "youtube.com" >> /config/blacklist/adblock-whitelist.txt
```

3. **Kör uppdatering med adblock:**
```bash
/config/scripts/blacklist.sh --adblock
```

Skriptet kommer att:
- Hämta alla adblock-källor (OISD, StevenBlack, 1Hosts Lite, AdGuard DNS filter).
- Konvertera till dnsmasq-format.
- Ta bort alla domäner som matchar whitelist.
- Aktivera adblock via dnsmasq.

4. **Kontrollera loggar:**
```bash
tail -n 50 /config/scripts/.blacklist_state/adblock.log
tail -n 50 /config/scripts/.blacklist_state/runs.log
```

> **Tips:** Du kan lägga till streamingtjänster, sociala medier och spelplattformar i whitelist för att undvika problem med appar.
