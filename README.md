# EdgeRouter Dynamic Blacklist (network-group)

En robust lösning för EdgeOS för att synkronisera en firewall **network-group** mot publika IPv4-blocklistor. Skriptet är designat för att vara stabilt och undvika de vanliga databasfel som kan uppstå vid stora ändringar i EdgeRouter-konfigurationen.

## Varför denna lösning?
Till skillnad från enkla skript som bara skriver över listan, använder detta skript en **tvåstegs commit-process** via `vyatta-cfg-cmd-wrapper`:
1. **Fas 1 (DEL):** Tar bort medlemmar som inte längre finns i källistan.
2. **Fas 2 (ADD):** Lägger till nya medlemmar.

Detta förhindrar felmeddelanden som `unexpected member not found` och säkerställer att brandväggen inte låser sig under uppdateringen.

## Funktioner
- **Idempotent:** Utför endast nödvändiga ändringar (diff).
- **Säker:** Inkluderar en inbyggd whitelist för att förhindra att du låser ute dig själv.
- **Historik:** Sparar detaljerad körlogg och statistik i `/config/scripts/.blacklist_state/`.
- **Reparation:** Inkluderar `repair-blacklist.sh` för att återställa gruppen vid behov.

## Installation

### 1. Förbered skripten
Ladda upp eller skapa `blacklist.sh` och `repair-blacklist.sh` i `/config/scripts/` och gör dem körbara:

```bash
chmod +x /config/scripts/blacklist.sh
chmod +x /config/scripts/repair-blacklist.sh
```

### 2. Skapa brandväggsgruppen (valfritt)
Om du inte redan har gruppen `blacklist_net`, skapa den:
```bash
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group network-group blacklist_net description "Dynamic blacklist"
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
```

## Användning

### Förhandsgranska ändringar (Dry-run)
För att se vad som skulle hända utan att faktiskt ändra något:
```bash
DRY_RUN=1 /config/scripts/blacklist.sh
```

### Manuell uppdatering
```bash
/config/scripts/blacklist.sh
```

### Automatisering
Schemalägg uppdatering var 12:e timme via EdgeOS:
```bash
configure
set system task-scheduler task update-blacklist executable path /config/scripts/blacklist.sh
set system task-scheduler task update-blacklist interval 12h
commit; save; exit
```

## Felsökning

### Vanliga fel
* **Unexpected member not found:** Kan uppstå om konfigurationsdatabasen är osynkad. Kör då:
  ```bash
  /config/scripts/repair-blacklist.sh
  ```
* **Inspektera temporära filer:** Kör med `KEEP_WORK=1` för att behålla filerna i `/tmp/blacklist_cidr.*` för manuell granskning.

## Källor
Skriptet hämtar data från FireHOL:
* [DShield netset](https://iplists.firehol.org/files/dshield.netset)
* [FireHOL Level 1](https://iplists.firehol.org/files/firehol_level1.netset)

---
*Används på egen risk. Se till att alltid ha en fungerande whitelist för dina administrativa IP-adresser.*