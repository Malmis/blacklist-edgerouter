
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
