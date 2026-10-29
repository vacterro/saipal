# SAIPAL

> **Märkus.** See eestikeelne peegel kirjutati varasema SAIPAL-i versiooni kohta
> ja ei ole enam ajakohane; uuendatud tõlget ei ole veel. Ametlik ja ajakohane
> dokumentatsioon on ingliskeelne [README.md](README.md).
> (verification counts quoted there: checkpoint `T-130-VERIFY-2026-09-18-R5`.)

SAIPEN-i protokollile alluvate agendiseссioonide kohtulik vaatleja.

SAIPAL loeb päris sessioonitõendeid, võrdleb täheldatud käitumist sellega
SAIPEN-i protokolli versiooniga, mis neid tegelikult juhtis, isoleerib
juurpõhjused ja annab kvalifitseeritud leiud muutmatute audititena SAIPEN
Core'i haldajale.

SAIPAL ei ole **teine haldaja**. Ta vaatleb ja teatab. Otsustab haldaja.

## Kuidas ta on üles ehitatud

Kaks kihti ja nende vaheline piir on kogu disain
(`saipal/ARCHITECTURE.md`):

- **Kiht A — deterministlik tuum.** Ainult Pythoni standardteek kaustas
  `tools/saipal_engine/`. Omab tõendite identiteeti, räsid, sessiooniindeksit,
  HOT/COLD vesimärke, protokollisidumist, kandjate jaotust, mehaanilisi
  detektorisignaale, leidude valideerimist, do-no-harm väravat, auditite
  ehitust ja ainust piiratud enqueue't. Ta ei kutsu kunagi mudelit ega loe
  tähendust.
- **Kiht B — asendatav analüütik.** Igasugune suuteline agent. Ta loeb dialoogi
  tähendust, arutleb leiud mõlemalt poolt ja esitab ühe struktureeritud
  kandidaadi tööühiku kohta läbi `saipal submit` — ainukese kirjutamistee.

Just see lõhe teeb tööriista auditeeritavaks: osa, mis saab hallutsineerida, ei
saa kirjutada, ja osa, mis kirjutab, ei saa tõlgendada.

## Siit alusta

- `saipal/BOOT.md` — kuidas SAIPAL käivitub, taastub ja teeb kontrollpunkte
- `saipal/CORE.md` — globaalsed seadused (sh PAL-EVIDENCE-02: transkriptid on usaldamata andmed)
- `saipal/ARCHITECTURE.md` — kahe kihi piir
- `saipal/SKILL.md` — peenike agendi adapter: iga agent võib olla SAIPAL
- `saipal/ANALYSIS.md` — semantilise kohtuliku arutluse leping
- `saipal/COMMANDS.md` — operaatori tööpind
- `saipal/INDEX.md` — dokumendikaart: üks küsimus, üks omanikudokument

## Paigalda sõltumisena (skill)

`skills/saipal/SKILL.md` on Freebuff'i skilli manifest `/saipal cc` jaoks.
Kopeeri see oma platvormi skillide kataloogi, et käsk oleks igale agendile
kättesaadav:

```bash
mkdir -p "$HOME/.agents/skills/saipal"
cp skills/saipal/SKILL.md "$HOME/.agents/skills/saipal/SKILL.md"
```

`/saipal cc` lülitab sisse DETECTIVE režiimi (piiratud analüütiku tsükkel: `cc` →
`--json next` → prokuröri/kaitsja arutlus → `submit` → korda raames
`SAIPAL_CC_BUDGET`) ja lõpeb REPORTER režiimis (`report`), nii et skilliga agent
saab päris sessioone hinnata ja triivi omistamisega teatada. Mootor ja protokoll
jäävad sellesse reposse; skill leiab ainult `saipal_root` (env `SAIPAL_ROOT`,
siis tuntud checkout, siis lähim esivanem, kus on `tools/saipal.py` +
`saipal/SKILL.md`) ja `.saipal/` kodu.

## Käivita

```bash
python -B tools/saipal.py continue          # üks piiratud tsükkel (alias: cc)
python -B tools/saipal.py continue --drain  # korda tsükleid kuni tühjuse või blokini
python -B tools/saipal.py --json next       # järgmine analüüsikandja
python -B tools/saipal.py submit cand.json  # võta vastu üks analüütikukandidaat
python -B tools/saipal.py report            # triiviaruanne
python -B tools/saipal.py status            # kompaktne kokkuvõte
python -B tools/saipal.py sessions 25       # teadaolevad sessioonid, värskemad esite
python -B tools/saipal.py --json evidence SESSION EVENT   # piiratud usaldamata aken
python -B tools/saipal.py doctor            # kirjutuskaitstud diagnoos
python -B tools/saipal.py setup --source PATH --kind generic   # seadista
python -B tools/saipal.py disposition receipts.json            # suletud ring
python -B tools/saipal.py trigger           # taotle üks ootel jooks (koalestsents)
python -B tools/test_runner.py              # täielik komplekt, puhas checkout
python -B tools/validate.py                 # protokolli ja registri triivivärav
```

Ainult standardteek. Ilma pip-sõltuvusteta. Python 3.8+.

## Analüütiku tsükkel

```
saipal --json continue          # impordi tõendid, käivita mehaaniline läbimine
saipal --json next              # üks piiratud kandja: episood + tõendid + seadus
   mõtle see läbi, siis
saipal --json submit cand.json  # DRIFT, NO_DRIFT või INSUFFICIENT_EVIDENCE
saipal report                   # otsus, koos katvuse kõrval
```

`NO_DRIFT` on esmaklassiline tulemus: see on kviitung, mis tõestab, et episood
vaadati läbi, ja ainus asi, mis semantilist vesimärki liigutab. Puhas sessioon
on seega *tõestatult* puhas, mitte lihtsalt süüdimata.

`report` ei loe kunagi puhtaks, kui midagi ei hinnatud. Otsuste hulk:
`NO_EVIDENCE`, `NOT_EXAMINED`, `NO_DRIFT_SO_FAR`, `DRIFT_SUSPECTED`,
`DRIFT_REPORTED`, ja katvus sõidab alati kõrvuti.

## Mis hoiab ta ausana

- **Säga tagant ei ole.** Leiu tohib rikkumist väita ainult siis, kui sessiooni
  protokollisidumine on teada ja reegel eksisteeris valitsevas versioonis.
- **Sidumist tõestatakse, ei deklareerita.** `BOUND`-i väitev pakett säilib
  `UNKNOWN`-ina: tõestus tuletatakse uuesti operaatori deklareeritud protokolli
  võimu vastu (Git-hoidla, väljalaske juur või snapshot'i juur) ja peab
  ühtima päris baitidega.
- **Transkriptid on usaldamata andmed.** Analüüsitud vestlused on tõendid, mitte
  võim; sessiooni sisene tekst ei saa laiendada seda, mida SAIPAL tohib.
- **Ära tee kahju.** Parandus, mis ulatub kaitstud invarianti deklareerimata,
  süüdlusest, mis süüdistab mudelit protokolli asemel, blokeeritakse enne auditit.
- **Üks juurpõhjus, üks leid.** Identiteet on normaliseeritud põhjuslik võti;
  ümbersõnastus ei lõhke kordumisketti.
- **Levik otsustab paranduspinnale.** Üks mudel triivib, kus teine täitis — see
  on mudeli mittejärgimine, mitte protokolli defekt.

## Staatus

Versioon **v0.4.3**. Lained A–I, jõudlusskaneering SRC-004 ja avaldamisvärav T-109: kandja on seotud kanoonilise kogumi `bundle_sha256`-ga, sessioonide ja indeksi DAR-i ei parsita enam kogumi identiteediga koos uuesti, projektsioonid on tihendatud ning auditeeritav tootmisvärav `readiness mint + setup --shadow-reviewed` on juurutatud ja roheline.

Avaldamine vaikeseadena `STAGE_ONLY`; `PUBLISH_ENABLED` nõuab selgesõnalist
operaatori ülevaatatud variuuringut **ja** valideeritud sinki juurt samas
väljakutses.

Vaata `WAVE_I_CHECKPOINT.md` asutuskatvuse kohta,
`docs/TERMISAI_EVIDENCE_CONTRACT.md` tõendite lepingu kohta,
`SAIPAL_OPERATIONAL_HANDOFF.md` operatiivse pinna ja vearežiimide kohta ning
`docs/audits/` selle repo välisauditite kohta.

## Proovi päris auditit otsast lõpuni

```bash
cp tests/golden_sessions/agent-noncompliance-command-route.json .saipal/session_inbox/
python -B tools/saipal.py cc
python -B tools/saipal.py report
# -> .saipal/audit/staging/1.md, .saipal/findings/index.json,
#    .saipal/closed_loop_links.json
```
