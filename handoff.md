# Handoff — Diplomski rad: IDS za CAN komunikaciju

> Sažetak svih dosadašnjih saznanja, ideja i statusa projekta nastalih kroz razgovore sa
> ranijim LLM pomoćnicima. Služi kao polazna tačka za nastavak rada bez ponavljanja.
> Projekat se vodi na srpskom jeziku.

> ⚙️ **JEZIK APLIKACIJE:** Web aplikacija (`frontend/`) i backend (`backend/`) **UVEK moraju
> biti na engleskom jeziku** — sav UI tekst, komentari, docstring-ovi i poruke. NIJEDAN srpski
> tekst u kodu aplikacije. (Dokumenti `handoff.md`, `plan_rada.html`, `reference/` ostaju na
> srpskom — to nije kod aplikacije.)

---

## 1. Tema diplomskog rada

> **Analiza i implementacija intrusion detection sistema (IDS) za zaštitu CAN komunikacije
> u automobilskim informacionim sistemima**

### Suština ideje

CAN mreža povezuje različite **ECU** jedinice u automobilu. Problem je što klasični CAN
protokol originalno nema ugrađene mehanizme kao što su autentifikacija i enkripcija, pa je
moguće da se na mreži pojavi sumnjiv ili zlonameran saobraćaj.

**Središnji problem rada:**

> Kako napraviti IDS koji prati CAN saobraćaj, prepoznaje anomalije/napade i upozorava ili
> reaguje kada detektuje sumnjivo ponašanje.

### Istraživačko pitanje

> Da li se jednostavan i objašnjiv IDS može koristiti za pouzdanu detekciju anomalija u CAN
> komunikaciji uz dovoljno malu latenciju za potencijalnu primenu u automobilskim sistemima?

### Priča / tok rada

1. Problem → CAN ima bezbednosne slabosti.
2. Postoje različiti IDS pristupi.
3. Implementiraš i testiraš odabrane pristupe.
4. Porediš tačnost i performanse.
5. Predlažeš najpogodniji pristup za **lightweight / realtime CAN IDS**.

---

## 2. Dve faze praktičnog dela

### Faza 1 — Dataset + Python (offline analiza)

- Javni CAN dataset sa normalnim i napadačkim saobraćajem, npr. **Car-Hacking dataset**.
- Implementacija više pristupa:
  - **rule-based** detekcija
  - **statistička / anomaly** detekcija
  - eventualno **Machine Learning**: Isolation Forest, Random Forest
- Poređenje metrika:
  - detection rate
  - precision
  - recall
  - F1-score
  - false positive rate (FPR)
  - brzina / latencija detekcije

### Faza 2 — Fizički demo sa ESP32 (live / realni auto)

Mala, potpuno izolovana CAN mreža, a kasnije i spajanje na pravi auto preko OBD2 porta.

```
ESP32 #1 + CAN transceiver
          │
       CAN BUS
          │
ESP32 #2 + CAN transceiver
          │
        IDS
```

Prikaz toka saobraćaja u simulaciji:

```
NORMALAN SAOBRAĆAJ
        ↓
ECU šalje očekivane CAN poruke

NAPAD / ANOMALIJA
        ↓
Neočekivana frekvencija poruka
Novi CAN ID
Neuobičajen payload
Flooding
        ↓
IDS DETEKTUJE
        ↓
ALERT
```

### Poređenje pristupa (tabela za rad)

| Pristup          | Prednost                            | Mana                        |
| ---------------- | ----------------------------------- | --------------------------- |
| Rule-based       | Brz i lako objašnjiv                | Teško detektuje nove napade |
| Statistical      | Relativno jednostavan               | Može imati false positive   |
| Isolation Forest | Može otkriti anomalije              | Potrebno podešavanje        |
| Random Forest    | Dobra klasifikacija poznatih napada | Zahteva označene podatke    |

---

## 3. Konkretna arhitektura projekta (automotive cybersecurity)

Real-time praćenje CAN bus saobraćaja, izvođenje napada ubrizgavanjem poruka
(spoofing / komanda za zaključavanje auta) i razvoj ML IDS-a koji u realnom vremenu
prepoznaje anomalije i lažne poruke.

```
[ Auto CAN Bus ] <---> [ SN65HVD230 ] <---> [ ESP32 TWAI ]
     <--- Serial/USB (SLCAN) ---> [ Linux/Mac SocketCAN (can0) ]
     <---> [ Python App (python-can + ML Model) ]
```

### Hardver i okruženje

- **Vozilo:** OBD2 port (CAN bus, tipično 500 kbps) — konkretno **VW Polo 6R (2009)**.
- **Mikrokontroler:** ESP32 (38-pin), ugrađeni TWAI/CAN kontroler.
- **CAN Transiver:** **SN65HVD230** (3.3V logika). Izbegnuti 5V moduli (TJA1050, MCP2515).
- **Host računari:** Linux sa integrisanim **SocketCAN** okvirom; za dom test se koristi MacBook.
- **Komunikacija:** ESP32 kao dvosmerni bridge između auta i laptopa preko Serial-to-USB
  (SLCAN/LAWICEL protokol), preslikan na `slcan0` / `can0` na hostu.

### Pinout i fizičko povezivanje (VW Polo 6R)

```
SN65HVD230 3.3V  -> ESP32 3V3
SN65HVD230 GND   -> ESP32 GND
SN65HVD230 CTX/TX -> ESP32 GPIO 4
SN65HVD230 CRX/RX -> ESP32 GPIO 5
SN65HVD230 Rs     -> GND   (fiksno high-speed režim za 500 kbps)

CANH -> OBD-II utičnica, pin 6
CANL -> OBD-II utičnica, pin 14
```

### Dosadašnja rešenja i status

- **Firmware:** ESP32 koristi ugrađeni hardverski TWAI drajver prepakovan u **SLCAN (LAWICEL)
  protokol** preko USB serijske komunikacije (115200 baud). Arduino IDE kod **već napisan**.
- **Softver na računaru:** Python + zvanična `python-can` biblioteka, koja komunicira sa ESP32
  preko `slcan` interfejsa na **500000 bps (500 kbps)**.
- **Status:** hardver sklopljen / izabran; kodovi za ESP32 i Python spremni.

### Ostali tehnički zaključci

1. ESP32 koristi TWAI biblioteke; SocketCAN i `vcan` na hostu služe za simulaciju,
   snimanje (`candump`), analizu i naprednu obradu.
2. Strategija testiranja: prvo simulacija na `vcan0` / stolu, potom spajanje na auto.
3. Python aplikacija mora koristiti **multithreading**, da čitanje SocketCAN-a ne kasni
   zbog računanja ML modela.

---

## 4. Sledeći koraci / mesta gde se stalo

1. Testiranje i flešovanje koda na ESP32.
2. Naprednije Python skripte za **filtriranje specifičnih CAN ID-jeva** (magistrala izbacuje
   ~100–500+ poruka u sekundi).
3. Reverse-engineering specifičnih komandi / praćenje parametara za **VW Polo 6R**
   (npr. zaključavanje auta, RPM, temperatura, brzina).
4. Pisanje / finalizacija **ML modela** za detekciju anomalija (featurei: ID, delta-t,
   dužina, payload).

### Odabrane metode IDS-a za diplomski (odluka — 09.2026)

Korisnik je odlučio da diplomski uporedi **tri metodologije** za IDS (a zatim komisiji
predstavi 1 "glavnu" za live prikaz; ostale služe kao uporedno poređenje u radu):

1. **Heurističko / statističko** — eksplicitna pravila zasnovana na bus-"otiscima":
   burst, nepoznati CAN ID-ovi, promena vrednosti/payload-a. **KOMPLETIRANO** u
   `backend/ids/ids_heuristic.py` (koraci 1–6, pogledaj `heuristics.html` §13):

   - **test1 (nepoznat ID):** ID van rečnika 27 naučenih ID-eva.
   - **test2 (burst):** per-ID prag `gap < 0.5 × period_min` (min gap iz čistog
     TRAIN-a), umesto globalnog `0.6×` koji je lažno okidao na prirodni jitter
     visokofrekventnih ID-eva.
   - **test3 (payload):** per-byte klasifikacija iz čistog TRAIN-a:
     **STATIC** (vrednost van [lo,hi] ≥3×), **DRIFT** (korak > 2× čisti max korak),
     **DYNAMIC** (preskače se — status/opcode bajtovi, ostavljeni ML-u).
   - **Korak 5:** logički OR tri testa = anomalija prozora.
   - **Rezultat:** FPR = 0% na VALID/TEST-normal; **100% coverage** na sva 4 napada
     (DoS→burst+payload, Fuzzy→nepoznat ID, gear/RPM→payload).

   Stariji istraživački prototip `ids_research.py` ostaje kao ranija verzija iste ideje.
2. **Isolation Forest** — nenadgledani ML; Feature-vektori iz iste featurizacije,
   trenira se samo na normal.csv.
3. **One-Class SVM** — nenadgledan; isti feature-i, trenira samo na normal.csv.

**ZAVRŠENO (09.2026)** — sve tri metode implementirane i pošteno izmerene (detalji u
`heuristics.html` §15/§16):

- **Isolation Forest** (`ids_isolation_forest.py`) — globalni model nad per-frame
  z-score obeležjima (`gap_z`, `max_abs_z`, `n_over_2`); NE per-ID profilisanje i NE
  per-(ID×1s-prozor), jer je jedan spoof okvir nevidljiv na nivou prozora (~1950 okvira/s).
- **One-Class SVM** (`ids_one_class_svm.py`) — RBF, `nu=0.001` (trening je čist),
  RobustScaler pre granice; deli isti feature-ekstraktor sa IF.
- **Red-team / injection evaluacija** (`ids_injection.py` + 3 manifesta
  `dataset /injection_manifest_1/2/3.json`) — ubrizgavanje pojedinačnih loših okvira u
  čist tok je POŠTENIJA mera od coverage-a (napadni fajlovi su zasićeni → heuristika na
  njima ima lažnih 100%, a realno 82–87%).

**Uporedni rezultati (detekcija na 3 manifesta, prosek):**

| Napad | Heuristika | Isolation Forest | One-Class SVM |
|-------|-----------|------------------|---------------|
| DoS   | 100%      | 100%             | 100%          |
| Fuzzy | 85%       | 89.3%            | **96.7%**     |
| gear  | 87%       | 77.3%            | **88.7%**     |
| RPM   | 82%       | 78.3%            | **87.0%**     |

FPR: 0% na VALID (sve tri); 0.001–0.013% na TEST-normal (1–2 okvira od ~148k).

**Zaključak poređenja:** One-Class SVM najbolji na svakoj kategoriji (glatka granica
gustine najbolje razdvaja pojedinačne spoof okvire); heuristika konkurentna na gear/RPM
(zbog "≥3 uzastopna" ojačanja), IF zaostaje na suptilnim single-frame spoof-ovima.

Važne naučne odluke (koje NE smemo zaboraviti kod implementacije):
- Sva tri dele **isti feature-ekstraktor** (po CAN ID / sekundi: rate, pravilnost
  ritma, promena vrijednosti) i **istu podelu**.
- Podela unutar jednog `normal.csv`: **TRAIN ~70% → VALIDATION ~15% → TEST-normal
  ~15%**, onda 4 napada (DoS/Fuzzy/gear/RPM) samo kao **evaluacija** (NIKAD u trening
  ili podešavanje — sprečava data leak).
- "Bolji algoritam" se **dokazuje merenjem** (precision/recall/F1) na sopstvenom
  dataset-u, ne unapred proglašava. Predlog: pustiti oba ML-a, izabrati po rezultatu.
- Plot: procjena je da 3 metode za analizu + 1 u aplikaciji **ne čini rad prevelikim**
  (zajednički feature = mali inkrementalni trud); all-3-u-live bi znatno povećao posao.

### Mogući fokus rada u nastavku (odabrati)

1. C++/Arduino kod za ESP32 (TWAI drajver + SLCAN/LAWICEL). _(napisano)_
2. Python skripte za čitanje, filtriranje i ubrizgavanje (spoofing) CAN poruka pomoću
   `python-can`.
3. Priprema i arhitektura ML modela za detekciju anomalija (feature extraction:
   ID, delta-t, dužina, payload).

---

## 5. Ciljevi

- **Primarni:** rad koji nije samo "evo ML model sa 99% accuracy", već konkretno poređenje
  pristupa primenjivo na lightweight/realtime CAN IDS.
- Obezbediti dovoljno malu latenciju za potencijalnu primenu u automobilskim sistemima uz
  objašnjivost detekcije.

---

## 6. Reference za rad

Sve izvore, linkove i literaturu čuvamo u `reference /references.md` (folder `reference `).
Glavni dataset je **Car-Hacking Dataset** (Kaggle / HCRL) — linkovi u tom fajlu;
podaci su raspakovani u `dataset /archive/` (<code>normal_run_data.txt</code> + `DoS`,
`Fuzzy`, `RPM`, `gear` CSV fajlovi).

---

## 7. Web aplikacija (React) — vizija i napredak

### Vizija: trodelna analitička + live aplikacija
Korisnik želi jednu React app sa **tri moda** koja deli isti UI, ali ima preklopiv izvor podataka:

1. **🔍 ANALIZA / čitanje (offline)** — čita prerecorded podatke (dataset, 15M poruka),
   analizira koji CAN ID, koji payload, koliko često, odakle dolaze → "učenje" koji je koji.
2. **🚗 LIVE mod** — povezan na auto (ESP32 + SN65HVD230), čita i šalje poruke uživo u mrežu.
3. **🎛 SIMULATOR** — kada nismo povezani na auto, vrti prerecorded podatke kao da su live
   (replay istim frekvencijama/redosledom), omogućava testiranje i demo bez auta.

### Arhitektura (ključna odluka)
Svi modovi dele isti **stream interfejs** backenda; UI se ne menja, samo se prebaci izvor:
```
 CSV (offline) / Simulator (replay) / Live (ESP32→socketcan)
        └──────────►  BACKEND (jedinstven stream)  ──► React UI (iste komponente)
```
- **Simulator = "fake live source"** (čita CSV, emituje poruke kao live) — omogućava test bez auta.
- Backend treba da podrži preklopu izvora tako da se live mod "prikači" kasnije bez prepravke frontenda.

### Definisan UI / interaktivne stvari
- Dashboard s više modula: ukupno poruka, TPS (broj/s), broj ID-jeva, raspodela tipova.
- Interaktivna tabela CAN ID-jeva → klik otvara detaljan panel:
  - frekvencija kroz vreme (chart)
  - histogram delta-t (periodičnost)
  - najčešći payload + heatmap bajtova
  - u kojim label-ovima se pojavljuje (normal/DoS/fuzzy/gear/RPM)
- Filteri: po label tipu, CAN ID-ju, DLC-u.
- Grafici: bar (ID frekvencije), line/area (vremenska serija), scatter/heatmap (bajtovi), pie (tipovi).
- Pretraga ID-jeva (hex ili decimal).
- Live mod: prikazuje poslednjih ~100 poruka + TPS + IDS alarme + filtre (ne bukvalno sve poruke — browser/DOM bi se usporio).

### Tehnološki izbor (odabrano)
- **Frontend:** React (Vite) + Recharts za grafikone, dark tema.
- **Backend:** Python + FastAPI (+ pandas) — čita dataset efikasno, izlaže REST + WebSocket.
- **Live hardver:** ESP32 + SN65HVD230 (pinovi iz handoff ranijeg dela), preko serial→socketcan.

### Stanje praksičnog poduhvata (do sada urađeno)
- `convert_dataset.py` — normalizuje sirovi dataset u čist CSV sa zaglavljem:
  `Timestamp, CAN_ID, DLC, B0..B7, Label` (CAN_ID sa `0x` prefiksom).
- Izlaz u `dataset /normalized/`: `normal.csv`, `DoS.csv`, `Fuzzy.csv`, `gear.csv`, `RPM.csv`
  (ukupno ~15.2M poruka, ~874MB).
- `backend/main.py` (FastAPI) — REST analiza + `/ws/stream` (simulator replay + live dev bridge).

### Live IDS + injection u Simulatoru (ZAVRŠENO — 09.2026)
- **`backend/ids/ids_runtime.py`** — objedinjeni per-frame `IdsEngine` koji obavija sve tri
  metode; skoruje svaki replej okvir u realnom vremenu (drži per-ID gap/step stanje).
- **`stream.py`** — `run_sim(..., ids_method=...)`; `/ws/stream` prima `ids=<method>`;
  komanda `{"cmd":"inject","attack":"DoS|Fuzzy|gear|RPM"}` ubacuje napad na trenutnu poziciju.
  DoS = burst od 8 okvira (2ms), ostali = 1 okvir. Payload-i su PRAVI outlieri iz 3 manifesta.
- **Frontend `SimulatorPage.jsx`** — IDS selektor (off/heuristic/IF/SVM), 4 "inject" dugmeta,
  ubrizgani okviri crveno, blokirani idu u **karantin** sa kolonom "Detect (ms)".

### Latency / brzina (mereno — 09.2026)
Ključni problem koji se pojavio u live prikazu (i koren "bagovanja"):

- **Isolation Forest je bio katastrofalno spor kad se zove per-frame:** ~23.5 ms/okvir
  (42 okvira/s, a magistrala ~1950/s). Uzrok: `decision_function` preko 300 zasebnih
  stabala ima ogroman fiksni overhead PO POZIVU kad se zove za jedan okvir.
- **Popravka:** `check_batch()` skoruje ceo batch (200 okvira) u JEDNOM vektorizovanom
  pozivu → IF pada na ~0.055 ms/okvir (18k okvira/s), SVM ~0.066 ms/okvir, heuristika
  ~0.024 ms/okvir. Rezultati IDENTIČNI (0/200 nepoklapanja block odluka).

**Izmerena latencija po okviru (batched):**

| Metoda | µs/okvir | okvira/s |
|--------|---------|----------|
| Heuristic       | ~24   | ~42 000 |
| Isolation Forest| ~55   | ~18 000 |
| One-Class SVM   | ~66   | ~15 000 |

**End-to-end "klik → karantin" (inject DoS, 8/8 uhvaćeno, preko WebSocket-a):**
heuristic ~5ms, one-class svm ~15ms, isolation forest ~57ms (dominantna je ~50ms
tick playback petlje, ne samo skorovanje).

### Propusnost vs. realna CAN magistrala (da li IDS može da isprati live?)
Pitanje za rad: da li naš IDS teoretski može da isprati SVE poruke u skoro-realtime?

**Naš dataset:** ~988 000 poruka / ~506 s ≈ **~1950 poruka/s** (normal.csv).

**Realne CAN magistrale (redovi veličine):**
- **500 kbit/s** (drivetrain) — max ~3500–5000 msg/s, realno **~1500–3000 msg/s** pri vožnji.
- **250 kbit/s** (comfort/infotainment) — **~1000–2000 msg/s**.
- **Diagnostics** (OBD) — **~10–100 msg/s** (request/response, skoro prazno).

**Polo 6R (2009, 1.6 TDI) — konkretno vozilo iz handoff-a:**
- Tačan broj msg/s po magistrali NIJE javno dokumentovan (zavisi od ECU-ova/opreme);
  koristimo tipične raspone gore.
- **Važno (već poznato):** OBD-II port (pin 6/14) NE daje pravi saobraćaj — ide na CAN
  Gateway i pokazuje samo dijagnostiku (request `0x100`/response `0x200`), pa je
  diagnostics saobraćaj zanemarljiv; drivetrain i comfort nose pravi saobraćaj.

**Margina našeg IDS-a nad najopterećenijom magistralom (drivetrain ~3000 msg/s):**

| Metoda | Naš protok | Margina (drivetrain) | Margina (comfort ~500/s) |
|--------|-----------|----------------------|--------------------------|
| Heuristic       | 42 000 msg/s | ~14× | ~84× |
| Isolation Forest| 18 000 msg/s | ~6×  | ~36× |
| One-Class SVM   | 15 000 msg/s | ~5×  | ~30× |

**Zaključak:** DA — čak i najsporija metoda (SVM, ~15k msg/s) ima ~5× marginu nad
najopterećenijom magistralom. Uz disclaimer: brojke su za **čisti Python na desktopu**;
na ESP32 (live hardver) model bi morao da se kvantizuje/pojednostavi — to je druga faza.
Iskreno formulisanje za rad: "tipičan raspon 1500–3000 msg/s za drivetrain, tačna vrednost
zavisi od konfiguracije vozila".

### Otvorena pitanja pre nastavka
1. Payload — app pokazuje sirove hex + statističke šablone; fizičko značenje (brzina/RPM...)
   tumačimo ručno / uz pomoć.
2. Simulator — da li simulira svaki tip zasebno ili mešavinu.
3. Live mod — potvrditi na koji interface (serial→socketcan) se naslanjamo.

---

## 8. Praktični deo — pristup magistrali (live fazu)

### Ključno saznanje o VW Polo 6R
- **OBD2 port (pin 6/14) NE daje pravi CAN saobraćaj** — vezan je na **CAN Gateway (J533)**;
  prikazuje samo dijagnostiku (request ID `0x100`, response `0x200`). RPM preko OBD2/Bluetooth
  je dijagnostika (PID request), ne pasivno slušanje magistrale — nedovoljno za IDS.
- **Pravi pristup magistrali:** instrument tabla (cluster) preko 32-pin konektora (T32),
  ili preko BCM (J519).
- **Comfort CAN** za zaključavanje/prozore/brisače ide kroz BCM (J519), konektor **T73b: pin 20 = CAN-H, pin 21 = CAN-L**.
- Cluster T32 CAN pinout — **dve verzije u izvorima, NE slagati nasumično**:
  - portal-diagnostov: drivetrain pin 7/8, comfort pin 9/10
  - Hackaday: pin 28/29
  - drive2.ru: drivetrain 19/20, comfort 8/9
  - → **potrebna provera multimetrom** na konkretnom vozilu; greška može da ošteti ESP32.
- Ostali priključci: CAN Gateway (J533), ABS/ESP modul, ECU, comfort (vrata/B-pillar).

### Mišljenje o fizičkom pristupu (za diplomski)
- **Cluster T32 pin 28/29 (kanali) najzad svakako najbezbednije za drivetrain** (za IDS: RPM/brzina),
  a **BCM T73b 20/21** za Comfort.
- **NE izvlačiti BCM** prilikom testa — Comfort sistemi zavise od njega; test se radi paralelnim priključivanjem (ti samo slušaš/šalješ, on ostaje u funkciji).
- **Bezbedni testovi na Comfort CAN:** samo informativni/prikazni ID-ovi; **NE dirati** realno zaključavanje, stakla koja se pomjeraju, brisače ni bilo šta mehanički opasno bez pažljivog testa (mogu da zaključaju ključeve unutra / oštete mehanizam).
- Terminacioni otpornik 120Ω: **NE treba na autu** (magistrala je fabrički terminirana); treba **samo na bench testu** bez vozila.

### Rigor
Ovde je bitan disclaimer: zvanične VAG šeme (Erwin/ELSA) su per-VIN + plaćene; online izvori pinouta se ne slažu (više verzija T32), pa je **obavezna potvrda na konkretnom vozilu multimetrom** (CAN ~2.5V idle, oscilacije tokom rada) pre spajanja.

