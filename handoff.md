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
- Početak `backend/main.py` (FastAPI) — na skici; treba doraditi API za analizu + simulator stream.

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

