# 📚 Reference / Literatura

> Ovde čuvamo izvore (linkovi, radovi, dokumentacija) koje koristimo tokom diplomskog rada —
> **"Analiza i implementacija IDS za zaštitu CAN komunikacije u automobilskim informacionim sistemima"**.
> Svaka referenca se dodaje u hronološkom poretku; dodaj i kratak opis zašto je korisna.

---

## 1. Dataset i izvori podataka

### Car-Hacking Dataset (Kaggle) — **glavni dataset za rad**
- **Link:** https://www.kaggle.com/datasets/pranavjha24/car-hacking-dataset
- **Šta je:** javni CAN bus dataset sa realnog vozila; sadrži CSV fajlove:
  - `normal` (benign/attack-free saobraćaj)
  - `attack_DoS`, `attack_Fuzzy`, `attack_spoofing`, `attack_replay`
- **Zašto koristimo:** glavni izvor za trening i testiranje IDS-a. Fajlovi su raspakovani lokalno u `dataset /archive/` folderu.
- **Objašnjenje kolona:** `Timestamp, CAN_ID, DLC, D0..D7, R` (bez zaglavlja); `normal_run_data.txt` ima CanLogger format (`Timestamp: ...  ID: ...  DLC: ...  payload`).

### Zvanični izvor — HCRL Car-Hacking Dataset (autori: Seo et al.)
- **Link:** https://ocslab.hksecurity.net/Datasets/car-hacking-dataset
- **Šta je:** originalna stranica akademskog dataset-a (Hanyang University / HCRL).
- **Zašto koristimo:** za citiranje u radu (primarni izvor), referenca na originalni rad.

### GitHub mirror / release
- **Link (release):** https://github.com/Rrai997/CAN_Bus_IDS/releases/tag/IDS_Dataset
- **Direktan download:** https://github.com/Rrai997/CAN_Bus_IDS/releases/download/IDS_Dataset/Merged_Dataset.zip
- **Zašto koristimo:** alternativa kada je potreban direktan download bez prijave.

---

## 2. Dokumentacija — CAN frejm i zaglavlja (generički protokolski nivo)

### Bosch CAN 2.0 specifikacija (osnovni standard frejma)
- **CAN 2.0 specifikacija:** https://www.bosch-semiconductors.com/media/ubk_semiconductors/pdf_1/canliteratur/can2spec.pdf
- **Šta je:** zvanični doc koji definiše CAN frejm (2.0A standardni 11-bit, 2.0B prošireni 29-bit), polja, DLC, kontrolno polje. Osnovna teorijska literatura za rad.

### ESP32 TWAI (CAN) drajver — ESP-IDF dokumentacija
- **Link:** https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/twai.html
- **Šta je:** zvanična ESP-IDF dokumentacija TWAI periferije; korelisana sa CAN/ISO 11898-1. Pryručno za praktični deo (ESP32). Navodi standardne okvire 11-bit ID i DLC [0:8].

### can2.0 / MCP2515 (transiver) — Microchip datasheet
- **Link:** https://pdf.ttic.cc/pdfdet/MCP2515-ESO_520624_520620_7.html
- **Šta je:** datasheet koji opisuje arbitraciono polje (12 bita: 11-bit ID + RTR), kontrolno polje (IDE + DLC), CRC, ACK. Korisno za razumevanje frejma.

### CAN frejm (NI-CAN dokumentacija, pregledna)
- **Link:** https://documentation.help/NI-CAN/CAN_Frames.html
- **Šta je:** kratak pregled dve vrste frejma (standard + extended), 11 vs 29 bit ID.

### DBC format i CAN baze (opcija za dekodovanje signala)
- **Link (awesome-canbus / CanDB):** https://github.com/azalea-dtt/awesome-canbus
- **Šta je:** linkbiblioteka CAN alata/baza; `CanDB`, `can_decoder` za pretvaranje sirovih CAN podataka u fizičke vrednosti pomoću DBC fajlova.

---

## 3. VW Polo CAN — specifični ID-ovi, komande, reverse engineering

### ⚠️ VAŽNO — OBD2 port na Polo 6R ide na CAN Gateway, ne direktno na magistralu
- **Link (detalji):** https://hackaday.io/project/6288/logs?page=4&sort=oldest
- **Šta je:** korisnik utvrdio da se preko OBD2 porta u Polo 6R NE vidi direktni CAN saobraćaj. OBD2 je vezan na **CAN Gateway (J533)**: dijagnostički adapter šalje ID `0x100`, Gateway odgovara `0x200`. Ovo znači da pini 6/14 daju **dijagnostičku** komunikaciju (UDS), a ne sve poruke na komandnoj magistrali — bitno za tvoj praktični plan (snimanje kroz OBD2 port).
- **Dodatak:** http://test.hackaday.io/project/6288/... (isti izvor, diskusija).

### Polo 6R / 6C CAN baza (zajednička, forum)
- **Link:** https://www.uk-polos.net/viewtopic.php?p=591157
- **Šta je:** recenzija baze za CAN poruke 6C ukljjučujući Polo (forum, ELM327 datoteke dekodovanja). Korisno kao polazna tačka za dekodovanje ID-a.

### CAN Gateway (J533) adrese / Label fajlovi — Ross-Tech (VCDS)
- **Link:** https://forums.ross-tech.com/index.php?threads/2861/
- **Šta je:** informacije o CAN Gateway-u Polo 6R (`6R0907530B` / `7N0907530D`), label fajlovi. Korisno za razumevanje gateway-a.

### Open Vehicle Control System — VW Polo reverse engineering (podcast/članak)
- **Link (snipd/članak):** https://share.snipd.com/chapter/816f8416-cab8-44b4-8629-eaf6210e30e1
- **Šta je:** opis reverse engineering-a CAN poruka na VW Polu (2007+), Open Vehicle Control System. Korisno jer dijele iskustvo i upozorenje da se pre modifikacija obavi kompletan CAN dump.

---

## 4. Akademski radovi (ideja za literaturu)

> *Sekcija za dodavanje — rad vezan za IDS, CAN bezbednost, mašinsko učenje u automobilskom kontekstu.*
