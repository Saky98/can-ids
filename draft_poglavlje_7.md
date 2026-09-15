# 7. Zaključak

## 7.1. Rezime rada

U ovom radu analizirane su bezbednosne slabosti CAN protokola i razvijen sistem za detekciju upada (IDS) koji prati CAN saobraćaj, prepoznaje anomalije i upozorava na sumnjive aktivnosti. Polazna tačka bila je uvid da CAN, kao protokol nastao u vremenu kada su vozila bila izolovani sistemi, ne poseduje ugrađene mehanizme autentifikacije pošiljaoca ni enkripcije podataka, zbog čega je svaka jedinica priključena na magistralu potencijalni vektor napada.

Kao odgovor na ovaj problem, projektovane su i implementirane tri komplementarne metode za detekciju anomalija: heuristički (statistički) detektor zasnovan na eksplicitnim pravilima, Isolation Forest i One-Class SVM kao dve nenadgledane metode mašinskog učenja. Sve tri metode obučavane su isključivo na čistom normalnom saobraćaju, uz strogu hronološku podelu podataka koja isključuje curenje informacija između faze obuke i faze evaluacije. Detekcija se zasniva na tri izdvojena obeležja svake poruke: identifikatoru, vremenskim razmacima između poruka i sadržaju payload-a. Rešenje je zaokruženo pratećom web aplikacijom sa Simulatorom koji omogućava reprodukciju saobraćaja, izbor detektora i ubrizgavanje napada u realnom vremenu, uz karantin za evidentiranje blokiranih poruka.

Evaluacija je sprovedena na javno dostupnom Car-Hacking skupu podataka, uz tri komplementarne mere: stopu lažnih pozitiva na čistom saobraćaju, pokrivenost celih napadnih snimaka i — kao najstrožu meru — stopu detekcije ubrizganih napada na punom normalnom toku od približno 990 hiljada okvira.

## 7.2. Odgovor na istraživačko pitanje

Istraživačko pitanje postavljeno na početku rada glasilo je da li se jednostavan i objašnjiv IDS može koristiti za pouzdanu detekciju anomalija u CAN komunikaciji, uz dovoljno malu latenciju za potencijalnu primenu u automobilskim sistemima.

Dobijeni rezultati daju potvrdan odgovor. Heuristički detektor je na interleaved testu prepoznao sve ubrizgane napade — DoS, Fuzzy, gear i RPM — sa stopom detekcije od 100 %, bez ijednog lažnog pozitiva na čistom saobraćaju, uz vreme obrade od približno 37 mikrosekundi po okviru. U odnosu na gornju granicu opterećenja najprometnije magistrale (oko 3 000 poruka u sekundi), to predstavlja marginu od približno 14 puta. Time je pokazano da jednostavno i transparentno rešenje može da zadovolji i zahtev pouzdanosti i zahtev realnog vremena.

## 7.3. Poređenje metoda i doprinos

Poređenje tri metode otkriva jasan kompromis između tačnosti, brzine i objašnjivosti. Heuristički detektor je u ovom eksperimentu ostvario najbolje rezultate po svim merenim parametrima: najvišu stopu detekcije, nultu stopu lažnih pozitiva i najmanju latenciju, uz dodatnu prednost što se svaka njegova odluka može neposredno objasniti prekršenim pravilom.

Mašinski naučene metode — Isolation Forest i One-Class SVM — pokazale su slabiju stopu detekcije, posebno kod spoofing napada (gear i RPM), kod kojih se suptilna izmena sadržaja pojedinačnih poruka postojećih identifikatora teže odvaja od prirodne varijabilnosti. Njihova vrednost, međutim, nije isključivo u tačnosti: kao nenadgledane metode one poseduju potencijal da prepoznaju i nepredviđene anomalije koje se ne uklapaju ni u jedno unapred definisano pravilo. Uočeni lažni pozitivi ovih metoda potiču od jednog identifikatora sa inherentno širokim rasponom signala, što zorno ilustruje osnovni trade-off: čvršća granica detekcije donosi veću osetljivost, ali i veći rizik od lažnih uzbuna.

Glavni doprinos rada stoga nije samo pojedinačna metoda, već celovit okvir koji omogućava pošteno poređenje pristupa različite složenosti nad istim podacima i istom metrikom, kao i praktična demonstracija da se detekcija upada može sprovesti uz zanemarljiv broj lažnih pozitiva i latenciju dovoljnu za primenu u realnom vremenu.

## 7.4. Ograničenja

Dobijene rezultate treba tumačiti uz nekoliko ograničenja. Evaluacija je sprovedena na jednom, javno dostupnom skupu podataka snimljenom na konkretnom vozilu, pa se generalizacija na druga vozila i drugačije topologije mreže mora uzeti sa rezervom. Ubrizgane poruke u testnom okruženju birane su tako da budu statistički izrazita odstupanja, zbog čega stopa detekcije može biti nešto niža u susretu sa suptilnijim, prikrivenim napadima. Konačno, izmerene vrednosti latencije odnose se na čist Python na radnoj stanici; u hardverskoj implementaciji na mikrokontroleru model bi bilo potrebno kvantizovati ili pojednostaviti.

## 7.5. Budući rad

Rezultati otvaraju nekoliko prirodnih pravaca za nastavak. Prvi je prelazak na live prikupljanje saobraćaja sa stvarnog vozila, čime bi se sistem evaluirao na autentičnom, a ne snimljenom saobraćaju. Drugi je kvantizacija i pojednostavljenje modela radi implementacije na ugrađenom hardveru, čime bi se detekcija približila samoj magistrali. Treći pravac je dekodovanje signala putem DBC baza, čime bi se od detekcije na nivou sirovih bajtova prešlo na semantički svesnu detekciju. Konačno, hibridni pristup koji kombinuje brzi heuristički detektor kao prvi sloj sa metodom mašinskog učenja kao drugim, potvrdnim slojem, predstavlja obećavajuću sintezu brzine i sposobnosti generalizacije.
