# 6. Rezultati i evaluacija

U ovom poglavlju prikazani su i analizirani rezultati evaluacije tri implementirane metode detekcije — heurističkog detektora, Isolation Forest-a i One-Class SVM-a. Svi rezultati dobijeni su ponovljivim postupkom opisanim u poglavlju 5.5 i mogu se reprodukovati pokretanjem jedinstvene skripte za evaluaciju. Evaluacija je sprovedena na Car-Hacking skupu podataka, pri čemu su metode obučene isključivo na čistom normalnom saobraćaju, a zatim testirane na (1) čistom neviđenom normalnom saobraćaju radi merenja stope lažnih pozitiva, (2) celim napadnim snimcima radi mere pokrivenosti i (3) realističnim ubrizgavanjem pojedinačnih napada u pun normalan tok radi mere stvarne osetljivosti.

## 6.1. Metodologija evaluacije

Metodologija evaluacije zasnovana je na principu da se model normalnog ponašanja gradi isključivo na čistom saobraćaju, dok se napadni podaci koriste isključivo za testiranje. Time se isključuje curenje informacija (engl. *data leakage*) između faze obuke i faze evaluacije, a dobijeni rezultati odražavaju stvarnu sposobnost detektora da prepozna neviđene anomalije.

Normalni saobraćaj podeljen je hronološki na tri disjunktna segmenta: segment za obuku (TRAIN), segment za validaciju (VALID) i segment za testiranje (TEST). Hronološka podela, umesto slučajnog mešanja, obezbeđuje da se validacija i testiranje vrše na podacima koje model nije video ni po vremenskom redosledu, čime se dodatno sprečava curenje informacija koje bi nastalo usled periodične prirode CAN saobraćaja. Veličine segmenata prikazane su u tabeli 6.1.

| Segment | Broj okvira |
| ------- | ----------- |
| TRAIN (obuka) | 692 209 |
| VALID (validacija) | 148 331 |
| TEST (testiranje) | 148 331 |

*Tabela 6.1 — Hronološka podela normalnog saobraćaja (no-leak).*

Segment za validaciju koristi se za kalibraciju pragova detektora (na primer, izbor kontaminacionog parametra kod Isolation Forest-a i One-Class SVM-a), dok se segment za testiranje koristi za konačno, nezavisno merenje stope lažnih pozitiva. Ovakva trostruka podela omogućava da se parametri podešavaju bez rizika od precenjivanja performansi na podacima korišćenim za podešavanje.

U evaluaciji se koriste četiri komplementarne mere:

* **Stopa lažnih pozitiva (FPR)** — udeo čistih poruka koje detektor pogrešno proglasi anomalnim. U automobilskom kontekstu lažni pozitivi su posebno problematični jer mogu dovesti do nepotrebnih blokada legitimnog saobraćaja i narušiti poverenje korisnika u sistem.
* **Mera pokrivenosti** — udeo okvira u celom napadnom snimku koje detektor proglasi anomalnim. Ova mera opisana je u poglavlju 5.5.1 kao previše optimistična, ali je zadržana radi celovitosti i poređenja sa postojećom literaturom.
* **Stopa detekcije ubrizganih napada** — udeo stvarno ubrizganih zlonamernih poruka koje detektor prepozna, merena na interleaved testu opisanom u poglavlju 5.5. Ovo je najstrožija i najrelevantnija mera osetljivosti.
* **Vremenska efikasnost** — vreme potrebno za obradu jednog okvira, izraženo u mikrosekundama po okviru, koje je ključno za primenljivost u realnom vremenu.

Sve tri metode ocenjuju svaki okvir pojedinačno (per-frame), na identičan način kao u živom Simulatoru opisanom u poglavlju 5.6.2, čime se osigurava da su evaluacioni rezultati direktno uporedivi sa ponašanjem sistema u realnom vremenu.

## 6.2. Stopa lažnih pozitiva

Prvi uslov koji svaki IDS u automobilskom okruženju mora da ispuni jeste da ne stvara lažne uzbune na čistom saobraćaju. Rezultati merenja stope lažnih pozitiva na validacionom i testnom segmentu prikazani su u tabeli 6.2.

| Metoda | VALID (označeno/okvira) | TEST-normal (označeno/okvira) |
| ------ | ----------------------- | ----------------------------- |
| Heuristički detektor | 0 / 148 331 (0,00 %) | 0 / 148 331 (0,00 %) |
| Isolation Forest | 0 / 148 331 (0,00 %) | 2 / 148 331 (0,001 %) |
| One-Class SVM | 0 / 148 331 (0,00 %) | 2 / 148 331 (0,001 %) |

*Tabela 6.2 — Stopa lažnih pozitiva na čistom normalnom saobraćaju.*

Rezultati pokazuju da su sve tri metode praktično bez lažnih pozitiva na čistom saobraćaju. Heuristički detektor nije proizveo nijedan lažni pozitiv, što je očekivano s obzirom na konzervativnu prirodu njegovih eksplicitnih pravila, čiji se pragovi uče direktno iz opsega vrednosti i perioda prisutnih u TRAIN segmentu. Isolation Forest i One-Class SVM označili su po dva okvira od ukupno 148 331 na testnom segmentu, što odgovara stopi od približno 0,001 % — vrednost zanemarljiva u praksi i daleko ispod nivoa koji bi izazvao operativne probleme.

Ovakav rezultat potvrđuje da je cilj postavljen tokom dizajna — stopa lažnih pozitiva blizu nule — ostvaren za sve tri metode, što je preduslov za pouzdanu primenu u automobilskim sistemima gde svaka nepotrebna blokada može imati funkcionalne posledice.

## 6.3. Mera pokrivenosti nad celim napadnim snimcima

Druga mera evaluacije jeste pokrivenost celih napadnih fajlova, odnosno udeo okvira u zasićenim napadnim snimcima koje detektor obeleži kao anomalne. Rezultati su prikazani u tabeli 6.3.

| Napad | Heuristički detektor | Isolation Forest | One-Class SVM |
| ----- | -------------------- | ---------------- | ------------- |
| DoS | 28,50 % | 16,82 % | 36,02 % |
| Fuzzy | 29,43 % | 16,80 % | 36,60 % |
| gear | 32,62 % | 15,32 % | 30,96 % |
| RPM | 28,46 % | 14,62 % | 25,89 % |

*Tabela 6.3 — Pokrivenost celih napadnih fajlova (per-frame).*

Kao što je objašnjeno u poglavlju 5.5.1, vrednosti u tabeli 6.3 ne treba tumačiti kao konačnu meru uspešnosti detekcije. Napadni snimci su kontinuirano zasićeni — svaka poruka u snimku predstavlja napad — pa delimična pokrivenost od približno 15 % do 37 % zapravo znači da detektor od početka do kraja snimka neprekidno prepoznaje anomalije, ali ne mora da obeleži svaki pojedinačni okvir. Ova mera je stoga samo grubi pokazatelj da nijedan tip napada ne prolazi nezapaženo, dok stvarnu osetljivost na pojedinačne pretnje precizno meri tek interleaved test opisan u nastavku.

## 6.4. Detekcija ubrizganih napada

Najstrožija i najrelevantnija mera jeste stopa detekcije na interleaved testu, u kojem se mali broj stvarno sumnjivih poruka ubrizga u pun normalan tok od približno 990 000 okvira, na mestima određenim kroz tri reproduktivna manifesta. Rezultati, iskazani kao prosek kroz tri manifesta, prikazani su u tabeli 6.4.

| Napad | Heuristički detektor | Isolation Forest | One-Class SVM |
| ----- | -------------------- | ---------------- | ------------- |
| DoS | 100,0 % (30/30) | 100,0 % (30/30) | 100,0 % (30/30) |
| Fuzzy | 100,0 % (300/300) | 89,3 % (268/300) | 96,7 % (290/300) |
| gear | 100,0 % (300/300) | 77,3 % (232/300) | 88,7 % (266/300) |
| RPM | 100,0 % (300/300) | 78,3 % (235/300) | 87,0 % (261/300) |

*Tabela 6.4 — Stopa detekcije ubrizganih napada na punom toku (interleaved, prosek kroz 3 manifesta).*

Rezultati otkrivaju jasnu i konzistentnu razliku među metodama. Heuristički detektor postigao je savršenu detekciju od 100 % na sva četiri tipa napada, prepoznavši svaki ubrizgani burst DoS-a i svaku pojedinačnu ubrizganu poruku Fuzzy, gear i RPM napada. Ovaj rezultat je očekivan, jer su ubrizgane poruke birane tako da budu statistički izraziti outlieri u odnosu na pravila koja heuristički detektor eksplicitno proverava — nepoznat identifikator, preterana gustina i odstupanje sadržaja.

One-Class SVM pokazao je nešto slabiju, ali i dalje visoku stopu detekcije: od 96,7 % za Fuzzy napad do 87,0 % za RPM napad. Isolation Forest postigao je najnižu stopu detekcije među tri metode, u rasponu od 100 % za DoS do 77,3 % za gear napad. Pad performansi kod ovih dveju mašinski naučenih metoda najizraženiji je upravo kod spoofing napada (gear i RPM), što je i očekivano: spoofing se manifestuje suptilnom izmenom sadržaja pojedinačnih poruka identifikatora koji su i inače prisutni u normalnom saobraćaju, pa je takvu anomaliju teže odvojiti od prirodne varijabilnosti nego očiglednu promenu gustine (DoS) ili potpuno novi identifikator (Fuzzy).

Doslednost rezultata kroz tri manifesta — pri čemu sva tri manifesta daju približno isti rezultat — potvrđuje da ostvarene vrednosti nisu posledica povoljnog slučajnog rasporeda ubrizgavanja, već stvarne osetljivosti detektora, kako je i predviđeno metodologijom iz poglavlja 5.5.3.

## 6.5. Vremenska efikasnost i latencija

Pored tačnosti, ključan zahtev za IDS u automobilskom okruženju jeste dovoljno mala latencija da bi detekcija bila moguća u realnom vremenu. Izmerena vremena skorovanja celog toka, zajedno sa prosečnim vremenom obrade po okviru, prikazana su u tabeli 6.5.

| Metoda | Vreme (s) | Skorovanih okvira | µs po okviru |
| ------ | --------- | ----------------- | ------------ |
| Heuristički detektor | 37,0 | 990 011 | 37,4 |
| Isolation Forest | 199,4 | 990 011 | 201,4 |
| One-Class SVM | 85,3 | 990 011 | 86,1 |

*Tabela 6.5 — Vremenska efikasnost skorovanja celog toka sa ubrizganim okvirima.*

Najbrža metoda je heuristički detektor sa približno 37 mikrosekundi po okviru, što je posledica jednostavnosti njegovih eksplicitnih pravila. One-Class SVM obrađuje okvir za približno 86 mikrosekundi, dok je Isolation Forest najsporiji sa približno 201 mikrosekundom po okviru, što odražava potrebu da svaki okvir prođe kroz više stabala ansambla.

Da bi se vremenske vrednosti stavile u kontekst, potrebno ih je uporediti sa stvarnim opterećenjem CAN magistrale. Najopterećenija magistrala (drivetrain) u tipičnoj vožnji emituje reda 1 500 do 3 000 poruka u sekundi. U odnosu na gornju granicu od 3 000 poruka u sekundi, heuristički detektor ima marginu od približno 14 puta, Isolation Forest približno 6 puta, a One-Class SVM približno 5 puta. To znači da čak i najsporija metoda może da obradi celokupan saobraćaj najprometnije magistrale uz višestruku rezervu vremena.

Važno je napomenuti da su navedena merenja dobijena u čistom Python okruženju na radnoj stanici, bez specifične optimizacije. U eventualnoj hardverskoj implementaciji na mikrokontroleru (na primer ESP32 u planiranoj live fazi) model bi bilo potrebno kvantizovati ili pojednostaviti, što je predmet budućeg rada. Rezultati ipak jasno pokazuju da sve tri metode zadovoljavaju osnovni vremenski zahtev za detekciju u realnom vremenu u softverskom okruženju.

## 6.6. Diskusija

Uporedna analiza tri metode otkriva jasan kompromis između tačnosti, brzine i objašnjivosti. Heuristički detektor ostvario je najbolje rezultate u svim dimenzijama: savršenu detekciju, nultu stopu lažnih pozitiva i najmanju latenciju. Njegova osnovna prednost leži u transparentnosti — svaka detekcija može se direktno objasniti konkretnim prekršenim pravilom, što je od velikog značaja u automobilskom kontekstu gde je poverenje u ispravnost odluke kritično. Ograničenje heurističkog pristupa jeste to što detektuje samo one anomalije koje su eksplicitno predviđene pravilima, pa je manje prilagodljiv sasvim novim vrstama napada koje se ne uklapaju u postojeće obrasce.

Mašinski naučene metode — Isolation Forest i One-Class SVM — nude prednost što mogu, barem u principu, da otkriju i nenaučene anomalije koje odstupaju od modela normalnog ponašanja na nepredviđene načine. Međutim, u ovom eksperimentu ostvarile su nižu stopu detekcije spoofing napada, jer suptilna izmena sadržaja pojedinačnih poruka postojećih identifikatora karakteristična za gear i RPM spoofing ne izlazi uvek dovoljno izvan naučenog modela normalnog ponašanja. Osim toga, njihove odluke su teže objašnjive, a podela na više stabala (Isolation Forest) nosi i veću računsku cenu.

U pogledu zadovoljenja istraživačkog pitanja, rezultati potvrđuju da je jednostavan i objašnjiv IDS — heuristički detektor — sposoban da pouzdano detektuje sve četiri testirane vrste napada, uz dovoljno malu latenciju za primenu u realnom vremenu. Složenije nenadgledane metode predstavljaju vrednu dopunu za detekciju novih, nepredviđenih anomalija, ali u ovom eksperimentu nisu nužno nadmašile jednostavnije rešenje po tačnosti.

Ograničenja evaluacije treba imati u vidu. Rezultati su dobijeni na jednom, javno dostupnom skupu podataka snimljenom na konkretnom vozilu, pa se generalizacija na druga vozila i druge topologije mora uzeti sa rezervom. Takođe, ubrizgavanja u manifestima konstruisana su tako da budu statistički izrazita, pa stopa detekcije može biti nešto niža u susretu sa suptilnijim, prikrivenim napadima. Ova ograničenja predstavljaju prirodan prostor za buduća poboljšanja, o kojima će biti reči u zaključku.
