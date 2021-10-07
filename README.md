# Dokumentaatio RuuviTag projektia varten 


### Tarvittavat komponentit 
Raspberry Pi 4 (16 Gt versio), Raspberry Pi touch Display, RuuviTag 

### Ei välttämättömät tarvikkeet 
Näppäimistö, Hiiri, Näyttö 

### Projektissa käytettävät ohjelmistot 
Debian käyttöliittymä Raspberrylle, Node-Red, InfluxDB, Grafana 

## Valmistelut projektia varten ennen aloitusta 

Varmista että sinulla on valmiiksi asennettu Raspberry Pi 4 Debian käyttöjärjestelmällä ja saat jollain tavalla otettua etäyhteyden Raspberryn. Voit myös koota ja asentaa Touch Displayn valmiiksi. 

## RuuviTag 

RuuviTag on Suomalaisen Ruuvi startup yrityksen tuotos, joka mittaa ilman lämpötilaa, ilmankosteutta, ilmanpainetta ja liikettä. Pro mallilla käyttää tarkempia antureita. Laite lähettää päällä ollessaan BlueTooth yhteydellä JSON muodossa olevaa data vastaanottaville laitteille, joka on tässä tapauksessa Raspberry Pi. Huomattavaa on että 2021 vuoden malleista puuttuu ilmanpaine sensorit, meneillään olevan/olleen piiripulan vuoksi. 

## Node-Red 

Ensimmäinen vaihe projektin tekoon on asentaa Node-Red ohjelmisto. Node-Red on visuaalinen ohjelmointi kieli, joka toimii osana Node.Js ympäristöä. Alla olevasta linkistä löydät ohjeet Node-Red asentamiseen uudelle Raspberry Pi Debian käyttöjärjestelmälle: 

https://nodered.org/docs/getting-started/raspberrypi 

Nyt kun Node-Red on käyttövalmis, voit avata sen käyttöliittymän kirjoittamalla Raspberry Pi:n IP-osoitteen nettiselaimen osoitepalkkiin. Jos käytät samaa Raspberry Pi:llä, jolle asensit node-red pääset käsiksi siihen osoitteella http://localhost:1880. Jos asensit node-red toiselle Raspberry Pi:lle löydät sen IP-osoitteen kysymällä hostname -I komennolla Raspberry Pi:n komentorivillä. Saatuasi IP osoite, lisää sen perään :1880 päästäksesi oikeasta portista node-red graafiseen käyttöjärjestelmään (esim. http://10.10.10.10:1880). 

## InfluxDB 

Toinen vaihe projektissa on asentaa influxDB, johon tallennamme datan, joka tulee RuuviTag:stä. InfluxDB asentamisen löydät alla olevasta linkistä: 

https://pimylifeup.com/raspberry-pi-influxdb/ 

Muistathan pistää tietokannan nimen muistiin seuraavaa vaihetta varten (käytän esimerkkinä ohjeistuksessa RuuviTagM). Jos teet projektia omaan käyttöön etkä odota, että kukaan pääsee käsiksi verkkoosi, ei ole tarvittavaa asettaa käyttäjä tunnuksia tai salasanaa tietokannalle. Jos taas otat yhteyttä muualta tai IP-osoitteesi saa yhteyden ulkoapäin on suositeltavaa pitää tietokanta käyttäjän ja salasanan takana. 

## Grafana 

Viimeisenä päätteenä projektissa on Saada data näytettyä hienosti Touch Displaylle, jota voi tarkastella joko livenä näytöltä tai VNC avulla etänä. Jos olet jo asentanut Raspberry Pi Touch Display:n voit hypätä seuraavaan osion yli. 

Touch Display:n asentamisen aikana, on suositeltavaa sulkea Raspberry Pi kokonaan, jottei komponenteille satu virtapiikkejä tai oikosulkuja. Jos ruuvaat Raspberry Pi:n suoraa Touch Display:n kiinni, kannattaa se tehdä ensimmäisenä, jottei tarvitse johtoja asennella moneen kertaan. 

Touch Display:stä lähtevä DSI johto tulee laittaa Raspberry Pi:ssä microSD kortin toisella puolella olevaan DSI kiinnitykseen. Asenna GPIO pinnit Raspberry Pi:hin siten että punainen johto, eli 5v virta, tulee joko pinniin 2 tai 4, musta johto, eli Ground johto, tulee pinniin 6 ja keltainen (SDA) ja vihreä (SCL) johdot tulevat pinneihin 3 (SDA) ja 5 (SCL). Keltainen ja Vihreä johto voivat olla väreiltään vaihtelevat erien Touch Display mallien välillä.  

Asennus ohjeet löytyvät alla olevasta linkistä: 

https://grafana.com/grafana/download/7.5.10?platform=arm 

Käytämme ohjeistuksessa 7.5.10 ARM versiota Grafanasta. Kun olet asentanut Grafanan, seuraavilla komennoilla saamme sen automaatiisesti käynnistymään aina kun Raspberry Pi käynnistyy uudelleen.  
```
$ sudo /bin/systemctl daemon-reload 
$ sudo /bin/systemctl enable grafana-server 
$ sudo /bin/systemctl start grafana-server 
$ sudo /bin/systemctl status grafana-server 
```
Voit nyt kirjautua Grafana serverille menemällä nettiselaimessa osoitteeseen localhost:3000 tai aiemmin saamaasi ”hostname -I” IP-osoitteeseen käyttäen portin numeroa 3000. Oletus tunnukset ensimmäisellä kirjautumisella ovat admin/admin. 

Yhdistäminen kaikkien välille. 

Tässä osuudessa käymme läpi, miten saamme RuuviTag:stä lähtevän JSON tiedon Raspberry Pi:n näytölle. Aluksi laitamme Node-Red osuuden toimintaan, että saamme RuuviTag:ltä JSON laitettua InfluxDB:lle. Ota yhteys IP-osoitteeseen 1880 portilla (http://localhost:1880 tai toimiva IP-osoite). Rakennamme alla olevan kuvan näköisen koodin. 

Ensimmäisenä menemme Manage Palette oikeasta yläkulmasta ja asennamme seuraavat paketit: node-red-contrib-noble, node-red-contrib-ruuvitag ja node-red-contrib-influxDB. Flow kulku on seuraavanlainen, joku 1 min välein BlueTooth skannaa RuuvitTag-tagillä olevan BlueTooth yhteyttä ja lukee sen antamaa JSON viestiä. Viesti muuntuu payloadiksi ja jakaantuu funktiossa neljään eri osaan, joka sitten lähetetään influxdb out moduulilla annetuun IP-osoitteeseen portin 8086 kautta. Eri viestit lähetetään niille annettuihin Measurement osioihin (temperature, humidity tai pressure). 

Funktio menee seuraavanlaisesti: 
```
let measure = JSON.parse(msg.payload); 

let msg0 = {}; 
msg0.payload = (measure.temperature).toFixed(2) 
msg0.topic = "Temperature"; 

let msg1 = {}; 
msg1.payload = measure.humidity; 
msg1.topic = "Humidity"; 

let msg2 = {}; 
msg2.payload = (measure.pressure/100).toFixed(2); 
// node.warn(msg2.payload) 
msg2.topic = "Pressure"; 

let msg3 = {}; 
msg3.payload = measure.battery/1000 
msg3.topic = "Battery"; 

let msg4 = {}; 
msg4.payload = measure.txPower 
msg4.topic = "TxPower"; 

let msg5 = {}; 
msg5.payload = measure.movementCounter 
msg5.topic = "Movement Counter"; 

return [msg0, msg1, msg2, msg3, msg4, msg5]; 
```
Kun käynnistät et ole varma toimiiko koodi, ota esille debug sivupalikasta. Mikäli et saa mitään viestejä ei koodi pyöri. Joitain ratkaisuita on ohjelman uudelleen käynnistäminen ”Deploy” napista tai esimerkiksi tehdä muutos koodiin ja sitten kokeilla käynnistää koodi uudelleen ”Deploy” napilla. 

Kun saat kaiken toimimaan oikein, voit mennä katsomaan Raspberry Pi:n komentoriviltä sisälle menneet datat. Komennolla influx aukaiset influxDB komentorivin ja komennolla use RuuviTagM pääset sisälle tehtyyn tietokantaan. Voit tarkastella dataa komennolla SELECT * FROM Temperature. Komentorivi tulostaa iso kasan rivejä, joissa on aikaleima ja haettu lukuarvo. 

Viimeisenä haemme Grafana:lla tallennetut tiedot influx tietokannasta. Kuten Node-Red, pääset Grafana:n käyttöliittymään menemällä selaimeen ja kirjoittamalla IP-osoitteen portilla 3000 (esim. http://localhost:3000).  

Lämpö tilannetiedot saat esille tekemällä uuden paneelin, lisäämällä uusi InfluxDB tietolähde RuuviTagM tietokannasta. Mene Asetuksiin (Settings) ja Tietolähde (Data Sources), siellä lisäät InfluxDB lähteen. Nimeä lähde mieleisellä tavalla, esimerkiksi RuuviTagM, nimellä ei ole väliä, kunhan muistat mikä se on. URL kohtaan lisäät localhost:8086, sillä InfluxDB ja Grafana ovat samalla koneella päällä. Database kohtaan tulee tietokannan nimi (esimerkkitapauksessa RuuviTagM). http Method kohtaan laitetaan GET. Tämän jälkeen laita Save & Test, tämä sekä tallentaa tiedot että testaa saako Grafana tietoa tuotua tietokannasta. Mikäli kaikki on OK, siirrytään lisäämään uusi paneeli. Jos Query kohdassa ei ole mitään, lisää siihen tehty Tietolähde (RuuviTagM). Sen alapuolelta löytyy Query parametrit, vaihda kysely tekstipohjaiseksi ja kirjoita siihen SELECT * FROM Temperature. Tämän jälkeen tee vielä paneelit Pressure ja Humidity arvoille. Humidity arvoon voit myös lisätä Left Y kohtaan minimi Y arvolle 0, kun kosteusarvo ei voi koskaan mennä alle nollan.  

## Puutteet ja Bugit 

Näillä ohjeistuksilla pitäisi sinulla olla nyt kirjautumisen alla oleva Ruudullinen Raspberry Pi. Päivittämällä nettiselaimen näet päivitetyt tilannetiedot. Paranneltavaa projektissa olisi vielä live päivitykset Grafana:n käyttöliittymässä, jottei tarvitse aina päivittää nettiselainta uuden tilannetiedon saamiseksi. Toinen paranneltava projektissa on saada avattua nettiväylä, josta saisit ilman kirjautumista nähtyä tilannetiedot mistä tahansa internet yhteydestä. Tämänhetkinen pääsy tilannetietoihin on kirjautumisen päässä ja toimii vain saman paikallisen verkon sisältä. 

Ainoa oikea bugi mihin on tullut törmättyä projektissa, on Mode-Red kanssa. Node-Red joskus harvakseltaan lopettaa koodin pyörittämisen. Syynä voi olla Raspberry Pi:n kiinni käyminen tai mahdollisesti lepotilaan menemisestä johtuva epäaktiivisuus. 

Viitteet: 

https://nodered.org/docs/getting-started/raspberrypi 
Node-Red asentaminen uudelle Raspberry Pi:lle. 

https://lab.ruuvi.com/node-red/ 
RuuviTag oma sivusto node-red varten. 

https://ruuvi.com/setting-up-raspberry-pi-as-a-ruuvi-gateway/ 
Grafanan yhdistäminen influxDB:hen. 

 
