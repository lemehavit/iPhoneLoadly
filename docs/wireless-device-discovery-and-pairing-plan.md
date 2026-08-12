# Plan: automatisk iPhone-upptäckt och trådlös parkoppling

## Beslut i korthet

Arbetet delas i två separata produktfunktioner:

1. **Automatisk upptäckt av redan betrodda iPhones.** Detta ska vara den
   stabila standardvägen och ersätta manuellt angivet UDID och fast IP-adress.
   Den fungerar med nuvarande Wi-Fi/Lockdown-transport efter en första USB-
   parkoppling.
2. **Trådlös första parkoppling.** Detta byggs som en separat, feature-flaggad
   iOS 27-funktion. Apples publika stöd börjar med iOS/iPadOS 27 och Xcode 27
   Device Hub. Den pinnade `idevice`-versionen innehåller byggblock för samma
   enhetsinitierade RemotePairing-flöde, men hela kedjan måste bevisas på riktig
   iPhone och Debian innan den får räknas som produktionsstöd.

iOS 26 och äldre behåller en USB-anslutning första gången. Efter den ska all
normal användning, ominstallation och förnyelse fungera trådlöst och utan
manuell IP-konfiguration.

## Mål

- Hitta samtliga nåbara, betrodda iPhones på det lokala nätverket automatiskt.
- Hantera flera telefoner och växlande DHCP-adresser.
- Visa online-, offline- och parkopplingsstatus tydligt i webbgränssnittet.
- Aldrig installera via USB av misstag; installation och förnyelse förblir
  Wi-Fi-only.
- Ge iOS 27-användare ett tidsbegränsat, användarinitierat flöde för trådlös
  första parkoppling.
- Behålla USB-onboarding som pålitlig fallback.
- Inte exponera UDID, pairing records, nycklar eller generiska enhetstunnlar via
  API eller loggar.

## Avgränsningar

- Ingen emulering av Apple TV:s PIN-protokoll på äldre iOS. Apple TV och vanlig
  iPhone har olika onboardingbeteende.
- Ingen nätverksskanning av hela subnät eller port 62078. Upptäckt ska ske via
  DNS-SD/mDNS och `netmuxd`, inte genom aggressiv IP-skanning.
- Ingen automatisk parkoppling utan en explicit åtgärd från administratören och
  ett godkännande på telefonen.
- Ingen produktionsgaranti för iOS 27 innan hårdvarugrinden i fas 4 är godkänd.
- Ingen generell TCP-, usbmuxd- eller RSD-proxy via webb-API:t.

## Nuläge och tekniska luckor

Nuvarande implementation:

- kräver `IPHONELOADLY_DEVICE_ID`, `IPHONELOADLY_DEVICE_IP` och
  `IPHONELOADLY_PAIRING_FILE`;
- skapar en enda `DirectTcpTransport` med fast IP-adress;
- returnerar högst en telefon från `GET /api/devices`;
- har redan Avahi, `netmuxd` och en separat mux-socket på
  `/run/iphoneloadly/mux.sock`;
- kontrollerar `_apple-mobdev2._tcp` och `idevice_id --network` i preflight,
  men använder inte denna upptäckt i API:t;
- låter `signing.rs` både signera och installera och accepterar endast
  `TcpProvider`, vilket blockerar en alternativ RSD-installationsväg;
- behandlar enhets-ID som Rust-typen `Uuid`. Ett Apple-UDID är en separat
  identifierartyp och får inte parsas eller exponeras som appens interna UUID.

Det första arbetet är därför inte ny protokollkod. Det är att koppla det redan
installerade `netmuxd`-lagret till backend och införa en riktig enhetskatalog.

## Stödmatris

| Enhetstillstånd | Upptäckt | Första parkoppling | Installation |
|---|---|---|---|
| Redan USB-parad, Wi-Fi aktiverat | Automatisk via `netmuxd`/mDNS | Inte tillämpligt | Befintlig Lockdown-väg över Wi-Fi |
| Oparad iPhone, iOS 26 eller äldre | Ska inte visas som installerbar | USB krävs en gång | Wi-Fi efter slutförd onboarding |
| Oparad iPhone, iOS 27+ | Under aktiv pairing-session | Experimentell RemotePairing | Avgörs av hårdvarugrind: Lockdown eller RSD |
| Offline/sovande, tidigare känd | Visas som offline efter timeout | Inte tillämpligt | Blockeras tills telefonen är nåbar |
| Endast synlig via USB | Kan visas som onboardingstatus | USB-onboarding tillåten | Installation blockeras på USB |

## Önskat användarflöde

### Redan parad telefon

1. Användaren öppnar dashboarden.
2. Backend läser nätverksenheter från `netmuxd` och frågar Lockdown efter namn,
   modell och iOS-version med kort timeout.
3. Telefonen visas automatiskt som **Online via Wi-Fi**.
4. Användaren väljer IPA och telefon och startar installationen.
5. Backend slår upp telefonens aktuella mux-post på nytt precis före jobbet.
   En gammal IP-adress eller gammal UI-lista används aldrig.

### Äldre eller USB-baserad första onboarding

1. UI visar **Lägg till iPhone med USB** och stegvisa instruktioner.
2. Telefonen ansluts och låses upp; användaren godkänner **Lita på den här
   datorn**.
3. Ett setup-verktyg parar, validerar och aktiverar Wi-Fi connections.
4. `netmuxd` startas om eller laddar om pairing record.
5. USB kopplas ur och onboarding godkänns först när samma telefon kan frågas via
   nätverket.
6. Ingen manuell inmatning av UDID eller IP-adress behövs.

### Trådlös första onboarding på iOS 27+

1. Administratören väljer **Lägg till iPhone trådlöst**.
2. Backend öppnar en enda tidsbegränsad pairing-session och annonserar en stabil
   värdidentitet som `_remotepairing-pairable-host._tcp.local`.
3. iPhone hittar värden. Exakt meny och instruktionstext fastställs i
   hårdvaruspiken och dokumenteras per iOS-version.
4. Telefonen ansluter till pairing-porten och driver RemotePairing-flödet.
5. Backend visar en sexsiffrig engångskod i den autentiserade dashboarden.
6. Användaren skriver koden på telefonen och godkänner trust-dialogen.
7. Backend sparar RemotePairing-identiteten och värdens `altIRK` krypterat,
   stoppar annonsen och stänger pairing-porten.
8. Backend bevisar en betrodd transport och läser enhetsinfo.
9. Telefonen läggs inte till som **installerbar** förrän ett signerat testpaket
   faktiskt kan installeras över Wi-Fi.

## Rekommenderad arkitektur

### 1. `DeviceRegistry`

Inför en bakgrundstjänst som äger den aktuella bilden av alla enheter.

Ansvar:

- läsa `ListDevices` från `/run/iphoneloadly/mux.sock`;
- filtrera `idevice::usbmuxd::Connection::Network`;
- aldrig använda en `Connection::Usb` för install eller refresh;
- fråga Lockdown om `DeviceName`, `ProductType` och `ProductVersion`;
- uppdatera `last_seen_at`, status och capabilities;
- mappa Apple-UDID till ett internt, icke-känsligt enhets-ID;
- hålla den riktiga mux-posten och UDID endast i processminnet;
- återansluta efter `netmuxd`-omstart och nätverksbyte;
- begränsa samtidiga frågor, exempelvis till fyra enheter;
- använda timeout per enhet så att en sovande telefon inte blockerar listan.

Första implementationen kan polla var femte sekund. När den är stabil kan den
kompletteras med `UsbmuxdConnection::listen` för snabbare connect/disconnect-
händelser. En periodisk full resync ska finnas kvar eftersom event kan tappas
vid daemon- eller socketomstart.

Föreslagen intern gränsyta:

```rust
trait DeviceDiscovery: Send + Sync {
    async fn snapshot(&self) -> Result<Vec<DiscoveredDevice>, DiscoveryError>;
}

trait DeviceTransport: Send + Sync {
    async fn list_devices(&self) -> Result<Vec<Device>, TransportError>;
    async fn resolve(&self, id: DeviceId) -> Result<ResolvedDevice, TransportError>;
    async fn install_signed_ipa(
        &self,
        device: ResolvedDevice,
        ipa: PathBuf,
    ) -> Result<(), TransportError>;
}
```

`ResolvedDevice` är ett kortlivat objekt. Det måste verifiera nätverkstypen och
den aktuella trust-sessionen när jobbet startar; det får inte återanvända en IP
från databasen.

### 2. Primär upptäcktsadapter: `NetmuxDiscovery`

- Konfigurera `IPHONELOADLY_MUX_SOCKET`, standard
  `/run/iphoneloadly/mux.sock`.
- Anslut med `idevice::usbmuxd::UsbmuxdAddr::UnixSocket`.
- Anropa `get_devices()` och behåll endast `Connection::Network`.
- Skapa en `UsbmuxdProvider` från den valda posten.
- Låt `netmuxd`/hostens pairing store tillhandahålla Lockdown record via
  mux-protokollet. API-processen ska normalt inte läsa plist-filer direkt.
- Behåll dagens `TcpProvider` som diagnostisk fallback, inte som ordinarie
  konfiguration.

Denna väg tar samtidigt bort behovet av fast IP och gör DHCP-byte transparent.

### 3. Beständig enhetskatalog

Lägg till en SQLite-tabell via en versionsstyrd migration, inte ytterligare
`CREATE/ALTER`-logik direkt i `initialize`.

```sql
devices (
  id TEXT PRIMARY KEY,                 -- internt UUIDv7
  udid_hash TEXT NOT NULL UNIQUE,      -- HMAC-SHA256, aldrig rått UDID
  display_name TEXT NOT NULL,
  product_type TEXT,
  ios_version TEXT,
  pairing_kind TEXT NOT NULL,          -- lockdown | remote_pairing
  onboarding_state TEXT NOT NULL,      -- trusted | experimental | revoked
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_network_seen_at TEXT
);
```

Regler:

- `id` används i API, jobb och UI.
- `udid_hash` skapas med en separat domännyckel och stabil master key.
- Rått UDID används endast för det aktuella mux-anropet i minnet.
- IP-adress lagras inte.
- Tidigare kända enheter kan visas offline, men installation kräver en färsk
  registry-post.
- Befintliga jobb fortsätter använda sina nuvarande interna UUID:n. Om den
  befintliga konfigurationen har ett giltigt internt ID importeras det vid
  första start; annars skapas ett nytt och gamla jobb märks som legacy.

### 4. Separera signering från installation

Refaktorera dagens `AppleSigningProvider::install_ipa(TcpProvider, ...)` till:

1. `SigningProvider::sign(...) -> SignedArtifact`;
2. `DeviceTransport::install_signed_ipa(...)`.

Det är nödvändigt av två skäl:

- samma signerade artefakt ska kunna installeras via både klassisk Lockdown och
  en eventuell RSD/CoreDevice-väg;
- signeringslagret ska inte känna till IP-adress, mux eller pairing record.

Den befintliga Lockdown/TCP-installationen implementeras först så att beteendet
inte förändras. RSD-adaptern läggs bara till om fas 4 visar att den behövs.

### 5. `PairingCoordinator`

Inför en separat abstraktion för onboarding:

```rust
trait PairingCoordinator: Send + Sync {
    async fn start(&self, mode: PairingMode) -> Result<PairingSession, PairingError>;
    async fn status(&self, id: PairingSessionId) -> Result<PairingStatus, PairingError>;
    async fn cancel(&self, id: PairingSessionId) -> Result<(), PairingError>;
}
```

Endast en aktiv trådlös pairing-session tillåts i första versionen. Sessionen
ska:

- kräva autentiserad administratör och CSRF-skydd;
- löpa ut efter fem minuter;
- ha högst tre PIN-försök;
- acceptera en telefon och därefter stänga lyssnaren;
- sluta annonsera vid success, avbrott, timeout eller processavslut;
- aldrig skriva PIN, pairing payload eller privata nycklar i logg.

Första implementationen kan ligga i API-processen eftersom nuvarande deployment
kör direkt under systemd. Inför containerdrift flyttas den LAN-lyssnande delen
till en liten host-agent bakom en privat Unix-socket; pairing-port och mDNS ska
inte lösas med `--privileged` eller host networking.

## iOS 27: prototypdesign

### Protokollbyggblock

Den pinnade `idevice = 0.1.65` innehåller:

- `remote_pairing::PairableHost` för det enhetsinitierade iOS 27-flödet;
- `PairableHostInfo` och TXT-records för
  `_remotepairing-pairable-host._tcp.local`;
- sexsiffrig PIN-callback;
- `RpPairingFile`, `altIRK`, peer validation och tunnelfunktioner;
- RSD- och installationstjänster bakom separata Cargo features.

Aktivera inte hela `full`-featuren. Lägg efter spiken endast till minsta
verifierade feature-set, sannolikt `remote_pairing`, `mdns`, `rsd` och den
installationstjänst som testet faktiskt kräver. Lås fortsatt exakt version och
lägg protokollanrop bakom egna adapters.

### mDNS-publicering

Spiken jämför två alternativ på målhosten:

1. in-process DNS-SD med en liten Rust-library;
2. Avahi över en begränsad, typad integration.

Välj den lösning som samtidigt kan:

- samexistera med `avahi-daemon`;
- publicera korrekta TXT-records och IPv4/IPv6-adresser;
- stoppas deterministiskt;
- fungera med systemd-härdningen;
- testas utan att bygga kommandosträngar eller använda ett shell.

Använd en fast konfigurerbar hög TCP-port så att brandväggsregeln kan vara smal.
Porten ska bara lyssna under en aktiv session. Tillåt inte pairing över routade
WAN-interface som standard.

### Hemligheter som måste bestå

- `RpPairingFile` för varje trådlöst parad telefon;
- värdens stabila RemotePairing-identifierare;
- värdens `altIRK`;
- master key för kryptering och UDID-HMAC.

Lagra materialet som root/service-user-ägt `0600`, krypterat med AEAD och med
separata nyckeldomäner. Ta med det i backup endast som en uttryckligt känslig,
krypterad del. **Unpair** ska ta bort lokal pairing state och markera enheten
revoked; det ska aldrig radera andra telefoners records.

### Obligatorisk transportgrind efter pairing

RemotePairing-success är inte samma sak som bevisad IPA-installation. Spiken ska
avgöra vilken av följande vägar som fungerar på iOS 27:

#### Väg A: klassisk Lockdown blir tillgänglig

- Telefonen dyker upp som betrodd `_apple-mobdev2._tcp`/`netmuxd`-enhet.
- En Lockdown-session kan startas utan USB.
- Befintlig install-adapter kan användas efter refaktoreringen.

Detta är den minsta och föredragna produktvägen om den kan bevisas.

#### Väg B: separat RemotePairing/RSD-transport krävs

- Upptäck telefonens `_remotepairing._tcp`-annons.
- Matcha annonsen kryptografiskt mot sparad RemotePairing-identitet.
- Etablera en betrodd userspace- eller systemtunnel.
- Läs enhetsinfo via RSD.
- Installera den redan signerade IPA:n via verifierad RSD/CoreDevice-
  installationstjänst.

Om väg B krävs ska den implementeras som `RsdDeviceTransport`; den får inte
smuggla in en tunneladress i `TcpProvider`. Om installation via RSD inte kan
bevisas ska trådlös pairing förbli labbfunktion, även om själva pairing-dialogen
fungerar.

## API-förslag

### Enheter

`GET /api/devices`

```json
[
  {
    "id": "019...",
    "displayName": "Min iPhone",
    "productType": "iPhone17,1",
    "iosVersion": "27.0",
    "status": "online",
    "connectionType": "network",
    "pairingKind": "lockdown",
    "installEligible": true,
    "lastSeenAt": "2026-08-12T10:15:00Z"
  }
]
```

Statusvärden ska vara stabila produktbegrepp: `online`, `offline`,
`trustRequired`, `pairing`, `unsupported` och `revoked`. Råa Apple-/biblioteksfel
ska inte bli API-kontrakt.

`POST /api/devices/rescan` begär en omedelbar resync men väntar inte på alla
telefoner. Normalt behövs den inte eftersom registry kör i bakgrunden.

### Pairing-sessioner

- `POST /api/pairing-sessions` med `{ "mode": "wireless" }`.
- `GET /api/pairing-sessions/{id}` för polling i första UI-versionen.
- `DELETE /api/pairing-sessions/{id}` för avbrott.

Exempelstatus:

```json
{
  "id": "019...",
  "phase": "awaitingDevice",
  "expiresAt": "2026-08-12T10:20:00Z",
  "setupCode": null,
  "publicMessage": "Öppna parkoppling på din iPhone."
}
```

När telefonen har anslutit blir fasen `awaitingCodeEntry` och `setupCode` visas
endast i den autentiserade sessionen. Slutfaser: `verifyingTransport`, `ready`,
`failed`, `cancelled`, `expired`.

## UI-plan

Ersätt dagens enkla select-lista med ett enhetskort eller en rikare select:

- namn, modell och iOS-version;
- grön **Online via Wi-Fi** eller grå **Senast sedd ...**;
- disabled Install-knapp om `installEligible` är false;
- **Sök igen** för manuell resync;
- **Lägg till iPhone** med valen USB och, när feature flag är på, trådlöst;
- en stegvis pairingdialog med nedräkning, PIN och Cancel;
- en tydlig experimentetikett för iOS 27 tills hårdvarumatrisen är godkänd;
- ingen visning av rått UDID, IP, HostID eller pairing-filens sökväg.

UI:t ska hantera tomma tillstånd separat:

- inga tidigare kända enheter;
- kända men offline;
- Bonjour fungerar men trust saknas;
- `netmuxd` är nere;
- telefon hittad endast via USB;
- iOS-version stöder inte trådlös första pairing.

## Säkerhet

- Pairing startas endast genom explicit administratörsåtgärd.
- API:t förblir bundet till localhost/TLS-proxy enligt befintlig modell.
- Pairing-porten är tillfällig, protokollspecifik och stängs fail-safe.
- Enhetens identitet måste verifieras kryptografiskt före trust och före varje
  återanslutning; namn och IP är aldrig identitet.
- Pairing state krypteras i vila och dekrypteras endast i minnet.
- Logga internt device-ID och fas, aldrig UDID, certifikat, `altIRK`, PIN,
  pairing plist eller fulla TXT-records.
- Begränsa pairingförsök, sessionstid och samtidighet.
- Inga användarvärden får interpoleras i shellkommandon.
- `GET /healthz` får bara ange att discovery-komponenten fungerar, inte lista
  enheter eller känslig status.
- Backup/restore ska verifiera filrättigheter och kunna återställa en telefon i
  taget utan att skriva ut pairingmaterial.

## Drift- och konfigurationsändringar

När automatisk discovery är införd:

- lägg till `IPHONELOADLY_MUX_SOCKET=/run/iphoneloadly/mux.sock`;
- ta bort produktkravet på `IPHONELOADLY_DEVICE_IP`;
- ta bort produktkravet på `IPHONELOADLY_DEVICE_ID`;
- ta bort API-tjänstens `ExecStartPre` för en specifik pairing-fil;
- behåll `/var/lib/lockdown` på hosten och `netmuxd` som enda normala läsare;
- ge API-användaren åtkomst endast till den dedikerade mux-katalogen;
- kör API:t som en dedikerad användare i stället för root när pairing-/socket-
  rättigheterna är lösta;
- lägg readiness för mux/discovery i doctor och diagnostics;
- dokumentera mDNS över VLAN, AP client isolation, IPv6 och brandvägg för
  pairing-porten.

Feature flags:

```text
IPHONELOADLY_WIRELESS_PAIRING=off|experimental|on
IPHONELOADLY_PAIRING_PORT=<fast hög port>
IPHONELOADLY_PAIRING_INTERFACE=<tomt eller explicit LAN-interface>
```

`on` tillåts först efter att produktionsgrinden är godkänd. Okänd eller saknad
konfiguration ska bete sig som `off`.

## Genomförandefaser

### Fas 0 – baslinje och adaptergränser

Arbete:

- lägg enhetstyper och traits i egna moduler;
- inför `DeviceId` som wrapper runt internt UUID och `AppleUdid` som privat
  strängtyp;
- flytta installation från `AppleSigningProvider` till transportlagret;
- skapa `FakeDeviceDiscovery` och `FakeDeviceTransport`;
- lägg SQLite-migrationsmekanism och `devices`-tabell;
- skriv regressionstest för dagens en-telefon-installation.

Acceptans:

- befintlig Wi-Fi-installation fungerar oförändrat;
- ett Apple-UDID behöver aldrig parsas som `Uuid`;
- tester kan simulera flera enheter utan hårdvara.

Storlek: medel. Risk: medel, eftersom signering/install delas.

### Fas 1 – automatisk upptäckt av redan parade telefoner

Arbete:

- implementera `NetmuxDiscovery` mot den dedikerade socketen;
- filtrera strikt på network connection;
- lägg registry-cache, timeouts, resync och reconnect;
- hämta enhetsmetadata parallellt med begränsad samtidighet;
- mappa till stabila interna ID:n och spara snapshots;
- ersätt miljövariabeltransporten i produktionsstarten;
- behåll fast TCP-konfiguration endast i test/diagnostik.

Acceptans:

- två redan parade telefoner visas automatiskt;
- ingen IP eller UDID skrivs in;
- DHCP-byte, Wi-Fi reconnect, telefon sleep/wake, `netmuxd`-restart och host-
  reboot kräver inte ny konfiguration;
- USB-only-enheter kan inte väljas för installation.

Storlek: medel. Risk: låg–medel.

### Fas 2 – flera enheter, API och UI

Arbete:

- utöka `/api/devices` med status och capabilities;
- lägg `/rescan` och offlinehistorik;
- uppdatera dashboarden med enhetsstatus och tomma tillstånd;
- slå upp vald enhet på nytt vid jobbstart;
- lägg ett aktivt jobb per enhet och separat global begränsning;
- gör refresh tolerant mot att en telefon är offline.

Acceptans:

- jobb hamnar alltid på rätt telefon efter samtidiga connect/disconnect;
- offlineenhet skapar inte ett installjobb;
- refresh hoppar över offlineenheter med tydlig, redigerad diagnos;
- inga råa identifierare visas i UI eller API.

Storlek: medel. Risk: medel.

### Fas 3 – förenklad USB-onboarding

Arbete:

- ersätt manuell UDID/IP-fråga i installskriptet;
- identifiera den nyanslutna USB-enheten entydigt;
- para, validera och aktivera Wi-Fi;
- kräva att USB kopplas ur;
- godkänn först efter lyckad nätverksfråga via mux-socketen;
- hantera fler än en ansluten USB-enhet genom explicit val, inte “första”.

Acceptans:

- en ny iPhone kan onboardas utan att användaren kopierar UDID eller IP;
- ett missat Trust-godkännande ger en konkret återställningsväg;
- pairing records visas aldrig i terminalen.

Storlek: liten–medel. Risk: låg.

### Fas 4 – iOS 27 hårdvaruspike

Spiken görs i ett separat testbinär först, inte i webb-API:t.

Testordning:

1. annonsera pairable host med stabil identitet;
2. bevisa att iPhone hittar hosten på Debian-LAN;
3. genomför PIN och trust;
4. spara och återanvänd RemotePairing record efter process- och host-restart;
5. läs namn, UDID och iOS-version över betrodd trådlös transport;
6. avgör väg A eller B för installation;
7. signera en säker test-IPA och installera med USB fysiskt frånkopplad;
8. upprepa efter telefon sleep/wake, Wi-Fi-byte och reboot;
9. testa unpair och nekad/felaktig PIN;
10. dokumentera modell, exakt iOS-build, nätverk, dependency-commit och loggkod.

Go-kriterium:

- hela trust- och installationskedjan fungerar utan USB på minst två iPhone-
  modeller och två iOS 27-builds;
- den överlever omstart utan ny PIN;
- ingen hemlighet hamnar i loggar eller processargument;
- upstream-API:t kan pinnas reproducerbart.

No-go betyder att fas 5 inte byggs. Fas 1–3 levereras ändå.

Storlek: medel som spike. Risk: hög och hårdvaruberoende.

### Fas 5 – experimentell trådlös pairing i produkten

Arbete:

- implementera `PairingCoordinator`;
- publicera tidsbegränsad mDNS och öppna pairing-port;
- lägg krypterad secret store;
- lägg pairing-session-API och UI-dialog;
- implementera verifierad Lockdown- eller RSD-adapter från fas 4;
- lägg cancel, timeout, rate limiting, cleanup och unpair;
- håll allt bakom `experimental`.

Acceptans:

- komplett browser-till-iPhone-onboarding utan terminal eller kabel;
- avbruten session lämnar ingen port, annons eller halv pairing state;
- om installationstransporten inte verifieras visas enheten inte som
  installerbar;
- USB-fallbacken är alltid tillgänglig.

Storlek: stor. Risk: hög.

### Fas 6 – härdning och generell aktivering

Arbete:

- kör full hårdvarumatris och längre soak-test;
- fuzz/property-testa parsing av mDNS TXT och pairingmeddelanden;
- threat-model-review av LAN-lyssnaren och secret store;
- verifiera backup/restore, unpair och ny iOS-uppgradering;
- uppdatera installer, systemd, doctor, diagnostics och användardokumentation;
- flytta LAN-pairing till host-agent innan containerisering om det behövs;
- ändra feature flag från `experimental` till `on` först efter release gate.

Acceptans:

- minst 30 dagars automatiska reconnect/refresh-tester utan manuell re-pair;
- uppgradering och rollback bevarar befintliga USB-parade enheter;
- säkerhets- och loggredigeringstester passerar;
- supportmatris och kända begränsningar är publicerade.

Storlek: medel–stor. Risk: medel.

## Teststrategi

### Enhets- och integrationstester utan telefon

- mux-lista med noll, en och flera network/USB-enheter;
- dubbla poster för samma UDID;
- enhet försvinner mellan listning och jobbstart;
- felaktigt och icke-UUID-format Apple-UDID;
- timeout och trasig pairing record för en av flera telefoner;
- `netmuxd` socket försvinner och kommer tillbaka;
- stabil intern ID-mappning efter omstart;
- inga IP/UDID/PIN/nycklar i serialiserade API-fel eller loggar;
- pairing state machine för success, reject, timeout, cancel och process-stop;
- migrations- och rollbacktest med befintlig databas;
- refresh mot online och offline targets.

### Hårdvarumatris

Minsta matris:

- en äldre iPhone/iOS 26 eller äldre, USB-onboarding + auto-discovery;
- minst två modeller med iOS 27 för trådlös pairing;
- ett vanligt hemnät och ett nät med separat VLAN/mDNS-reflector;
- IPv4, IPv6 och dual stack;
- AP client isolation som negativt test;
- telefon låst, upplåst, sovande och efter reboot;
- host reboot, `netmuxd` restart och DHCP lease-byte;
- två telefoner online samtidigt;
- fel PIN, nekat trust, session timeout och explicit unpair.

Varje testprotokoll ska ange exakt iOS-build, modell, Debian-version,
`idevice`/`netmuxd`-version och vald transportväg, men redigera UDID och
pairingmaterial.

## Observability och felmodell

Stabila diagnostikkoder:

- `discovery_mux_unavailable`
- `discovery_no_network_devices`
- `device_offline`
- `device_usb_only`
- `device_trust_required`
- `pairing_not_supported`
- `pairing_advertise_failed`
- `pairing_rejected`
- `pairing_expired`
- `pairing_transport_unverified`
- `install_transport_unavailable`

Loggfält: request/job/session ID, internt device-ID, fas, varaktighet och kod.
Logga inte råa upstream-fel förrän de passerat typad redigering.

Doctor ska separat kontrollera:

- mux-socket och `netmuxd`;
- Avahi/mDNS;
- antal network-enheter utan identifierare;
- Lockdown-fråga för uttryckligen valt internt device-ID;
- feature flag och pairing-portens konfiguration;
- secret-store-rättigheter;
- att ingen pairingannons finns när ingen session är aktiv.

## Migrering och rollback

1. Leverera databas- och adapterrefaktoreringen utan att ta bort gamla env-vars.
2. Om nya discovery fungerar används den primärt; gammal konfiguration kan
   aktiveras med en explicit legacy-flag under en övergångsrelease.
3. Importera den konfigurerade telefonen till `devices` vid första lyckade
   nätverksupptäckt.
4. Ta bort IP/UDID/pairing-file från standardinstallern först efter fas 1:s
   hårdvarugrind.
5. Behåll pairing records vid rollback. Databasmigrationer ska vara additiva i
   första releasen.
6. Trådlös iOS 27-pairing är av som standard och kan stängas av utan att påverka
   redan USB-parade telefoner.

## Viktigaste riskerna

| Risk | Konsekvens | Motåtgärd |
|---|---|---|
| RemotePairing ger inte en transport som nuvarande installer kan använda | Pairing lyckas men IPA kan inte installeras | Fas 4 kräver verklig installation; separat RSD-adapter vid behov |
| Privat Apple-protokoll ändras mellan iOS-builds | Onboarding eller reconnect slutar fungera | Exakt pinning, adaptergräns, hårdvarumatris och feature flag |
| mDNS blockeras av VLAN/AP | Telefoner hittas inte | Tydlig doctor, dokumenterad reflector/brandvägg, ingen subnätsskanning |
| Sovande telefon ger långsamma API-anrop | Dashboard och refresh hänger | Cache, kort timeout, bounded concurrency och offline-status |
| Fel telefon väljs efter nätverksbyte | Installation på fel mål | Kryptografisk/UDID-baserad identitet och resolve precis före jobb |
| Pairing endpoint exponeras på LAN | Angreppsyta och DoS | Explicit femminuterssession, rate limit, en klient och fail-safe cleanup |
| Pairing state eller UDID läcker | Bestående enhetsåtkomst exponeras | AEAD, 0600, typad redigering och inga generiska debug-dumpar |
| Upstream `idevice` bryter API före 0.2 | Bygg- eller runtimefel | Exakt version/commit och intern adapter med kontraktstester |

## Definition of done

### Automatisk upptäckt

- Ingen produktionskonfiguration innehåller fast iPhone-IP.
- Ingen användare behöver kopiera UDID.
- Alla betrodda Wi-Fi-enheter visas och uppdateras automatiskt.
- Flera telefoner, DHCP-byte, sleep/wake och daemon/host-restart är testade.
- Install och refresh verifierar `Network` vid jobbstart.
- Råa identifierare och pairing records exponeras inte.

### Trådlös iOS 27-parkoppling

- Pairing initieras och godkänns helt utan USB.
- Pairing state överlever kontrollerad omstart och kan tas bort med unpair.
- Enheten återupptäcks och autentiseras utan ny PIN.
- En riktig, säker test-IPA kan signeras och installeras över Wi-Fi.
- Negativa tester lämnar ingen lyssnande port eller halv pairing state.
- Funktionen kan stängas av omedelbart utan att påverka den stabila USB-
  fallbacken.

## Rekommenderad första leverans

Börja med fas 0–3 som en sammanhängande release: dynamisk `netmuxd`-upptäckt,
flera telefoner och USB-onboarding utan manuell IP/UDID. Det ger den största
användarvinsten med lägst protokollrisk.

Kör därefter fas 4 som en isolerad iOS 27-spike. Ta inte in trådlös pairing i
dashboarden förrän samma pairing record har lett till en verklig IPA-
installation med USB fysiskt frånkopplad.

## Referenser

- Apple: [Managing your simulated and physical devices in Device Hub](https://developer.apple.com/documentation/xcode/pairing-your-devices-with-your-mac)
- `pymobiledevice3`: [iOS 17+ tunnels](https://github.com/doronz88/pymobiledevice3/blob/master/docs/guides/ios17-tunnels.md)
- `idevice` 0.1.65 i lokal Cargo-cache: `remote_pairing::PairableHost`,
  `PairableHostInfo`, `RpPairingFile`, `mdns` och `usbmuxd`.
- Befintlig hostdesign: [architecture-assessment.md](architecture-assessment.md)
- Befintlig leveransplan: [mvp-v0.1-plan.md](mvp-v0.1-plan.md)

