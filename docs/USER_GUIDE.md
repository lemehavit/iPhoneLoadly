# Användarguide för iPhoneLoadly

Den här guiden beskriver den vanliga användningen efter att servern, Caddy och
den första USB-parkopplingen har konfigurerats. Dashboarden öppnas normalt på:

```text
https://iphoneloadly.local
```

En certifikatvarning kan visas eftersom Caddy använder en lokal
certifikatutfärdare. Du kan fortsätta efter webbläsarens varning på ett nätverk
du litar på, eller installera Caddys publika rotcertifikat enligt
[Caddy-guiden](operations/caddy-lan.md). Publicera aldrig dashboarden på
Internet.

## 1. Orientera dig i dashboarden

![Dashboardens översikt](images/dashboard-overview.png)

Menyn överst leder direkt till **Översikt**, **Apple-signering**,
**IPA-filer**, **Installera** och **Historik**. Språkväljaren växlar hela
gränssnittet mellan svenska och engelska.

Systemstatus visar om Apple-signeringen är redo. Översikten visar lyckade
installationer, återstående signeringstid, betrodda iPhones och endast appar
som installerats genom iPhoneLoadly.

## 2. Logga in hos Apple

![Apple-inloggning och IPA-uppladdning](images/dashboard-workflow.png)

1. Ange Apple-ID och lösenord under **Apple-signering**.
2. Markera **Spara inloggningen krypterat på denna server** endast om du vill
   att servern ska försöka återställa sessionen efter omstart.
3. Tryck **Logga in** och ange Apples 2FA-kod när den efterfrågas.
4. Kontrollera att systemstatus ändras till att Apple-signeringen är redo.

Lösenordet ligger endast i minnet om du inte aktivt väljer krypterad lagring.
2FA-koder sparas aldrig. Apple kan ändå kräva en ny kod efter en omstart.

Knappen för att frigöra ett gammalt utvecklingscertifikat ska bara användas om
Apple uttryckligen säger att certifikatgränsen är nådd. Ett återkallat
certifikat kan göra tidigare signerade appar obrukbara tills de signeras om.

## 3. Ladda upp en IPA

1. Tryck **Choose File/Välj fil** under **Ladda upp IPA**.
2. Välj en `.ipa`-fil från datorn.
3. Tryck **Ladda upp** och vänta på bekräftelsen.
4. Den uppladdade filen blir valbar under **Installera eller förnya**.

En IPA kan tas bort med **Ta bort vald IPA från servern**. Borttagningen är
permanent och blockeras medan filen används av ett aktivt installations- eller
förnyelsejobb.

## 4. Installera på en betrodd iPhone

![Installation och historik](images/dashboard-installation.png)

1. Kontrollera att iPhone är på samma LAN/Wi-Fi, parkopplad och nåbar.
2. Välj IPA under **IPA att signera och installera**.
3. Välj telefon under **iPhone**.
4. Tryck **Signera och installera**.
5. Följ progressfältet genom signering, överföring och installation.

Telefonen kan behöva vara upplåst. Om den inte visas, tryck **Sök igen** och
kontrollera Wi-Fi, `iphoneloadly-netmuxd` och Bonjour om den fortfarande är
offline.

## 5. Välj dag för automatisk förnyelse

![Inställning för automatisk förnyelse](images/dashboard-refresh-settings.png)

1. Öppna **Översikt → Automatisk förnyelse**.
2. Välj dag 1–6 efter den senaste lyckade installationen.
3. Tryck **Spara inställning**.

Dag 6 är standard och rekommenderas eftersom den normalt lämnar ungefär ett
dygn före den kostnadsfria sjudagarssigneringens utgång. Inställningen sparas i
serverns databas och överlever omstarter. Timern kontrollerar varje timme och
försöker igen senare om telefonen är offline. Förnyelsen kräver att
Apple-signeringen är redo.

**Förnya alla tidigare installationer** använder samma valda dag och köar de
installationer som har nått gränsen.

## 6. Kontrollera giltighet och historik

Under **Installerade IPA:er** visas hur många dagar som återstår för varje
lyckad installation. Välj en telefon och tryck **Visa iPhoneLoadly-appar** för
att se appar som tjänsten själv har installerat; vanliga App Store-appar visas
inte.

Historiken visar de senaste 20 jobben, status, progress och säker redigerad
diagnostik. Den visar inte lösenord, Apple-sessioner eller fullständiga
telefonidentifierare.

## Svenska och engelska etiketter

| Svenska | English |
| --- | --- |
| Översikt | Overview |
| Apple-signering | Apple signing |
| Ladda upp IPA | Upload IPA |
| Installera eller förnya | Install or refresh |
| Automatisk förnyelse | Automatic refresh |
| Spara inställning | Save setting |
| Historik och diagnostik | History and diagnostics |

## Felsökning

- [Installation och vanlig felsökning](INSTALL.md#troubleshooting)
- [Caddy och LAN-åtkomst](operations/caddy-lan.md)
- [Debian, Bonjour och Wi-Fi](operations/debian13-host-preparation.md)
- [Systemd, refresh, backup och återställning](operations/api-systemd.md)
