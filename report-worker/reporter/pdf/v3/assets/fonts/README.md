# Inter (mitgeliefert)

Vier statische Schnitte aus dem Release **Inter v4.1** (`extras/ttf/`) von
<https://github.com/rsms/inter>, Lizenz SIL Open Font License 1.1 (`OFL.txt`).
Verwendete Gewichte im Stylesheet: 400 Regular, 500 Medium, 600 SemiBold, 700 Bold.

Warum mitgeliefert und nicht per apt installiert: die Schrift bestimmt Zeilenumbruch und
damit die Seitenzahl des Berichts. Ueber Fontconfig haengt sie an dem, was das jeweilige
System zufaellig installiert hat, und die Seitenzahl waere in Abbild, CI und
Entwicklungsumgebung verschieden. `tests/golden/render/expected-pages.json` waere dann
wertlos.

Aktualisieren: neues Release herunterladen, dieselben vier Dateien aus `extras/ttf/`
ersetzen, `python -m reporter.pdf.v3 --update-pages` laufen lassen und die geaenderten
Seitenzahlen im Commit begruenden.

`DejaVu Sans Mono` kommt weiterhin aus dem Debian-Paket `fonts-dejavu-core` im Abbild
und wird nur fuer Nachweisbloecke und Kennungen benutzt.
