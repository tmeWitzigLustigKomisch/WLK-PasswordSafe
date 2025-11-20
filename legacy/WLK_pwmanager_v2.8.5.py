#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pwmanager.py – Hochsicherer Passwort‑Manager als Einzeldatei.

### Zusätzliche Funktionen / Additional features

- **Keyfile & Gerätebindung / Keyfile & device binding:** Sie können optional eine Schlüsseldatei (Keyfile) und sogar eine Gerätebindung aktivieren. Das Keyfile erhöht die Entropie Ihres Master‑Passworts deutlich. Die Gerätebindung mischt eine eindeutige Geräte‑ID (Linux: ``/etc/machine-id``, Windows: ``MachineGuid``) in den KDF‑Input. / You can optionally use an external key file and even bind the vault to a specific device. The key file dramatically increases your password entropy. Device binding mixes a unique machine ID (Linux: ``/etc/machine-id``, Windows: ``MachineGuid``) into the KDF input.
- **Argon2 Auto‑Tuning / Argon2 auto‑tuning:** Wenn das Modul ``argon2-cffi`` verfügbar ist, nutzt der Passwortmanager Argon2id anstelle von scrypt. Ein Auto‑Tuning ermittelt auf Ihrem System passende Parameter für Zeit und Speicher. / If the ``argon2-cffi`` module is available, the password manager uses Argon2id instead of scrypt. An auto‑tuning step picks safe time and memory parameters for your hardware.
- **Mindestpasswortqualität / Minimum password quality:** Beim Anlegen eines Tresors wird Ihr Master‑Passwort auf Mindestlänge, Groß‑/Kleinbuchstaben, Ziffern und Sonderzeichen geprüft. / When creating a new vault, your master password is checked for minimum length, uppercase/lowercase letters, digits and special characters.
- **Zwischenablage‑Sicherheit / Clipboard security:** Passwörter im Klartext werden automatisch wieder maskiert und die Zwischenablage wird nach wenigen Sekunden geleert. / Plaintext passwords are automatically re‑masked and the clipboard is cleared after a few seconds.
- **Tabellen & Sortierung / Tables & sorting:** Info‑Felder können als formatierbare Tabellen dargestellt werden. Sie können Spalten und Zeilen definieren, die Spaltennamen nachträglich anpassen und Spalten per Klick sortieren. Auch die Hauptliste der Einträge lässt sich durch Klicken auf die Spaltenköpfe sortieren. / Info fields can be formatted as tables. You can define columns and rows, rename columns later and sort by clicking a column header. The main entry list can also be sorted by clicking its headers.

### Datenschutz & Quellen / Privacy & sources

- Dieses Programm verarbeitet alle Daten ausschließlich lokal. Es werden keine Passwörter oder personenbezogenen Daten an Dritte übertragen. / This program processes all data solely on your local machine. No passwords or personal data are sent to third parties.
- Verwendete Python‑Module: Es werden primär Standardbibliotheken genutzt; zusätzlich wird das Paket ``cryptography`` benötigt. Optional können ``pyperclip`` und ``argon2-cffi`` verwendet werden (KDF-Funktion). Dazu gehören u. a. ``argparse``, ``base64``, ``getpass``, ``os``, ``pathlib``, ``json``, ``hashlib``, ``hmac``, ``secrets``, ``shutil``, ``stat``, ``string``, ``subprocess``, ``sys``, ``tempfile``, ``textwrap``, ``time``, ``csv``, ``threading``, ``struct``, ``dataclasses``, ``webbrowser``, ``locale`` und ``tkinter`` für die GUI. / Used Python modules: the standard library is used wherever possible; the ``cryptography`` package is required, and ``pyperclip`` and ``argon2-cffi`` may optionally be installed (for KDF functionality). Modules used include ``argparse``, ``base64``, ``getpass``, ``os``, ``pathlib``, ``json``, ``hashlib``, ``hmac``, ``secrets``, ``shutil``, ``stat``, ``string``, ``subprocess``, ``sys``, ``tempfile``, ``textwrap``, ``time``, ``csv``, ``threading``, ``struct``, ``dataclasses``, ``webbrowser``, ``locale`` and ``tkinter`` for the GUI.
- Ihre Tresordatei und Konfigurationsdatei werden nur lokal gespeichert. Wir speichern keinerlei Telemetrie. / Your vault and configuration files are stored locally. We do not collect any telemetry.

### Credits & Werbung / Credits & advertising

- Dieses Programm wurde von **FleXcon** entwickelt. / This program was developed by **FleXcon**.
- Besuchen Sie unseren Telegram‑Kanal: @WitzigLustigKomisch / Check out our Telegram channel: @WitzigLustigKomisch

### Haftungsausschluss / Disclaimer

- Dieses Programm wird ohne jegliche Gewährleistung bereitgestellt. Die Nutzung erfolgt auf eigene Gefahr. Der Entwickler haftet nicht für Schäden, Datenverluste oder sonstige Probleme, die durch die Verwendung dieser Software entstehen. / This program is provided without any warranty. Use it at your own risk. The developer is not liable for any damage, data loss or other issues arising from the use of this software.
- Bitte erstellen Sie stets Sicherungskopien Ihrer Daten, bevor Sie Verschlüsselungs- oder Steganografie‑Funktionen verwenden, und prüfen Sie die Wiederherstellbarkeit Ihrer Backups. / Please always make backup copies of your data before using encryption or steganography functions and verify that your backups can be restored.

### Lizenz / License

- Dieses Programm wird unter der MIT‑Lizenz veröffentlicht. Sie dürfen den Quellcode frei verwenden, ändern und weitergeben, solange Sie den ursprünglichen Copyright‑Hinweis und diese Lizenzbedingungen beibehalten. / This program is released under the MIT License. You may use, modify and distribute the source code freely, provided that you retain the original copyright notice and these licence terms.

Deutsch:
Dieser Passwortmanager speichert Ihre Passwörter sicher in einer verschlüsselten Tresor‑Datei.
Er nutzt eine dreifache Verschlüsselungskaskade (AES‑256‑GCM → XOR‑Obfuskation via
HMAC‑Pad → ChaCha20‑Poly1305). Darüber hinaus können Sie beliebig viele **zusätzliche
Verschlüsselungsschichten** aktivieren: Jede Schicht fügt ein eigenes Salt, Nonce,
One‑Time‑Pad und eine HMAC hinzu und erschwert so eine nachträgliche Analyse.  Die Anzahl dieser
Schichten wird durch die Variable ``EXTRA_ENCRYPTION_LAYERS`` bestimmt. Eine Eingabe von ``0``
bedeutet, dass nur die Triple‑Verschlüsselung verwendet wird (Dateiformatversion 3); ``1``
entspricht einer zusätzlichen XOR/HMAC‑Schicht (Version 4); ``2`` bedeutet zwei zusätzliche
Schichten (Version 5) usw. Es gibt kein festes Maximum – mehr Schichten erhöhen jedoch die
Dateigröße und den Rechenaufwand beim Öffnen und Speichern. Über den scrypt‑KDF werden drei
unabhängige Schlüssel (AES‑, ChaCha‑ und MAC‑Schlüssel) aus Ihrem Master‑Passwort abgeleitet.
Ein HMAC‑SHA512 sichert die Integrität der Daten. Bei jedem Speichervorgang werden
Salt/Nonce/Pad neu generiert, sodass die Datei binär immer anders aussieht.  Das Speichern
erfolgt atomar; optional können vor dem Überschreiben Backups der vorherigen Version angelegt
werden. Eine optionale Passwortstärkewarnung erinnert an die Mindestlänge des Master‑Passworts.

### GUI‑Benutzung
1. Starten Sie das Programm mit ``python pwmanager.py`` und geben Sie ein Master‑Passwort ein.
2. **Login‑Fenster:** Die Schaltflächen erlauben das Erstellen eines neuen Tresors, das Öffnen
   einer vorhandenen Tresor‑Datei, das Auswählen einer anderen Tresor‑Datei, das Laden, Erstellen
   oder Bearbeiten einer Konfigurationsdatei, das Umschalten der Sprache, das Aufrufen dieser Hilfe
   und das Verlassen des Programms.
3. **Hauptansicht:** Nach dem Entsperren zeigt die Liste Ihre Einträge. Die Buttons rechts bieten
   folgende Funktionen:
   * *Anzeigen:* Doppelklick oder Button, um einen Eintrag inklusive Benutzername, Passwort,
     E‑Mail und URL anzuzeigen. Der URL‑Link ist klickbar.
   * *Hinzufügen/Bearbeiten/Löschen:* Neue Einträge erstellen, vorhandene bearbeiten oder löschen.
   * *Exportieren:* Einzelne Einträge als TXT, alle Einträge als TXT oder CSV exportieren.
     Exportierte Dateien sind unverschlüsselt – bitte sicher löschen.
   * *Importieren:* CSV‑Datei importieren; Einträge werden mit neuen IDs in den Tresor eingefügt.
   * *Starkes Passwort generieren:* Erstellt ein zufälliges Passwort und kopiert es in die Zwischenablage.
   * *Master‑Passwort ändern:* Ermöglicht das Ändern des Master‑Passworts. Stellen Sie sicher, dass
     Sie sich das neue Passwort merken.
   * *Neu verschlüsseln (save):* Speichert den Tresor und generiert neue Zufallsdaten (Salt/Nonce/Pad).
     Backups werden entsprechend der Konfiguration angelegt.
   * *Datei‑Operationen:* Öffnet ein Untermenü für das Verschlüsseln/Entschlüsseln beliebiger
     Dateien sowie das Verstecken/Extrahieren von Dateien in Cover‑Bildern.

4. **Datei‑Operationen:**
   * *Datei verschlüsseln/entschlüsseln:* Wählen Sie eine Eingabedatei, geben Sie ein Passwort ein
     und wählen Sie den Zielpfad. Die verschlüsselte Datei erhält die Endung ``.enc``.
   * *Datei verstecken:* Wählen Sie zuerst die zu versteckende Datei, dann ein Cover‑Bild
     (BMP/PNG/JPEG) und einen Zielnamen. Ein Passwort schützt den Inhalt; die Ausgabedatei
     bekommt die Endung ``.hid``.
   * *Versteckte Datei extrahieren:* Wählen Sie eine ``.hid``‑Datei und einen Zielpfad. Geben Sie
     das Passwort ein, um die ursprüngliche Datei zu extrahieren.

5. Unten im Fenster wird der aktuelle Tresor‑Status angezeigt sowie ein Hinweis zur Telegram‑Gruppe.
   Mit der Schaltfläche „Sprache wechseln“ können Sie jederzeit zwischen Deutsch und Englisch
   umschalten.

### CLI‑Benutzung
Starten Sie die Kommandozeile mit ``python pwmanager.py --cli`` und geben Sie Ihr Master‑Passwort
ein. Ein numerisches Menü erscheint. Geben Sie die passende Nummer ein und bestätigen Sie mit Enter:

```
1 – Einträge auflisten
2 – Eintrag anzeigen
3 – Eintrag hinzufügen
4 – Eintrag bearbeiten
5 – Eintrag löschen
6 – Einzelnen Eintrag exportieren (TXT)
7 – Alle Einträge exportieren (TXT)
8 – Alle Einträge exportieren (CSV)
9 – Starkes Passwort generieren
P – Passwort in Zwischenablage kopieren
S – Tresor neu verschlüsseln (save)
C – Konfiguration erstellen
10 – Datei verschlüsseln
11 – Datei entschlüsseln
12 – Datei verstecken
13 – versteckte Datei extrahieren
14 – CSV importieren
0 – Beenden (speichert automatisch)
```

Die Optionen 10–13 führen die gleichen Datei‑Operationen wie in der GUI aus. Option 14 importiert
eine CSV‑Datei, wobei neue IDs vergeben werden. Beachten Sie, dass Exporte im Klartext erfolgen.
Verwenden Sie die folgenden Befehle, um Cover‑Bilder für das Steganografie‑Feature zu erstellen oder
vorhandene Bilder aufzufüllen:

```
python pwmanager.py --make-cover OUT.(bmp|png|jpg) --size-mib 1.0
python pwmanager.py --inflate-image SRC.(jpg|jpeg|png|bmp) OUT.(jpg|png|bmp) --size-mib 1.0
```

English:
This password manager stores your passwords securely in an encrypted vault file. It uses a
triple‑layer encryption cascade (AES‑256‑GCM → XOR obfuscation via an HMAC pad →
ChaCha20‑Poly1305). Beyond this, you can enable an arbitrary number of **additional encryption
layers**: each extra layer derives its own salt and nonce from your master password,
generates a one‑time pad and computes an HMAC, making the vault even more difficult to analyze.
The number of extra layers is controlled via the ``EXTRA_ENCRYPTION_LAYERS`` variable. A value
of ``0`` means only the triple‑layer encryption is used (file format version 3); ``1`` adds
one extra XOR/HMAC layer (version 4); ``2`` adds two layers (version 5) and so on. There is
no fixed maximum – increasing the number of layers will grow the file size and CPU time when
opening or saving a vault.  The scrypt KDF derives three independent keys (AES, ChaCha and
MAC keys) from your master password. An HMAC‑SHA512 protects the data integrity. Each save
operation regenerates salts, nonces and pads so the file always looks different at the binary
level. Saving is atomic and can optionally create backups. An optional password strength warning
reminds you of the minimum length of the master password.

### GUI usage
1. Start the program with ``python pwmanager.py`` and enter a master password.
2. **Login window:** Buttons allow you to create a new vault, open an existing vault file, select
   a different vault file, load, create or edit a configuration file, switch languages, open this
   help or exit.
3. **Main view:** After unlocking, the list displays your entries. The buttons on the right offer
   these functions:
   * *View:* Double‑click or click to see an entry’s details (username, password, email and URL).
     The URL is a clickable link.
   * *Add/Edit/Delete:* Create new entries, modify existing ones or remove them.
   * *Export:* Export a single entry as TXT, all entries as TXT or CSV. Exported files are
     plaintext – securely delete them afterwards.
   * *Import:* Import a CSV file; entries will be assigned new IDs.
   * *Generate strong password:* Creates a random password and copies it to the clipboard.
   * *Change master password:* Allows you to change the master password. Ensure you remember the
     new password.
   * *Re‑encrypt (save):* Saves the vault and generates fresh randomness (salts, nonces and pads).
     Backups are created according to the configuration.
   * *File operations:* Opens a submenu to encrypt/decrypt arbitrary files and hide/extract files
     inside cover images.

4. **File operations:**
   * *Encrypt/Decrypt file:* Select an input file, enter a password and choose an output path.
     The encrypted file gets the extension ``.enc``.
   * *Hide a file:* Select the file to hide, then a cover image (BMP/PNG/JPEG) and an output
     name. Enter a password; the output will have the extension ``.hid``.
   * *Extract hidden file:* Select a ``.hid`` file and an output path. Enter the password to
     extract the original file.

5. The status bar shows the current vault state and a Telegram channel invitation. Use
   “Switch language” to toggle between English and German at any time.

### CLI usage
Start the command‑line interface with ``python pwmanager.py --cli`` and enter your master
password. A numeric menu will appear. Type the number and press Enter:

```
1 – List entries
2 – View entry
3 – Add entry
4 – Edit entry
5 – Delete entry
6 – Export single entry (TXT)
7 – Export all entries (TXT)
8 – Export all entries (CSV)
9 – Generate a strong password
P – Copy password to clipboard
S – Re‑encrypt the vault (save)
C – Create configuration file
10 – Encrypt a file
11 – Decrypt a file
12 – Hide a file
13 – Extract hidden file
14 – Import CSV
0 – Exit (automatically saves)
```

Options 10–13 perform the same file operations as the GUI. Option 14 imports a CSV file and
assigns new IDs. Please note that exports are created in plaintext. Use the standalone tools
below to generate cover images for steganography or enlarge existing images until they reach the
specified minimum size:

```
python pwmanager.py --make-cover OUT.(bmp|png|jpg) --size-mib 1.0
python pwmanager.py --inflate-image SRC.(jpg|jpeg|png|bmp) OUT.(jpg|png|bmp) --size-mib 1.0
```

Diese Werkzeuge / These tools erzeugen ein zufälliges Cover‑Bild oder blasen ein vorhandenes Bild
auf einen zufälligen Hintergrund auf, bis es eine Mindestgröße erreicht.

### Beispiele / Examples

Deutsch:
- **Neuen Tresor erstellen:** Wenn noch keine Tresor‑Datei existiert, geben Sie einfach ein neues
  Master‑Passwort ein und klicken Sie im Login‑Fenster auf „Neu“. Der Tresor wird angelegt,
  sobald Sie ihn speichern.
- **Datei verschlüsseln:** Öffnen Sie im Menü „Datei‑Operationen“ die Option „Datei
  verschlüsseln“. Wählen Sie Ihre Datei, geben Sie ein Passwort ein und speichern Sie das
  Ergebnis als .enc‑Datei ab.
- **Datei verstecken und extrahieren:** Verwenden Sie ein unauffälliges Bild als Cover.
  Verstecken Sie Ihre Datei mithilfe eines Passworts. Zum Extrahieren wählen Sie die .hid‑Datei,
  geben Sie das Passwort ein und speichern das extrahierte Original.
- **Konfiguration verwenden:** Erstellen Sie eine Konfigurationsdatei über „Create config“.
  Die Datei ``pwmanager_config.json`` speichert Einstellungen wie Backups, Farbschema und
  KDF‑Parameter. Laden Sie diese Datei im Login‑Fenster, um Ihr persönliches Profil zu verwenden.


English:
- **Creating a new vault:** If no vault file exists, simply enter a new master password and click
  “New” in the login window. The vault will be created once you save it.
- **Encrypting a file:** Open the “Encrypt file” option in the file operations menu. Select your
  file, enter a password and save the result as a .enc file.
- **Hiding and extracting a file:** Use an innocuous image as the cover. Hide your file using a
  password. To extract, choose the .hid file, enter the password and save the extracted original.
- **Using a configuration:** Create a configuration file via “Create config”. The file
  ``pwmanager_config.json`` stores settings such as backups, color scheme and KDF parameters.
  Load this file in the login window to apply your personal preferences.

"""

from __future__ import annotations
import argparse
import base64
import getpass
import os
import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import csv  # für CSV-Export
import threading  # für CLI‑Zwischenablagen-Löschung
import struct
from dataclasses import dataclass, asdict
import webbrowser  # Für klickbare Links in der GUI
import locale  # für deutsches Datumsformat
from pathlib import Path
from typing import Dict, Optional, Tuple, Callable

# ====================================
# SECTION Z — Cover-Datei Generatoren & Bild-Aufblähung (BMP/PNG/JPEG)


# ---- Deutsche Datums-/Zeitformatierung ----
try:
    locale.setlocale(locale.LC_TIME, "")
except Exception:
    pass

def fmt_de(ts: float) -> str:
    return time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(ts))
# -------------------------------------------


# ====================================
# SECTION A — Konfiguration (oben editierbar)
# ====================================
DEFAULT_VAULT_NAME = "vault.pwm"        # Standard-Dateiname, liegt neben Skript/EXE
DEFAULT_CONFIG_FILENAME = "pwmanager_config.json"  # Name der Standard-Konfigurationsdatei

# Pfad zur aktuell geladenen Konfigurationsdatei (falls vorhanden).
# Wird gesetzt, wenn eine Konfiguration angewendet wird. Wenn keine externe
# Konfiguration verwendet wird, bleibt der Wert None.
ACTIVE_CONFIG_PATH: Optional[Path] = None
AUTOLOCK_MINUTES = 5                    # Sperrdauer in Minuten (kann hier angepasst werden)
KDF_N = 2 ** 15                         # scrypt N (Kosten). Erhöhen für mehr Sicherheit/Verzögerung
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 96                          # 96 bytes -> AES_key(32) | ChaCha_key(32) | MAC_key(32)
MIN_MASTER_PW_LEN = 12                  # Warnung wenn Master-PW kürzer
HMAC_ALG = "sha512"                     # HMAC Algorithmus
MAGIC = b"PWM3"                         # Dateiformat-Magic
# Dateiformat‑Version.
# Die Version bestimmt den Aufbau der verschlüsselten Tresor‑Datei. In dieser
# gehärteten Version wird Version 2 verwendet, um separate Schlüssel für das
# XOR‑Pad und den finalen HMAC abzuleiten. Ältere Tresore (Version 1) können
# damit nicht mehr geöffnet werden. Bitte lege bei Umstellung einen neuen
# Tresor an.
SALT_LEN = 16
NONCE_LEN = 12
CLIP_CLEAR_MS = 30 * 1000               # Clipboard leeren nach 30s in GUI
BACKUP_KEEP = 2                         # Anzahl Backup-Dateien (älteste löschen)
BACKUPS_ENABLED = True                  # Globale Option: Backups erstellen? True/False
SAFE_CLI_DEFAULT = False                # Standard: CLI-Erweiterungen wie Export erlaubt

# Steganographie-Marker und Längenfeldgröße.
# Beim Verstecken einer Datei in einer Cover-Datei werden die verschlüsselten
# Nutzdaten am Dateiende gefolgt von einem Längenfeld (big endian) und einem
# Marker abgelegt. Diese Konstanten definieren den Marker und die Größe des
# Längenfelds. Der Marker sollte eindeutig sein, um Kollisionen mit zufälligen
# Daten im Cover zu verhindern. Die Länge des Längenfelds (in Bytes) legt fest,
# wie viele Bytes zur Speicherung der verschlüsselten Nutzlastlänge genutzt
# werden. Eine größere Länge ermöglicht das Verstecken sehr großer Dateien.
STEGO_MARKER = b"PWMSTEGO3\x00\xff"
STEGO_LENGTH_LEN = 8

# ---------------------------------------------------------------------------
# Sprachoptionen
#
# FORCE_LANG erlaubt es, die Benutzeroberfläche auf eine bestimmte Sprache
# festzulegen. Erlaubte Werte sind 'de' für Deutsch oder 'en' für Englisch.
# Wenn FORCE_LANG leer bleibt, versucht der Passwortmanager, die Systemsprache
# automatisch zu erkennen. Dies ermöglicht eine lokale Anpassung der Sprache
# der GUI und der CLI ohne Codeänderungen.
FORCE_LANG = ""  # 'de' oder 'en' erzwingt die Sprache; leer = auto

# Der Parameter CURRENT_LANG wird zur Laufzeit gesetzt und bestimmt, ob
# deutsch ('de') oder englisch ('en') verwendet wird. Die Funktion
# init_language() initialisiert diese Variable beim Programmstart. Dieses
# Design stellt sicher, dass die Auswahl sowohl vor dem GUI‑Start als auch
# im CLI‑Modus funktioniert.
CURRENT_LANG: str | None = None

def detect_system_language() -> str:
    """
    Versucht, die Sprache des Betriebssystems zu ermitteln. Wenn die
    Standardsprache mit "de" beginnt, wird "de" zurückgegeben, ansonsten
    "en". Bei Fehlern fällt die Funktion auf Englisch zurück.

    Returns:
        str: "de" für Deutsch oder "en" für Englisch.
    """
    try:
        import locale  # lokaler Import, um die System-Locale abzufragen
        loc = locale.getdefaultlocale()[0]
        if loc and str(loc).lower().startswith("de"):
            return "de"
    except Exception:
        pass
    return "en"

def tr(de_text: str, en_text: str) -> str:
    """
    Gibt abhängig von CURRENT_LANG den deutschen oder englischen Text
    zurück. Diese Helferfunktion zentralisiert die Sprachumschaltung
    und erleichtert die Internationalisierung der Oberfläche.

    Args:
        de_text (str): Der deutsche Text.
        en_text (str): Der englische Text.
    Returns:
        str: Der Text passend zur aktuellen Sprache.
    """
    # Fallback zu Deutsch, wenn CURRENT_LANG noch nicht gesetzt ist
    lang = globals().get('CURRENT_LANG')
    return de_text if lang == 'de' else en_text

# Hilfe-Text je nach Sprache aus dem Modul-Docstring extrahieren.
# Diese Funktion trennt den zweisprachigen Docstring in einen deutschen
# und einen englischen Teil. Falls die Marker "Deutsch:" bzw. "English:"
# nicht gefunden werden, wird der gesamte Docstring zurückgegeben.
def get_help_text() -> str:
    """
    Liefert den Hilfe-Text passend zur aktuellen Sprache.

    Der Modul-Docstring enthält sowohl deutsche als auch englische Abschnitte.
    Diese Funktion versucht, nur den Teil in der gewählten Sprache
    zurückzugeben. Sie erkennt die Marker ``Deutsch:`` und ``English:`` und
    ignoriert den jeweils anderen Abschnitt. Darüber hinaus trennt sie
    gemischte Zeilen mit Slash (" / ") in der Mitte und gibt nur den
    entsprechenden Teil aus (z. B. ``"Speichern als / Save as"`` wird zu
    ``"Speichern als"`` auf Deutsch bzw. ``"Save as"`` auf Englisch).

    Falls keine Marker gefunden werden, oder Zeilen außerhalb eines
    Sprachabschnitts stehen, werden diese Zeilen dennoch übernommen. Dadurch
    bleiben allgemeine Hinweise (wie Dateinamen oder Codebeispiele) erhalten.

    Returns:
        str: Hilfe-Text, in dem nur die ausgewählte Sprache erscheint.
    """
    doc = __doc__ or ""
    lines = doc.splitlines()
    lang = globals().get('CURRENT_LANG') or 'de'
    current = None  # aktiver Abschnitt: 'de', 'en' oder None
    out_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        # Abschnittswechsel anhand Marker erkennen
        if stripped.startswith("Deutsch:"):
            current = 'de'
            # Marker selbst nicht aufnehmen
            continue
        if stripped.startswith("English:"):
            current = 'en'
            continue
        # Bestimme, ob die Zeile genommen wird: innerhalb des passenden Abschnitts
        # oder außerhalb beider Abschnitte (current is None).
        take_line = (current == lang) or (current is None)
        if not take_line:
            continue
        # Wenn eine gemischte Zeile vorliegt, die durch " / " getrennt ist,
        # wähle den Teil entsprechend der Sprache. Dies erlaubt, bilingual
        # formatierte Zeilen in eine einsprachige Hilfe zu zerlegen.
        if " / " in line:
            parts = [p.strip() for p in line.split("/")]
            # Teile könnten durch Schrägstrich ohne Leerzeichen getrennt sein; nutze
            # das erste Element für Deutsch, das letzte für Englisch.
            if len(parts) >= 2:
                selected = parts[0] if lang == 'de' else parts[-1]
                out_lines.append(selected)
                continue
        # In allen anderen Fällen die Zeile unverändert übernehmen
        out_lines.append(line)
    return "\n".join(out_lines).strip()

def init_language() -> None:
    """
    Initialisiert CURRENT_LANG anhand von FORCE_LANG oder der ermittelten
    System-Sprache. Zusätzlich werden die CLI-Menütexte angepasst,
    wenn Englisch ausgewählt ist. Diese Funktion sollte nach dem Laden
    der Konfiguration aufgerufen werden, bevor GUI oder CLI gestartet
    werden.
    """
    global CURRENT_LANG, MENU, OUTER_MENU
    # Bestimme gewünschte Sprache: zuerst FORCE_LANG aus Config lesen
    lang: str | None = None
    try:
        forced = globals().get("FORCE_LANG", "")
        if forced:
            forced_lower = str(forced).lower()
            if forced_lower in ("de", "en"):
                lang = forced_lower
    except Exception:
        lang = None
    # Wenn keine Sprache erzwungen wird, versuche System-Sprache
    if not lang:
        lang = detect_system_language()
    CURRENT_LANG = lang
    # Passe die CLI-Menüs basierend auf der aktuellen Sprache an.  Für Englisch
    # (CURRENT_LANG == 'en') verwenden wir die vordefinierten englischen Menüs.
    # Andernfalls stellen wir sicher, dass die deutschen Menüs verwendet
    # werden.  Dadurch können die Menüs nach einem Sprachewechsel auch
    # wiederhergestellt werden.
    global MENU, OUTER_MENU
    if CURRENT_LANG == "en":
        MENU = MENU_EN
        OUTER_MENU = OUTER_MENU_EN
    else:
        # Stelle die deutschen Menüs wieder her
        MENU = MENU_DE
        OUTER_MENU = OUTER_MENU_DE

# Farbkonfigurationen für CLI und GUI.
#
# Diese Variablen können über die Konfigurationsdatei angepasst werden.
# CLI-Farben verwenden ANSI-Steuersequenzen, z. B. '\033[40m' für
# schwarzen Hintergrund und '\033[32m' für grüne Schrift. GUI-Farben
# erwarten Hex-Codes (z. B. '#000000' für schwarz). Die Variablen
# werden leer gelassen, damit standardmäßig das systemeigene
# Erscheinungsbild verwendet wird. Möchte der Benutzer ein eigenes
# Farbschema definieren, kann er die Werte in der Konfigurationsdatei
# anpassen.
CLI_COLOR_ENABLED = False  # True aktiviert farbige CLI-Ausgabe. Wird über die Konfig gesetzt.
CLI_BG_COLOR = ""         # ANSI-Farbcodierung für CLI-Hintergrund (leer = Standard)
CLI_FG_COLOR = ""         # ANSI-Farbcodierung für CLI-Schriftfarbe (leer = Standard)
GUI_BG_COLOR = ""         # Hex-Code für GUI-Hintergrund (leer = Standard-Theme)
GUI_FG_COLOR = ""         # Hex-Code für GUI-Schriftfarbe (leer = Standard-Theme)
GUI_BUTTON_COLOR = ""     # Hex-Code für GUI-Buttons (leer = Standard-Theme)
# Schalter für den Hell/Dunkel-Umschalter im GUI.
# False = Button wird komplett ausgeblendet, True = Button anzeigen.
SHOW_LIGHT_DARK_TOGGLE = globals().get("SHOW_LIGHT_DARK_TOGGLE", False)


# Farben für Eingabefelder und Tabellenhintergründe.  In der hellen
# Standardeinstellung werden leichte Grautöne verwendet.  Diese
# Konstanten werden im Dunkelmodus dynamisch überschrieben (siehe
# toggle_dark_mode).  Verwende diese Variablen anstelle von
# Hardcodes wie "#f5f5f5" oder "#f9f9f9", damit das Farbschema
# konsistent bleibt.
ENTRY_BG_COLOR = "#f5f5f5"
TABLE_BG_COLOR = "#f9f9f9"

# Farbe für dünne Gitterlinien in Tabellen.  Diese Farbe ist ein
# dezentes Grau, sodass sie sowohl im hellen als auch im dunklen
# Farbschema sichtbar bleibt, ohne zu stark hervorzutreten.
# Farbe für dünne Gitterlinien in Tabellen.
GRID_LINE_COLOR = "#a0a0a0"  # Grau für Spaltentrenner
# Wenn dir das immer noch zu dezent ist, kannst du auch z.B. "#808080" oder "#606060" nehmen.

def add_vertical_grid_to_treeview(tv: 'ttk.Treeview') -> None:
    """
    Zeichnet senkrechte Spaltentrenner über eine Treeview.
    Wird vor allem im Detail-Fenster genutzt.
    """
    import tkinter as _tk

    # Canvas auf der Treeview
    canvas = _tk.Canvas(tv, highlightthickness=0, bd=0, bg="")
    tv._grid_canvas = canvas  # Referenz speichern, damit es nicht weg-gc't wird

    def _draw_grid(_event=None) -> None:
        canvas.delete("gridline")
        try:
            tv.update_idletasks()
        except Exception:
            pass

        width = tv.winfo_width()
        height = tv.winfo_height()

        # Spaltenbreiten abfragen und senkrechte Linien ziehen
        x = 0
        for col in tv["columns"]:
            try:
                col_width = int(tv.column(col, width=None))
            except Exception:
                col_width = 0
            x += col_width
#            canvas.create_line(x-1, 0, x-1, height, fill=GRID_LINE_COLOR, tags="gridline")
            canvas.create_line(x-1, 0, x-1, height, fill=GRID_LINE_COLOR, width=1, tags="gridline")

    # Canvas über der Treeview platzieren
    try:
        canvas.place(in_=tv, relx=0, rely=0, relwidth=1, relheight=1)
        canvas.lift()
        canvas.configure(state="disabled")  # keine Maus-Events abfangen
    except Exception:
        pass

    _draw_grid()

    # Neu zeichnen bei Größen-/Inhaltsänderungen
    for seq in ("<Configure>", "<<TreeviewOpen>>", "<<TreeviewClose>>",
                "<<TreeviewSelect>>", "<Motion>", "<MouseWheel>", "<Button-4>", "<Button-5>"):
        try:
            tv.bind(seq, _draw_grid, add="+")
        except Exception:
            pass


def add_grid_to_treeview(tv: 'ttk.Treeview') -> None:
    """
    Ergänzt eine Treeview um dünne Linien zwischen den Spalten und Zeilen.

    Tkinter/ttk stellt von Haus aus keine Gitterlinien für die Treeview bereit.
    Um dennoch eine klare Tabellenstruktur zu erhalten, wird über der
    Treeview ein Canvas gelegt, das horizontale und vertikale Linien
    zeichnet. Diese Linien werden aktualisiert, wenn die Treeview ihre
    Größe ändert oder wenn sich deren Inhalte ändern. Das Canvas ist
    deaktiviert, damit es keine Maus‑Events abfängt.

    Args:
        tv: Die zu erweiternde Treeview.
    """
    import tkinter as _tk  # lokale Einbindung, damit in anderen Kontexten tk verfügbar ist
    # Canvas zur Darstellung der Gitterlinien anlegen
    canvas = _tk.Canvas(tv, highlightthickness=0, bd=0, bg="")
    # Referenz am Treeview speichern, damit das Canvas nicht vom GC gesammelt wird
    tv._grid_canvas = canvas
    def _draw_grid(event=None) -> None:
        """Zeichnet die Gitterlinien neu."""
        canvas.delete("gridline")
        # Größe ermitteln
        try:
            tv.update_idletasks()
        except Exception:
            pass
        width = tv.winfo_width()
        height = tv.winfo_height()
        # Vertikale Linien entsprechend den Spaltenbreiten zeichnen
        x = 0
        for col in tv["columns"]:
            try:
                col_width = int(tv.column(col, width=None))
            except Exception:
                col_width = 0
            x += col_width
            # -1 Pixel Korrektur, damit die Linie genau an der Kante liegt
            #canvas.create_line(x-1, 0, x-1, height, fill=GRID_LINE_COLOR, tags="gridline")
            canvas.create_line(x-1, 0, x-1, height, fill=GRID_LINE_COLOR, width=1, tags="gridline")
        # Horizontale Linien unterhalb jeder Zeile zeichnen
        for item in tv.get_children(""):
            try:
                bbox = tv.bbox(item)
            except Exception:
                bbox = None
            if bbox:
                y = bbox[1] + bbox[3] - 1  # untere Kante der Zeile
                #canvas.create_line(0, y, width, y, fill=GRID_LINE_COLOR, tags="gridline")
                canvas.create_line(0, y, width, y, fill=GRID_LINE_COLOR, width=1, tags="gridline")
    # Canvas über der Treeview platzieren und deaktivieren, damit es keine Events abfängt
    try:
        canvas.place(in_=tv, relx=0, rely=0, relwidth=1, relheight=1)
        canvas.lift()
        canvas.configure(state="disabled")
    except Exception:
        pass
    # Initiale Linien zeichnen
    _draw_grid()
    # Treeview-Ereignisse an das Neuzeichnen binden
    for seq in ("<Configure>", "<<TreeviewOpen>>", "<<TreeviewClose>>", "<<TreeviewSelect>>", "<Motion>", "<MouseWheel>", "<Button-4>", "<Button-5>"):
        try:
            tv.bind(seq, _draw_grid, add="+")
        except Exception:
            pass

# --- Hardening-Schalter ---
# Export in Klartext erfordert eine deutliche Bestätigung
REQUIRE_EXPLICIT_EXPORT_CONFIRM = True

# Clipboard: Auto-Clear (GUI ist schon konfiguriert), CLI zusätzlich aktivieren
CLI_CLIPBOARD_CLEAR_SECONDS = 30

# Audit-Log: sensible Details optional schwärzen + Logrotation
AUDIT_REDACT = True
AUDIT_MAX_BYTES = 2 * 1024 * 1024  # 2 MiB
AUDIT_BACKUPS_TO_KEEP = 3          # Rotationskopien

# Strenger "Safe Mode": export/clipboard/stego in CLI und GUI sperren (kannst du manuell im Code enforce'n)
HARDENED_SAFE_MODE = True


# Werbehinweis und Programm-Icon.
#
# Die folgenden Konstanten definieren den Text und den Link für den
# Telegram‑Kanal, der im GUI an mehreren Stellen angezeigt wird. Zudem
# enthält ICON_PNG_BASE64 ein einfaches 32×32‑PNG‑Symbol (Schlüsselsymbol),
# das automatisch als Fenster‑Icon gesetzt wird. Wird der Icon-Support auf
# einem System nicht unterstützt, bleibt das Standard-Icon bestehen.
# Personalisierte Telegram-Nachricht und Link.
# TELEGRAM_MESSAGE ist die sichtbare Aufforderung im GUI, um auf den Telegram‑Kanal
# hinzuweisen. TELEGRAM_LINK ist der sichtbare Text des Links. Um den Link
# anzupassen, ohne den sichtbaren Text zu ändern, setze TELEGRAM_TARGET unten.
#
# SHOW_TELEGRAM_AD steuert, ob der Telegram‑Hinweis in der GUI angezeigt wird.  Wird
# dieser Wert in der Konfigurationsdatei auf ``false`` gesetzt, so werden die
# entsprechenden Widgets nicht erzeugt.  Standardmäßig ist die Werbung aktiv.
TELEGRAM_MESSAGE = "Schau doch mal in meinem Telegram-Kanal vorbei:"
TELEGRAM_LINK = "t.me/WitzigLustigKomisch"
# Tatsächliche Ziel‑URL für den Telegram‑Link. Diese wird geöffnet, wenn der
# Benutzer auf TELEGRAM_LINK klickt.
TELEGRAM_TARGET = "https://t.me/+lk64Nq48NndkZGZi"
# Standardwert für die Anzeige der Telegram-Werbung.  Kann in der Konfiguration
# überschrieben werden (siehe CONFIG_KEYS).  Bei False werden keine
# Werbe‑Widgets erzeugt.
SHOW_TELEGRAM_AD = True

#
# Zusätzliche Sicherheit: Schlüsseldatei und Gerätebindung
#
# KEYFILE_PATH: Optionaler Pfad zu einer Schlüsseldatei (z. B. auf einem USB‑Stick).
# Wenn gesetzt, wird der Inhalt der Datei vor der KDF als "Pepper" in die
# Schlüsselableitung einbezogen. Dadurch erhöht sich die Entropie erheblich,
# und der Tresor ist ohne die Schlüsseldatei praktisch wertlos für Angreifer.
# Das Dateiformat bleibt unverändert – die KDF‑Eingabe wird lediglich um das
# gehashte Keyfile ergänzt.  Ist dieser Wert leer, wird wie bisher nur das
# Master‑Passwort verwendet.
KEYFILE_PATH = globals().get("KEYFILE_PATH", "")

# DEVICE_BIND: Aktiviert optional eine Bindung des Tresors an das aktuelle Gerät.
# Wenn wahr, wird neben dem Keyfile (sofern vorhanden) auch ein gerätespezifischer
# Wert (z. B. /etc/machine-id oder Hostname) in die Schlüsselableitung gemischt.
# So kann selbst bei Kenntnis von Master‑Passwort und Schlüsseldatei kein Tresor
# auf einem anderen System geöffnet werden.  Diese Option kann in der
# Konfigurationsdatei überschrieben werden.  Standardmäßig ist die Bindung
# deaktiviert, damit Tresore zwischen Systemen transferiert werden können.
DEVICE_BIND = globals().get("DEVICE_BIND", False)

# REQUIRE_KEYFILE: Optional erzwingt die Verwendung des Keyfiles.
# Wenn diese Option aktiviert ist (True), dann wird beim Laden und Speichern
# geprüft, ob ein KEYFILE_PATH gesetzt ist und die Datei existiert. Ist der
# Pfad gesetzt, die Datei jedoch nicht vorhanden, wird der Vorgang mit einem
# Fehler abgebrochen. Dies erlaubt es, zwischen einem komfortablen Modus
# (Keyfile optional) und einem strengen Modus (Keyfile zwingend erforderlich)
# zu wählen.
REQUIRE_KEYFILE = globals().get("REQUIRE_KEYFILE", False)

# Anzahl der zusätzlichen Verschlüsselungsschichten über der Triple‑Verschlüsselung.
# Jede Schicht fügt ein neues Salt, Nonce, XOR‑Pad und HMAC hinzu und verschleiert den
# v3‑Blob mehrfach.  Ein Wert von 0 bedeutet, dass keine weitere Schicht verwendet wird
# (Dateiformatversion 3).  Ein Wert von 1 erzeugt Version 4 (eine zusätzliche
# XOR/HMAC‑Schicht), 2 ergibt Version 5 (zwei Schichten) und so weiter.  Dieser
# Parameter kann in der Konfigurationsdatei angepasst werden, um die Sicherheit weiter
# zu erhöhen.  Es gibt kein festes Maximum – mehr Schichten führen jedoch zu größeren
# Dateien und höherem CPU‑Aufwand.  Vor Version 2.6 wurde der Wert auf maximal 10
# geklemmt, um übermäßig große Dateien zu verhindern.  Da die Dokumentation jedoch
# ausdrücklich kein Maximum vorsieht, wird hier bewusst keine Obergrenze mehr gesetzt.
EXTRA_ENCRYPTION_LAYERS = 5
# Clamp negative Werte auf 0, belasse ansonsten den Wert unverändert.  Eine Obergrenze
# wird nicht erzwungen.  Achtung: Sehr hohe Werte können die Dateigröße massiv
# vergrößern und die Laufzeit verlängern.
try:
    _tmp_layers = int(EXTRA_ENCRYPTION_LAYERS)
    if _tmp_layers < 0:
        _tmp_layers = 0
    EXTRA_ENCRYPTION_LAYERS = _tmp_layers
except Exception:
    EXTRA_ENCRYPTION_LAYERS = 0

# Die Dateiformat‑Version wird aus der Anzahl der zusätzlichen Schichten abgeleitet.
# Sie entspricht ``3 + EXTRA_ENCRYPTION_LAYERS``.  Der Wert 3 bedeutet, dass nur die
# Triple‑Verschlüsselung verwendet wird (keine Zusatzschicht).  4 steht für eine
# zusätzliche XOR/HMAC‑Schicht, 5 für zwei usw.  Dieser Wert wird automatisch in
# der verschlüsselten Datei gespeichert und sollte nicht manuell verändert werden.
VERSION = 3 + int(EXTRA_ENCRYPTION_LAYERS)

# Basis‑64 kodiertes PNG‑Icon (16×16) für das Programmfenster. Dieses einfache
# Vorhängeschloss‑Symbol erscheint in der Titelleiste und in der Taskleiste,
# wodurch das Zahnrad‑Standardicon ersetzt wird. Das Bild wurde stark
# komprimiert, um die Skriptgröße gering zu halten. Sie können den Wert
# ersetzen, sofern Sie ein eigenes, base64‑kodiertes PNG verwenden möchten.
# Farbiges Programm-Icon als 32×32 PNG, base64‑kodiert. Dieses Bild ersetzt das
# ursprüngliche schwarz-weiße Symbol. Sie können den String durch ein eigenes
# base64‑kodiertes PNG ersetzen, solange die Bildgröße 32×32 Pixel beträgt.
ICON_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAGcklEQVR4nL2XS2wdVxnHf+fMzL1zr1/xI3biOI7zsp00TZTQBCWkSIRS0UWREBWvqq5ArKArxJING6TCArFgA0IgggRSVAQVBUrTtDSiCe4ibhK3dtPYrhPn2o5rX7uxfed1PhZzn77jNKoQ32aOvnPmfP/v/R0VBIEYY1BKUU0iUuaV1tU8BFD/g3O+5wu1sv8vJAJKgf0gwsVExKpUSCkNStdqe1+BtedKS/tjJCMorLSLpmxNACIDJiwUORsAVB0sLxMwCmAnaSAAEqFtF63go6mLLE+cx1+eQlkpMlsPsWX/F8l0DBCFIWKi2CKl/1VFnqJk7uQYU77vS7Vm8WaElXLxFsaYfOm7rN96jUwG0q6DiGF9LcIP07Qd+RY9j/0UbWeRKIAiiI33VQuEiv9FqA9CEYNlp1mbHWbsd4/TkvXoPfAwbvMWsO349sBjeWGeqWvX0Z2fZuDpf6DsBhBTBvFxVAKpfN+vRJcIaIXxlhn95WHaGgr0HXkETMTq4gIfLc2jtcWWzh2kmpsxXsDom/8itftL7HvqL0Shh1I60QKbUQ1ckQjLdsi9+TyOn6Pv0FEk8Ji8PsLolavcXe8il89y9fIw85MTaMem/9gJVsZeZPnm37FS6WLGJGucRJUgFEFph8hfJ//uH9ixqwdSDndG32FhSTMwdJHGnadBDAtv/5bJv34HN5OheXsPre1p7o78itb9TxBRX1ZKPk/i6XJgIGjbprB4k2jtDs1tXUihwPzMLDsf+zEtvacJvTWiMKDr6Ldpf/ibzE6Ng9K0tG+lcPcaYRCgtI3IxprBJrwaFwgoMP4KSgTLdoh8D1GK7LZPEUZBnGomxJiA7Pbj+F4IxmA7KSRcjzNhE+/Xp2HRAlVHEAHLbUOURRj4WGkXhbA68x9sywEMaAetHe7NXCbl2mBp/MIaymlC2ykEkwhggwHKLtEVhkLCkHTrbqzGneQXcqi0S1dPNzOv/ZD81OtYTgat4c7wL1i6/ke29w1CFLF0d4GmnY+ibQs2CcLEMJSaSqgQE+CkM7Qdepbcv39E164Buvf0E/ij3Pj950hvPYjxVwnyH7BncC9NHVtZX/yQ5XxI/8GvoVCIGLSur/D3rYR1jjEe7/76GG50m/5HToGG9cVFVhZn0dpmS2c3TmMjBAFRGHHj2lWCdD/7n/4bTraTyF9HbQBRnQmlOiEiKM/zRW2ohNpOESy9x9jZx0kF0/QePExTWwc46fh3r8Di7AzpTAMNba0YP2DsrcuE2YMMDL2KlenABAWUtmo9kBCftRYonTUROuUSreaYfvkHLI+fI2UFpNyifA9ClUWCNQaOHKapvQMThoy9dYkwM8jA0AWsTDsm8GpBJFAigBIIZaexLMXq3Dvcm36DwtIE2kqR6RikZc8Z5od/Tu6Nn3Dg+EYQBxgYOl9lCTvRBQDK8zxJaseq6DgRg5VyUVUtVoiDXVtw+5XvM3fpZwweO0JT6xZEYGz4EkF2kIFnXi1aorBpTCS24zpriIk7XaWHFUuZIZXOcOPcl1ke+zNHHz2NZSkMKrZE9qE4Jty2mpiotGNBFwvg/f2kNErbKO0UvxYIWOkMi2N/Iv/+BXr29qFtDVqjtWLwxEnstVHGz36eqPAhluPGilAUTpya+pMMpCIRluOwlrvC++e+Qu+uVrbt3YtCMf3eOPn5ObRtc+DEKezVUcbPfoFgdQ6tdRlEiR5seqi3SdxIrBTadgmCABHFxOjb5HJ5Jm/eYmV+DqVg8Pgp9PIVbr38PZTlABLnP0UX1HQpKWlYrW09DzQmCnA7H2L/N15idmaRkVfOs1Jo5uAz5xG7g6BwL3ZHJkP3vn2sTF/EBD5K2WX/K6Wwax4SRXdUJ4Wq4pUjV8UgIq9AY98Z+ocusDDyAttOPcf0P5/DlRztuz5LYTlPfnGCuZsf0DL4FNpJEQUFQJcfJnYpGKpps1m/nMclINoi8gpkd5ykr+dkbBttEfg++bsLTF4bwbi9tB56lu4zzyNRCKjiAERCL3hAqi0qEjNMBJaNUsLkC19l4cqLbD3xdXY/+Ru04xKFBjFhnWKfCEAtmOpx26AtB4kCVm9fpqH3MyilMaEHSte8HWLwm1TCukMPxCwBMiil0Y6DCYLkgZCEmXAzStyt6Z71b0YRIfIL8f4m9ysVK1KThqV1Mi9ZaGWorewppVDKqmBNGoYkLsH/BSzNW8d19YDoAAAAAElFTkSuQmCC"
)

# Anzahl der Tage, nach denen eine Schlüsselrotation empfohlen wird.
# Wenn der Tresor länger als diese Anzahl von Tagen nicht mehr gespeichert
# wurde, zeigt das Programm beim Öffnen eine Warnung an. Ein Wert von 0
# deaktiviert die Warnung. Dieser Mechanismus dient dazu, an die regelmäßige
# Neuerzeugung der internen Schlüssel (Re-randomizing) zu erinnern.
ROTATION_WARNING_DAYS = 180

# Automatische Schlüsselrotation nach einer gewissen Anzahl von Tagen.
# Wenn diese Zahl größer als 0 ist, prüft das Programm beim Entsperren des
# Tresors, ob der Zeitpunkt der letzten Aktualisierung (``vault.updated_at``)
# oder das Änderungsdatum der Tresor-Datei älter ist als die angegebene
# Anzahl von Tagen. Ist dies der Fall, wird der Tresor sofort neu
# verschlüsselt (Re‑Randomizing) und gespeichert. Ein Wert von 0 deaktiviert
# die automatische Schlüsselrotation vollständig.
AUTO_ROTATION_DAYS = 0

# Mindestgröße des Tresors in Kilobyte (KiB).
# Wenn der verschlüsselte Tresor kleiner als dieser Wert ist, fügt das
# Programm beim Speichern zufällige Daten als Padding ein, um die
# Dateigröße zu vergrößern. Dieser Mechanismus kann verwendet werden,
# um sehr kleine Tresore schwerer von zufälligen Daten zu unterscheiden.
# Ein Wert von 0 deaktiviert das Padding vollständig.
MIN_VAULT_SIZE_KB = 0

# KDF-Algorithmusauswahl: 'scrypt' oder 'argon2'. Standard ist 'argon2'.
# In dieser gehärteten Version wird Argon2 als Vorgabe gewählt, da es
# gegenüber GPU‑basierten Angriffen deutlich besser schützt. Die Parameter
# können in der Konfiguration angepasst werden. Falls Argon2 nicht verfügbar
# ist, wird automatisch auf scrypt zurückgefallen.
KDF_MODE = "argon2"
# Argon2-Parameter: nur relevant, wenn KDF_MODE='argon2'.
# Die gewählten Werte nutzen einen hohen Speicherbedarf und eine erhöhte
# Iterationsanzahl, um Brute‑Force‑Angriffe weiter zu erschweren. Beachte,
# dass ein hoher Speicherverbrauch (hier 256 MiB) auf Geräten mit wenig
# Arbeitsspeicher zu Problemen führen kann. Passe die Parameter gegebenenfalls
# in der Konfigurationsdatei an.
ARGON2_TIME = 3
# Speicher in Kibibyte: 262144 KiB = 256 MiB. Je höher dieser Wert,
# desto größer der Aufwand für Passwort-Hacker. Für Geräte mit wenig RAM
# kann dieser Wert reduziert werden.
ARGON2_MEMORY = 262144
# Parallelität (Anzahl Threads). Die meisten Systeme kommen mit 4 gut zurecht.
ARGON2_PARALLELISM = 4

# Audit-Logging: Wenn aktiviert, werden Aktionen wie Erstellen, Ändern, Löschen
# oder Exportieren eines Eintrags in einer Logdatei protokolliert.
AUDIT_ENABLED = False
AUDIT_LOG_FILE = "audit.log"

# ----------------------------------------------------
#  Konfigurations-Management
#
#  Der Passwortmanager ermöglicht das Überschreiben der standardmäßigen
#  Konfigurationsparameter über eine externe JSON-Datei. Dies erleichtert das
#  Anpassen der Parameter auch, wenn das Programm zu einer EXE kompiliert
#  wurde. Mit der Funktion ``apply_config`` werden globale Variablen je nach
#  Inhalt der Konfigurationsdatei aktualisiert. Die Funktion ``load_config_file``
#  legt bei Bedarf eine neue Datei mit den aktuellen Standardwerten an.

# Liste der Konfigurationsvariablen, die extern überschrieben werden dürfen.
CONFIG_KEYS = [
    "AUTOLOCK_MINUTES",
    "KDF_N",
    "KDF_R",
    "KDF_P",
    "KDF_DKLEN",
    "MIN_MASTER_PW_LEN",
    "BACKUP_KEEP",
    "BACKUPS_ENABLED",
    "SAFE_CLI_DEFAULT",
    "KDF_MODE",
    "ARGON2_TIME",
    "ARGON2_MEMORY",
    "ARGON2_PARALLELISM",
    "AUDIT_ENABLED",
    "AUDIT_LOG_FILE",
    "CLI_COLOR_ENABLED",
    "CLI_BG_COLOR",
    "CLI_FG_COLOR",
    "GUI_BG_COLOR",
    "GUI_FG_COLOR",
    "GUI_BUTTON_COLOR",
    "ROTATION_WARNING_DAYS",
    "AUTO_ROTATION_DAYS",
    "MIN_VAULT_SIZE_KB",
    "FORCE_LANG",
    # Steuerung, ob der Telegram-Hinweis angezeigt wird.  True = anzeigen
    # False = ausblenden
    "SHOW_TELEGRAM_AD",

    # Steuerung, ob der Hell/Dunkel-Umschalter angezeigt wird
    "SHOW_LIGHT_DARK_TOGGLE",

    # Anzahl zusätzlicher Verschlüsselungsschichten (jenseits der Triple‑Verschlüsselung).
    # 0 = nur Triple-Verschlüsselung (Version 3), 1 = eine zusätzliche Schicht (Version 4),
    # 2 = zwei Schichten (Version 5) usw.
    "EXTRA_ENCRYPTION_LAYERS",

    # Pfad zu einer zusätzlichen Schlüsseldatei (Keyfile).  Wenn gesetzt, wird der
    # Inhalt der Datei vor der Passwortableitung als "Pepper" in die KDF eingemischt.
    "KEYFILE_PATH",
    # Gerätebindung: Wenn true, wird zusätzlich ein gerätespezifischer Wert in die
    # Schlüsselableitung einbezogen.  Dadurch können Tresore nur auf dem
    # ursprünglichen Gerät geöffnet werden.  False belässt das bisherige Verhalten.
    "DEVICE_BIND",

    # Striktes Keyfile: Wenn true und KEYFILE_PATH gesetzt ist, muss die
    # Schlüsseldatei beim Laden und Speichern existieren. Fehlt die Datei,
    # bricht das Programm mit einem Fehler ab. Dies erzwingt die Nutzung
    # des Keyfiles.
    "REQUIRE_KEYFILE",
]

# Beschreibungstexte für die einzelnen Konfigurationsparameter. Diese Erklärungen
# werden beim Erstellen einer neuen Konfigurationsdatei als Kommentare in die
# Datei geschrieben. So kann der Benutzer nachvollziehen, wofür jeder Wert
# zuständig ist und welche Anpassungen möglich sind. JSON unterstützt keine
# Kommentare, daher beginnen diese Zeilen mit einem '#' und werden beim
# Einlesen ignoriert.
CONFIG_EXPLANATIONS: Dict[str, str] = {
    "AUTOLOCK_MINUTES": "Sperrdauer in Minuten bis der Tresor bei Inaktivität automatisch gesperrt wird.",
    "KDF_N": "scrypt: CPU-/Speicher-Kostenparameter N (höher = sicherer, aber langsamer)",
    "KDF_R": "scrypt: Blockgröße r (typischerweise 8)",
    "KDF_P": "scrypt: Parallelitätsfaktor p (typischerweise 1)",
    "KDF_DKLEN": "Länge des abgeleiteten Schlüssels in Byte (96 für drei 32-Byte-Schlüssel)",
    "MIN_MASTER_PW_LEN": "Mindestlänge des Master-Passworts. Eine Warnung erfolgt, wenn das Passwort kürzer ist.",
    "BACKUP_KEEP": "Anzahl der Backup-Dateien, die aufbewahrt werden sollen.",
    "BACKUPS_ENABLED": "Erstellt vor jedem Speichern eine Backup-Datei (True/False)",
    "SAFE_CLI_DEFAULT": "Standardwert für den sicheren CLI-Modus (Exports deaktivieren)",
    "KDF_MODE": "Verwendeter KDF-Algorithmus: 'argon2' (Standard) oder 'scrypt'",
    "ARGON2_TIME": "Argon2: Anzahl der Iterationen (time_cost). Höhere Werte erhöhen die Sicherheit und die Dauer der Schlüsselableitung.",
    "ARGON2_MEMORY": "Argon2: Speicherbedarf in KiB (memory_cost). Standard ist 262144 (256 MiB) zur Erschwerung von Brute‑Force‑Angriffen. Reduziere bei knappem RAM.",
    "ARGON2_PARALLELISM": "Argon2: Anzahl der Parallelthreads (parallelism)",
    "AUDIT_ENABLED": "Audit-Logging einschalten (True/False)",
    "AUDIT_LOG_FILE": "Pfad zur Audit-Logdatei, in die Aktionen protokolliert werden.",
    "CLI_COLOR_ENABLED": "Aktiviert die Farbgestaltung im CLI (True/False). Wenn True, werden Farbcodes für Hintergrund und Schrift verwendet.",
    "CLI_BG_COLOR": "ANSI-Farbcodierung für den CLI-Hintergrund. Standard ist '\033[40m' (schwarz).",
    "CLI_FG_COLOR": "ANSI-Farbcodierung für die CLI-Schriftfarbe. Standard ist '\033[32m' (grün).",
    "GUI_BG_COLOR": "Hex-Code für die Hintergrundfarbe der GUI (z. B. '#000000' für schwarz).",
    "GUI_FG_COLOR": "Hex-Code für die Schriftfarbe der GUI (z. B. '#00FF00' für grün).",
    "GUI_BUTTON_COLOR": "Hex-Code für die Hintergrundfarbe der Schaltflächen in der GUI (z. B. '#444444' für grau).",
    "ROTATION_WARNING_DAYS": "Schwelle in Tagen, nach der beim Laden des Tresors eine Schlüsselrotation empfohlen wird (0 = aus).",
    "AUTO_ROTATION_DAYS": "Automatische Schlüsselrotation nach dieser Anzahl von Tagen (0 = deaktiviert). Wenn der Tresor älter ist als diese Schwelle, wird er beim Entsperren automatisch neu verschlüsselt.",
    "MIN_VAULT_SIZE_KB": "Mindestgröße der Tresordatei in KiB. Wird die verschlüsselte Datei kleiner als dieser Wert, wird zufälliges Padding hinzugefügt (0 = kein Padding).",

    # Steuerung der Telegram-Werbung.  Setze diesen Wert auf "false" in der
    # Konfiguration, um den Telegram-Hinweis im GUI auszublenden.  Bei "true"
    # wird die Einladung standardmäßig angezeigt.
    "SHOW_TELEGRAM_AD": "Aktiviert die Anzeige des Telegram-Hinweises (True/False). False blendet den Hinweis aus.",

    "EXTRA_ENCRYPTION_LAYERS": "Zusätzliche Verschlüsselungsschichten jenseits der Triple-Verschlüsselung. 0 = keine Zusatzschicht (nur Triple‑Layer), 1 = eine Schicht (Version 4), 2 = zwei Schichten (Version 5) usw. Es gibt kein festes Maximum – jede zusätzliche Schicht erhöht die Dateigröße und den Zeitaufwand; Werte >20 sollten nur verwendet werden, wenn du genau weißt, was du tust.",

    # Neue Sicherheitsoptionen: Keyfile und Gerätebindung
    "KEYFILE_PATH": "Pfad zu einer optionalen Schlüsseldatei (Keyfile). Der Hash des Keyfiles wird zusammen mit dem Master-Passwort als KDF-Eingabe verwendet, wodurch der Tresor ohne Keyfile unbrauchbar wird. Leerer Wert = kein Keyfile.",
    "DEVICE_BIND": "Aktiviert die Bindung des Tresors an das aktuelle Gerät. Wenn true, wird ein gerätespezifischer Hash in die KDF eingemischt. Tresore sind dann nicht ohne das ursprüngliche Gerät öffnbar.",

    # Erklärung für die strikte Nutzung eines Keyfiles. Diese Option erzwingt,
    # dass beim Laden und Speichern eines Tresors ein Keyfile vorhanden sein muss,
    # sofern KEYFILE_PATH gesetzt ist. Fehlt die Datei, bricht das Programm mit
    # einer Fehlermeldung ab. Dies erlaubt eine paranoidere Nutzung, bei der
    # das Keyfile zwingende Voraussetzung ist.
    "REQUIRE_KEYFILE": "Erzwingt die Verwendung des Keyfiles, wenn KEYFILE_PATH gesetzt ist (True/False). Ist der Pfad gesetzt, die Datei existiert aber nicht, bricht das Programm mit einer Fehlermeldung ab.",

    # Spracheinstellung: Mit FORCE_LANG kann der Benutzer die Sprache der
    # Benutzeroberfläche erzwingen. "de" steht für Deutsch, "en" für Englisch.
    # Wenn dieser Parameter leer bleibt, wird die Sprache anhand der
    # System-Locale automatisch bestimmt.
    "FORCE_LANG": "Erzwingt die Sprache der Benutzeroberfläche ('de' für Deutsch, 'en' für Englisch). Leerer Wert = automatische Erkennung.",
}

def _default_config() -> Dict[str, object]:
    """Erzeugt ein Dict aller konfigurierbaren Parameter mit aktuellen Werten."""
    return {k: globals()[k] for k in CONFIG_KEYS}

def write_config_with_comments(cfg_path: Path, cfg: Dict[str, object]) -> None:
    """Schreibt eine Konfigurationsdatei im JSON-Format, ergänzt um
    Erklärungskommentare. Jede Zeile, die mit "#" beginnt, wird beim
    Einlesen ignoriert. Die Kommentare erläutern die Bedeutung der
    jeweiligen Konfigurationsparameter.

    ``cfg`` sollte ein Dict enthalten, dessen Keys in ``CONFIG_KEYS`` stehen.
    """
    lines = []
    # Allgemeine Kopfzeile der Konfigurationsdatei. Diese Kommentare werden beim
    # Einlesen ignoriert, dienen aber als Hilfestellung für den Benutzer. Sie
    # erklären, dass jede Zeile mit '#' ein Kommentar ist und nicht Teil des
    # JSON-Objekts. Der Benutzer kann die Werte hinter den Doppelpunkten
    # verändern, um die Konfiguration anzupassen.
    lines.append("# pwmanager Konfiguration")
    lines.append("# Jede Zeile, die mit '#' beginnt, ist ein Kommentar und wird beim Einlesen ignoriert.")
    lines.append("# Bearbeite die Werte nach dem Doppelpunkt, um Parameter wie KDF, Auto-Lock oder Audit-Logging zu ändern.")
    lines.append("{")
    # Iteriere über alle zulässigen Konfig-Keys in der festgelegten Reihenfolge
    for i, key in enumerate(CONFIG_KEYS):
        # Füge den Kommentar hinzu, falls vorhanden
        comment = CONFIG_EXPLANATIONS.get(key, "")
        if comment:
            # Kommentarzeilen beginnen mit '#'
            lines.append(f"    # {key}: {comment}")
        # JSON-Key und -Value serialisieren
        value = cfg.get(key, globals().get(key))
        # JSON-Darstellung des Wertes (z. B. True/False als true/false)
        value_repr = json.dumps(value, ensure_ascii=False)
        # Letztes Element ohne Komma
        comma = "," if i < len(CONFIG_KEYS) - 1 else ""
        lines.append(f"    \"{key}\": {value_repr}{comma}")
    lines.append("}")
    _secure_write_text(cfg_path, "\n".join(lines))

def load_config_file(cfg_path: Path) -> Dict[str, object]:
    """
    Läd eine JSON-Konfigurationsdatei. Wenn die Datei nicht existiert, wird
    sie mit den aktuellen Standardwerten erstellt und zurückgegeben. Die Werte
    werden nicht automatisch angewendet; nutze ``apply_config`` dafür.
    """
    try:
        if not cfg_path.exists():
            # Wenn die Datei nicht existiert, erstelle sie mit den aktuellen
            # Standardwerten und erläuternden Kommentaren. Die Kommentare
            # ermöglichen es dem Benutzer, die Bedeutung der einzelnen
            # Parameter zu verstehen.
            cfg = _default_config()
            write_config_with_comments(cfg_path, cfg)
            return cfg
        # Datei existiert: Lese den Inhalt ein und ignoriere Zeilen, die mit
        # '#' oder '//' beginnen (Kommentare). Dadurch können wir JSON mit
        # Kommentarzeilen laden. Leere Zeilen werden ebenfalls übersprungen.
        try:
            with open(cfg_path, encoding="utf-8") as f:
                lines = []
                for line in f:
                    stripped = line.lstrip()
                    if not stripped:
                        continue
                    if stripped.startswith("#") or stripped.startswith("//"):
                        continue
                    lines.append(line)
                # Füge eine Zeile ein, um eventuelle trailing commas zu entfernen
                json_data = "".join(lines)
            data = json.loads(json_data)
        except Exception:
            # Falls Parsing fehlschlägt, falle auf eine leere Dict zurück
            data = {}
        # Fallback: fehlende Keys durch Standardwerte ergänzen
        cfg = _default_config()
        for k in CONFIG_KEYS:
            if k in data:
                cfg[k] = data[k]
        return cfg
    except Exception:
        # Bei Fehler wird Standardkonfig zurückgegeben
        return _default_config()

def apply_config(cfg: Dict[str, object]) -> None:
    """
    Übernimmt die Werte aus ``cfg`` in die globalen Konfigurationsvariablen.
    Nur Keys aus CONFIG_KEYS werden berücksichtigt. Beachte, dass Änderungen
    kryptographischer Parameter (KDF_*) nicht rückwirkend auf bestehende
    Tresore wirken, sondern nur für neu angelegte Tresore gelten.
    """
    global AUTOLOCK_MINUTES, KDF_N, KDF_R, KDF_P, KDF_DKLEN, MIN_MASTER_PW_LEN, BACKUP_KEEP, BACKUPS_ENABLED, SAFE_CLI_DEFAULT
    for key, value in cfg.items():
        if key == "AUTOLOCK_MINUTES":
            AUTOLOCK_MINUTES = int(value)
        elif key == "KDF_N":
            KDF_N = int(value)
        elif key == "KDF_R":
            KDF_R = int(value)
        elif key == "KDF_P":
            KDF_P = int(value)
        elif key == "KDF_DKLEN":
            KDF_DKLEN = int(value)
        elif key == "MIN_MASTER_PW_LEN":
            MIN_MASTER_PW_LEN = int(value)
        elif key == "BACKUP_KEEP":
            BACKUP_KEEP = int(value)
        elif key == "BACKUPS_ENABLED":
            BACKUPS_ENABLED = bool(value)
        elif key == "SAFE_CLI_DEFAULT":
            SAFE_CLI_DEFAULT = bool(value)
        elif key == "KDF_MODE":
            # Nur 'scrypt' oder 'argon2' zulassen
            if str(value).lower() in ("scrypt", "argon2"):
                globals()["KDF_MODE"] = str(value).lower()
        elif key == "ARGON2_TIME":
            globals()["ARGON2_TIME"] = int(value)
        elif key == "ARGON2_MEMORY":
            globals()["ARGON2_MEMORY"] = int(value)
        elif key == "ARGON2_PARALLELISM":
            globals()["ARGON2_PARALLELISM"] = int(value)
        elif key == "AUDIT_ENABLED":
            globals()["AUDIT_ENABLED"] = bool(value)
        elif key == "AUDIT_LOG_FILE":
            globals()["AUDIT_LOG_FILE"] = str(value)
        elif key == "CLI_COLOR_ENABLED":
            globals()["CLI_COLOR_ENABLED"] = bool(value)
        elif key == "CLI_BG_COLOR":
            globals()["CLI_BG_COLOR"] = str(value)
        elif key == "CLI_FG_COLOR":
            globals()["CLI_FG_COLOR"] = str(value)
        elif key == "GUI_BG_COLOR":
            globals()["GUI_BG_COLOR"] = str(value)
        elif key == "GUI_FG_COLOR":
            globals()["GUI_FG_COLOR"] = str(value)
        elif key == "GUI_BUTTON_COLOR":
            globals()["GUI_BUTTON_COLOR"] = str(value)
        elif key == "ROTATION_WARNING_DAYS":
            try:
                days = int(value)
            except Exception:
                days = 0
            globals()["ROTATION_WARNING_DAYS"] = max(0, days)
        elif key == "AUTO_ROTATION_DAYS":
            # Auto-Rotation: akzeptiere Ganzzahlen oder Fließkommazahlen, 0 = deaktiviert
            try:
                days = float(value)
            except Exception:
                days = 0
            globals()["AUTO_ROTATION_DAYS"] = max(0, days)
        elif key == "MIN_VAULT_SIZE_KB":
            # Mindestgröße des Tresors in KiB. Negative Werte werden als 0 behandelt.
            try:
                size = int(value)
            except Exception:
                size = 0
            globals()["MIN_VAULT_SIZE_KB"] = max(0, size)
        elif key == "FORCE_LANG":
            # Übernehme Sprache aus der Konfiguration. Leerer String schaltet auf Auto-Erkennung.
            try:
                globals()["FORCE_LANG"] = str(value)
            except Exception:
                globals()["FORCE_LANG"] = ""
        elif key == "SHOW_TELEGRAM_AD":
            # Steuerung für die Anzeige der Telegram-Werbung
            try:
                globals()["SHOW_TELEGRAM_AD"] = bool(value)
            except Exception:
                globals()["SHOW_TELEGRAM_AD"] = True
        elif key == "SHOW_LIGHT_DARK_TOGGLE":
            # Steuerung für den Hell/Dunkel-Button
            try:
                globals()["SHOW_LIGHT_DARK_TOGGLE"] = bool(value)
            except Exception:
                globals()["SHOW_LIGHT_DARK_TOGGLE"] = False
        elif key == "EXTRA_ENCRYPTION_LAYERS":
            # Anzahl der zusätzlichen Verschlüsselungsschichten
            try:
                layers = int(value)

            except Exception:
                layers = 0
            # Stelle sicher, dass nur nicht-negative Werte erlaubt sind
            layers = max(0, layers)
            globals()["EXTRA_ENCRYPTION_LAYERS"] = layers
            # Aktualisiere die Dateiformat-Version entsprechend (Basis 3)
            globals()["VERSION"] = 3 + layers
            # Soft‑Warnung bei sehr vielen Schichten: Ab ~20 Schichten wird die Verarbeitung träge
            try:
                if layers > 20:
                    warn_msg = tr(
                        "WARNUNG: EXTRA_ENCRYPTION_LAYERS > 20 – Speichern und Laden kann sehr langsam werden.",
                        "WARNING: EXTRA_ENCRYPTION_LAYERS > 20 – saving and loading might be very slow."
                    )
                    try:
                        # Warnung in der CLI ausgeben
                        print(warn_msg)
                    except Exception:
                        pass
                    try:
                        # Wenn eine GUI aktiv ist, zusätzlich Dialog anzeigen
                        from tkinter import messagebox  # lokaler Import, falls tkinter verfügbar ist
                        messagebox.showwarning(tr("Zusätzliche Schichten", "Additional layers"), warn_msg)
                    except Exception:
                        pass
            except Exception:
                pass
        elif key == "KEYFILE_PATH":
            # Optionaler Pfad zu einer Schlüsseldatei. Ein leerer Wert deaktiviert die Nutzung des Keyfiles.
            try:
                globals()["KEYFILE_PATH"] = str(value)
            except Exception:
                # Bei ungültigen Typen belasse den vorhandenen Wert
                pass
        elif key == "DEVICE_BIND":
            # Aktiviere oder deaktiviere die Bindung an das aktuelle Gerät
            try:
                # Merke den alten Wert, um Änderungen zu erkennen
                old_bind = bool(globals().get("DEVICE_BIND", False))
                new_bind = bool(value)
                globals()["DEVICE_BIND"] = new_bind
                # Bei Aktivierung erstmals: deutliche Warnung ausgeben, da bestehende Tresore
                # nicht mehr geöffnet werden können, solange sie nicht neu verschlüsselt wurden.
                if (not old_bind) and new_bind:
                    warn_msg = tr(
                        "Gerätebindung aktiviert. Nur für neu erstellte Tresore; bestehende Tresore müssen vor Aktivierung neu verschlüsselt werden.",
                        "Device binding enabled. Only applies to newly created vaults; existing vaults must be re‑encrypted before enabling this option."
                    )
                    try:
                        print(warn_msg)
                    except Exception:
                        pass
                    try:
                        from tkinter import messagebox  # lokaler Import, falls tkinter verfügbar ist
                        messagebox.showwarning(tr("Gerätebindung", "Device binding"), warn_msg)
                    except Exception:
                        pass
            except Exception:
                pass
        elif key == "REQUIRE_KEYFILE":
            # Striktes Keyfile: bestimmt, ob ein gesetztes Keyfile zwingend vorhanden sein muss.
            try:
                globals()["REQUIRE_KEYFILE"] = bool(value)
            except Exception:
                pass
# Programmversionsnummer (für Anzeige oder interne Zwecke).
# Diese Version beschreibt die aktuelle Version dieses Skripts und kann bei
# zukünftigen Änderungen erhöht werden. Sie ist unabhängig von der
# Tresor-Dateiversion ("VERSION"), welche das Dateiformat beschreibt.
# Die Versionsnummer des Programms. Bitte bei jeder Erweiterung erhöhen.
# Erhöhe die Programmversionsnummer bei jeder Erweiterung.
# Diese Variable kennzeichnet die Versionsnummer dieses Programms. Sie wird bei
# jeder funktionalen Erweiterung oder Bugfix angehoben. Die Dateiformat-Version
# ("VERSION") bleibt davon unberührt und beschreibt das interne Layout der
# Tresor-Datei. Bitte aktualisiere diese Nummer, wenn du neue Features
# hinzufügst oder Fehler behebst.
# Programmversionsnummer (für Anzeige oder interne Zwecke).
# Diese Version wird bei jeder funktionalen Erweiterung oder
# sicherheitsrelevanten Änderung erhöht. Sie ist unabhängig vom
# Dateiformat ("VERSION"), das interne Layout der Tresor-Datei beschreibt.
# Programmversionsnummer. Diese sollte bei jeder Funktionsänderung oder
# Fehlerbehebung erhöht werden. Sie dient zur Anzeige in der Hilfe und in
# Audit‑Logs, hat aber keinen Einfluss auf das Dateiformat.
PROGRAM_VERSION = "2.8.5"

# ====================================
# SECTION B — Abhängigkeitsprüfung
# ====================================
REQUIRED = ["cryptography"]
OPTIONAL = ["pyperclip"]  # optional für CLI clipboard

def ensure_dependencies(interactive: bool = True) -> None:
    """
    Prüft ob benötigte Pakete vorhanden sind. Falls nicht und interactive=True wird
    gefragt, ob pip installiert werden soll. Bei 'Nein' wird das Programm abgebrochen.
    """
    import importlib
    missing = []
    for pkg in REQUIRED:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        # Liste fehlender Pakete übersetzen
        print(
            tr(
                "\n[!] Fehlende Python-Pakete: " + ", ".join(missing),
                "\n[!] Missing Python packages: " + ", ".join(missing),
            )
        )
        if not interactive:
            raise SystemExit(
                tr(
                    "Fehlende Pakete. Bitte manuell installieren.",
                    "Missing packages. Please install them manually.",
                )
            )
        ans = input(
            tr(
                "Fehlende Pakete automatisch installieren? (erfordert Internet) [j/N]: ",
                "Automatically install missing packages? (requires Internet) [y/N]: ",
            )
        ).strip().lower()
        # deutsch akzeptiert ja/j, englisch y/yes
        if ans in ("j", "y", "ja", "yes"):
            for pkg in missing:
                print(
                    tr(
                        f"Installiere {pkg} ...",
                        f"Installing {pkg} ...",
                    )
                )
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                except Exception as e:
                    print(
                        tr(
                            "Installation von {pkg} fehlgeschlagen: {err}",
                            "Installation of {pkg} failed: {err}",
                        ).format(pkg=pkg, err=e)
                    )
                    raise SystemExit(
                        tr(
                            "Bitte installiere die Abhängigkeiten manuell.",
                            "Please install the dependencies manually.",
                        )
                    )
        else:
            raise SystemExit(
                tr(
                    "Benötigte Abhängigkeiten fehlen. Abbruch.",
                    "Required dependencies missing. Aborting.",
                )
            )

# Run the check (interactive)
# # ensure_dependencies(interactive=True)  # entfernt: keine Auto-Installation beim Import  # entfernt: keine Auto-Installation beim Import

# Now safe to import cryptography primitives
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Optional import: try to use cryptography's Scrypt implementation when available.
# On systems where ``cryptography`` is not installed or cannot be installed
# (e.g. offline environments), we fall back to ``hashlib.scrypt`` with an
# increased ``maxmem`` parameter to avoid the default OpenSSL memory limit.
try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as _CryptoScrypt
except Exception:
    _CryptoScrypt = None

# Optional import: Argon2 KDF (via argon2-cffi). Wenn nicht vorhanden,
# kann dennoch die scrypt-KDF verwendet werden.
try:
    from argon2.low_level import hash_secret_raw, Type as _Argon2Type
    _HAS_ARGON2 = True
except Exception:
    _HAS_ARGON2 = False

# optional pyperclip for CLI clipboard support
try:
    import pyperclip
    _HAS_PYPERCLIP = True
except Exception:
    _HAS_PYPERCLIP = False

# Try import tkinter lazily later

# ====================================
# SECTION C — Dataclasses und Hilfsfunktionen
# ====================================
@dataclass
class Entry:
    """Ein einzelner Passwort-Eintrag innerhalb des Tresors.

    Zusätzlich zu den bisherigen Feldern enthält jeder Eintrag ein Feld
    "website", das die zugehörige Webseite oder IP-Adresse speichert. Dies
    erleichtert die Zuordnung eines Passworts zu einer bestimmten URL oder
    Maschine. Alle Felder sind als Strings definiert; Zeitstempel werden als
    Floats gespeichert.
    """
    id: str
    label: str
    username: str
    email: str
    password: str
    info: str
    website: str
    created_at: float
    updated_at: float

@dataclass
class Vault:
    entries: Dict[str, Entry]
    created_at: float
    updated_at: float

    @staticmethod
    def empty() -> "Vault":
        now = time.time()
        return Vault(entries={}, created_at=now, updated_at=now)

def exe_dir() -> Path:
    """Verzeichnis der laufenden Datei (Script oder EXE)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def default_vault_path() -> Path:
    return exe_dir() / DEFAULT_VAULT_NAME

def safe_filename(name: str) -> str:
    """Erzeugt einen Dateinamen-freundlichen String aus 'name'."""
    allowed = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filtered = ''.join(c for c in name if c in allowed)
    return filtered[:120] or "export"

def generate_password(length: int = 20) -> str:
    """Erzeugt ein starkes Passwort mit sicheren Zufallszahlen."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$_-+.^*?"
    return ''.join(secrets.choice(chars) for _ in range(max(8, min(128, length))))

# Neue Kurz-ID-Generation für Einträge
def generate_entry_id(existing: Dict[str, Entry]) -> str:
    """
    Erzeugt eine kurze, eindeutige ID für neue Einträge.

    Die ursprüngliche Implementierung verwendete ``secrets.token_hex(8)`` (16
    Hex-Zeichen), was bei der Eingabe in der CLI umständlich ist. Wir
    verwenden stattdessen 6 Hex-Zeichen (3 Bytes). Falls eine Kollision mit
    einer bereits existierenden ID auftritt, wird erneut generiert. Für Vaults
    mit wenigen Tausend Einträgen ist die Kollisionswahrscheinlichkeit
    vernachlässigbar.

    ``existing``: Mapping der bereits genutzten IDs.
    Returns: eine eindeutige kurze ID.
    """
    while True:
        new_id = secrets.token_hex(3)  # 6 Hex-Zeichen
        if new_id not in existing:
            return new_id

# Audit-Logging-Funktion

def _ensure_file_0600(path: str) -> None:
    try:
        if os.name == "posix" and os.path.exists(path):
            os.chmod(path, 0o600)
    except Exception:
        pass

def _rotate_audit_if_needed(path: str) -> None:
    try:
        if not os.path.exists(path):
            return
        size = os.path.getsize(path)
        if AUDIT_MAX_BYTES and size > int(AUDIT_MAX_BYTES):
            # rotiere: audit.log -> audit.log.1, ..., .N
            for i in range(AUDIT_BACKUPS_TO_KEEP - 1, 0, -1):
                older = f"{path}.{i}"
                newer = f"{path}.{i+1}"
                if os.path.exists(older):
                    try:
                        os.replace(older, newer)
                    except Exception:
                        pass
            try:
                os.replace(path, f"{path}.1")
            except Exception:
                pass
    except Exception:
        pass

def write_audit(action: str, details: str) -> None:
    """
    Gesichertes Audit-Log mit Rechtesetzung (0600), optionaler Redaction und Rotation.
    """
    if not AUDIT_ENABLED:
        return
    try:
        _rotate_audit_if_needed(AUDIT_LOG_FILE)
        red = details
        if AUDIT_REDACT:
            # nur Hash statt Inhalt schreiben
            red = hashlib.sha256(details.encode("utf-8")).hexdigest()[:16]
        line = f"{time.time()}|{action}|{red}\n"
        # Öffnen + Rechte
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        mode = 0o600 if os.name == "posix" else 0o666
        fd = os.open(AUDIT_LOG_FILE, flags, mode)
        try:
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as f:
                f.write(line)
        finally:
            _ensure_file_0600(AUDIT_LOG_FILE)
    except Exception:
        # niemals die App stoppen
        pass
# ====================================
# SECTION C1 — CLI Status Informationen
# ====================================

def _secure_write_text(path: Path, text: str, newline: bool=False):
    """
    Schreibt Text mit restriktiven Rechten (POSIX 0600). Auf Windows ohne POSIX-Rechte.
    """
    path = Path(path)
    if os.name == "posix":
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n" if newline else None) as f:
            f.write(text)
        try:
            os.chmod(str(path), 0o600)
        except Exception:
            pass
    else:
        with open(path, "w", encoding="utf-8", newline="\n" if newline else None) as f:
            f.write(text)

def print_cli_status(path: Path) -> None:
    """
    Gibt zur Laufzeit Informationen über die verwendete Tresor-Datei und
    die geladene Konfigurationsdatei aus. Diese Funktion wird beim Start
    der CLI aufgerufen, um dem Benutzer klar zu machen, welche Dateien
    verwendet werden und ob Standardwerte zum Einsatz kommen.

    ``path``: Pfad der Tresor-Datei, die geöffnet bzw. erstellt werden soll.
    """
    # Bestimme Tresor-Status
    try:
        def_vault = default_vault_path()
    except Exception:
        def_vault = None
    if def_vault and Path(path).resolve() == def_vault.resolve():
        # Standard-Tresor: unterscheide vorhanden/nicht vorhanden
        if path.exists():
            print(
                tr(
                    f"Standard-Tresor-Datei: {path} (vorhanden)",
                    f"Default vault file: {path} (present)",
                )
            )
        else:
            print(
                tr(
                    f"Standard-Tresor-Datei: {path} (wird bei Bedarf angelegt)",
                    f"Default vault file: {path} (will be created if needed)",
                )
            )
    else:
        # Externe Tresor-Datei
        if path.exists():
            print(
                tr(
                    f"Externe Tresor-Datei: {path}",
                    f"External vault file: {path}",
                )
            )
        else:
            print(
                tr(
                    f"Externe Tresor-Datei: {path} (wird bei Bedarf angelegt)",
                    f"External vault file: {path} (will be created if needed)",
                )
            )
    # Bestimme Konfig-Status
    try:
        active_cfg = globals().get("ACTIVE_CONFIG_PATH")
        default_cfg = exe_dir() / DEFAULT_CONFIG_FILENAME
        if not active_cfg:
            if default_cfg.exists():
                print(
                    tr(
                        "Keine gültige externe Konfiguration geladen – Standardwerte werden verwendet.",
                        "No valid external configuration loaded – using defaults from script.",
                    )
                )
            else:
                print(
                    tr(
                        "Keine Konfiguration gefunden – es werden die im Skript hinterlegten Werte verwendet.",
                        "No configuration found – using values embedded in the script.",
                    )
                )
        elif Path(active_cfg).resolve() == default_cfg.resolve():
            print(
                tr(
                    f"Standard-Konfigurationsdatei geladen: {active_cfg}",
                    f"Default configuration file loaded: {active_cfg}",
                )
            )
        else:
            print(
                tr(
                    f"Externe Konfigurationsdatei geladen: {active_cfg}",
                    f"External configuration file loaded: {active_cfg}",
                )
            )
    except Exception:
        print(
            tr(
                "Konfigurationsstatus konnte nicht ermittelt werden.",
                "Could not determine configuration status.",
            )
        )

# ------------------------------------
# SECTION C2 — Schlüsselrotations-Warnungen
# ------------------------------------
def maybe_warn_rotation(vault: Vault) -> Optional[str]:
    """
    Prüft, ob der Tresor seit einer konfigurierten Zeit (``ROTATION_WARNING_DAYS``)
    nicht mehr gespeichert wurde. Wenn die Differenz zwischen dem aktuellen
    Zeitpunkt und dem Zeitstempel ``vault.updated_at`` größer ist als der
    in der Konfiguration angegebene Schwellenwert, wird eine Warnung
    zurückgegeben, die den Benutzer auf eine empfohlene Schlüsselrotation
    hinweist. Ist ``ROTATION_WARNING_DAYS`` 0 oder kleiner, wird niemals
    gewarnt.

    ``vault``: Das geöffnete Vault-Objekt.
    Returns: Ein Warnhinweis als String oder ``None``, wenn keine
    Rotation notwendig ist.
    """
    try:
        threshold_days = globals().get("ROTATION_WARNING_DAYS", 0)
        if not isinstance(threshold_days, (int, float)) or threshold_days <= 0:
            return None
        last_update = vault.updated_at or 0
        # Berechne vergangene Tage seit dem letzten Update
        days_since = (time.time() - last_update) / 86400.0
        if days_since >= threshold_days:
            # Formatierbares Datum des letzten Updates
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_update))
            # Gib die Warnung zweisprachig aus. Titel/Msg werden über die
            # Übersetzungsfunktion tr angepasst, um das Datum dynamisch einzufügen.
            return tr(
                f"Warnung: Der Tresor wurde zuletzt am {ts} gespeichert.\nEs wird empfohlen, die Schlüssel zu rotieren (Tresor neu verschlüsseln).",
                f"Warning: The vault was last saved on {ts}.\nIt is recommended to rotate the keys (re‑randomize the vault).",
            )
    except Exception:
        pass
    return None

def maybe_warn_rotation_cli(vault: Vault) -> None:
    """
    Gibt eine Warnung zur Schlüsselrotation im CLI aus, falls ``maybe_warn_rotation``
    einen Hinweis zurückliefert. Wenn keine Warnung notwendig ist, geschieht
    nichts. Diese Funktion trennt die Logik der Warnung von der
    konkreten Ausgabe, sodass sie sowohl in CLI als auch in der GUI
    verwendet werden kann.
    """
    msg = maybe_warn_rotation(vault)
    if msg:
        print("\n" + msg + "\n")

def maybe_warn_rotation_gui(vault: Vault) -> None:
    """
    Zeigt eine Warnung zur Schlüsselrotation in der GUI an, falls
    ``maybe_warn_rotation`` einen Hinweis zurückliefert. Es wird ein
    modaler Hinweisdialog geöffnet. Wenn keine Warnung notwendig ist, wird
    nichts angezeigt.
    """
    try:
        msg = maybe_warn_rotation(vault)
        if msg:
            from tkinter import messagebox
            # Zeige Warnung zweisprachig. Der Titel wird in die aktuelle Sprache übersetzt.
            messagebox.showwarning(
                tr("Schlüsselrotation empfohlen", "Key rotation recommended"),
                msg,
            )
    except Exception:
        # Falls Tkinter nicht verfügbar oder ein Fehler auftritt, keine Warnung anzeigen
        pass


def auto_rotate_if_due(path: Path, vault: Vault, master_pw_str: str) -> bool:
    """
    Führt eine automatische Schlüsselrotation durch, wenn der Tresor älter
    ist als die in ``AUTO_ROTATION_DAYS`` konfigurierte Schwelle. Die
    Rotation wird durch erneutes Speichern des Tresors ausgelöst, wobei neue
    Salt/Nonces/Pads generiert werden (Re-randomizing). Nach erfolgter
    Rotation wird der Zeitstempel ``vault.updated_at`` aktualisiert und ein
    Audit‑Eintrag geschrieben.

    Parameter:
        path: Pfad der Tresor-Datei.
        vault: Geladenes Vault-Objekt.
        master_pw_str: Das Master-Passwort als Klartext-String.

    Returns:
        True, wenn eine Rotation durchgeführt wurde, ansonsten False.
    """
    try:
        days = globals().get("AUTO_ROTATION_DAYS", 0)
        if not isinstance(days, (int, float)) or days <= 0:
            return False
        # Wieviel Zeit seit letzter Aktualisierung?
        last = vault.updated_at or 0
        age_days = (time.time() - last) / 86400.0
        if age_days >= days:
            # Tresor neu verschlüsseln (ohne Backup, um unnötige Kopien zu vermeiden)
            save_vault(path, vault, master_pw_str, make_backup=False)
            # Aktualisiere updated_at im laufenden Objekt
            try:
                vault.updated_at = time.time()
            except Exception:
                pass
            # Audit‑Log vermerken
            try:
                write_audit("auto_rotate", f"{path}")
            except Exception:
                pass
            return True
    except Exception:
        # Bei Fehlern keine Rotation durchführen
        pass
    return False

# ====================================
# SECTION D — Kryptographische Hilfsfunktionen
# ====================================
def derive_three_keys(master_pw: bytes, salt: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Leitet drei unabhängige Schlüssel (AES‑Key, ChaCha‑Key und MAC‑Key) aus
    ``master_pw`` und ``salt`` ab. Normalerweise wird hierfür die
    standardmäßige scrypt‑KDF verwendet, die starke Parameter (``KDF_N``,
    ``KDF_R``, ``KDF_P``) unterstützt. Allerdings begrenzt die
    OpenSSL‑Implementierung von ``hashlib.scrypt`` die maximal zulässige
    Speicherverwendung auf ca. 32 MiB, was bei den hier gewählten Parametern
    zu einem ``ValueError: memory limit exceeded`` führen kann. Wenn das
    ``cryptography``‑Paket verfügbar ist, verwenden wir dessen
    Scrypt‑Implementierung, die ohne diese Beschränkung arbeitet. Ansonsten
    berechnen wir die benötigte Speichermenge und erhöhen den
    ``maxmem``‑Parameter von ``hashlib.scrypt`` entsprechend, um die
    Ableitung dennoch zu ermöglichen.

    ``master_pw``: muss als bytes angegeben werden (wird später versucht zu
    überschreiben).
    Returns: Tupel (AES‑Schlüssel, ChaCha‑Schlüssel, MAC‑Schlüssel), je 32 Byte.
    """
    # Bereite das Passwort vor: Keyfile und Geräte-Pepper einmischen.
    try:
        master_pw = _pre_kdf(master_pw)
    except FileNotFoundError:
        # Wenn ein Keyfile zwingend erforderlich ist (REQUIRE_KEYFILE=True),
        # soll ein fehlendes Keyfile den Vorgang abbrechen und nicht still
        # in einen weniger sicheren Modus fallen.
        raise
    except Exception:
        # Alle anderen Fehler (z.B. defekte Keyfile-Datei) ignorieren wir
        # wie bisher, damit die KDF weiterhin mit dem reinen Master-Passwort
        # funktioniert.
        pass

    # Optionale Verwendung von Argon2 anstelle von scrypt, wenn konfiguriert
    # und die Bibliothek vorhanden ist. Argon2 bietet eine moderne, speicherintensive
    # KDF. Die Parameter werden über die Konfiguration gesteuert.
    if KDF_MODE == "argon2" and _HAS_ARGON2:
        # memory_cost ist in Kibibytes. time_cost ist die Iterationsanzahl.
        # parallelism bestimmt die Anzahl Threads.
        dk = hash_secret_raw(
            secret=master_pw,
            salt=salt,
            time_cost=ARGON2_TIME,
            memory_cost=ARGON2_MEMORY,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KDF_DKLEN,
            type=_Argon2Type.ID,
        )
    else:
        # Verwende scrypt. Wenn cryptography's Scrypt verfügbar ist, verwenden
        # wir diese Implementierung ohne Speicherbegrenzung. Ansonsten
        # verwenden wir hashlib.scrypt mit erhöhtem maxmem.
        if _CryptoScrypt is not None:
            kdf = _CryptoScrypt(
                salt=salt,
                length=KDF_DKLEN,
                n=KDF_N,
                r=KDF_R,
                p=KDF_P,
            )
            dk = kdf.derive(master_pw)
        else:
            # Fallback: hashlib.scrypt mit erhöhtem maxmem.
            required = 128 * KDF_N * KDF_R * KDF_P
            MAX_SCRYPT_MAXMEM = 256 * 1024 * 1024  # 256 MiB Cap
            maxmem = min(required * 2, MAX_SCRYPT_MAXMEM)
            if maxmem < required * 2:
                raise RuntimeError(
                    "Scrypt-Fallback nicht sicher (Speicherlimit). Bitte 'cryptography' installieren "
                    "oder KDF‑Parameter in der Konfig reduzieren."
                )
            dk = hashlib.scrypt(
                password=master_pw,
                salt=salt,
                n=KDF_N,
                r=KDF_R,
                p=KDF_P,
                dklen=KDF_DKLEN,
                maxmem=maxmem,
            )
    aes_key = dk[0:32]
    chacha_key = dk[32:64]
    mac_key = dk[64:96]
    # best effort: überschreibe temporären Schlüssel
    try:
        del dk
    except Exception:
        pass
    return aes_key, chacha_key, mac_key

# -- Internal KDF helper for decryption with embedded parameters --
def _derive_three_keys_with_params(master_pw: bytes, salt: bytes, params: Dict[str, object]) -> Tuple[bytes, bytes, bytes]:
    """
    Derive three independent keys from the given master password and salt using
    the KDF parameters extracted from a vault file.  The returned tuple is
    (AES‑key, ChaCha‑key, MAC‑key), each 32 bytes.  This helper mirrors
    ``derive_three_keys`` but does not rely on global KDF settings, thereby
    allowing vaults encrypted with historic parameters to be opened after
    configuration changes.

    :param master_pw: the master password as raw bytes
    :param salt: the salt read from the vault file
    :param params: a dictionary with keys "mode" (``"argon2"`` or ``"scrypt"``)
        and the associated KDF parameters.  For scrypt these are ``n``, ``r``,
        ``p`` and ``dklen``.  For Argon2 they are ``time``, ``memory``,
        ``parallel`` and ``dklen``.  Unknown keys are ignored.
    :returns: a tuple of (aes_key, chacha_key, mac_key)
    """
    # Bereite das Passwort vor: Keyfile und Geräte-Pepper einmischen.
    try:
        master_pw = _pre_kdf(master_pw)
    except FileNotFoundError:
        # Bei aktivem REQUIRE_KEYFILE darf ein fehlendes Keyfile nicht
        # still zu einem weniger sicheren Modus führen.
        raise
    except Exception:
        # Andere Fehler (z.B. beschädigtes Keyfile) ignorieren wir weiterhin,
        # damit alte Tresore notfalls noch mit reinem Master-Passwort geöffnet
        # werden können.
        pass

    mode = str(params.get("mode", "scrypt")).lower()
    dklen = int(params.get("dklen", 96))
    # Use Argon2 when requested and available
    if mode == "argon2" and _HAS_ARGON2:
        t = int(params.get("time", 3))
        mem = int(params.get("memory", 262144))
        par = int(params.get("parallel", 4))
        dk = hash_secret_raw(
            secret=master_pw,
            salt=salt,
            time_cost=t,
            memory_cost=mem,
            parallelism=par,
            hash_len=dklen,
            type=_Argon2Type.ID,
        )
    else:
        # scrypt fallback
        n = int(params.get("n", KDF_N))
        r = int(params.get("r", KDF_R))
        p = int(params.get("p", KDF_P))
        # Use cryptography's Scrypt if available to avoid OpenSSL's memory cap
        if _CryptoScrypt is not None:
            kdf = _CryptoScrypt(salt=salt, length=dklen, n=n, r=r, p=p)
            dk = kdf.derive(master_pw)
        else:
            # Compute required memory for hashlib.scrypt; double for margin
            required = 128 * n * r * p
            MAX_SCRYPT_MAXMEM = 256 * 1024 * 1024  # 256 MiB cap
            maxmem = min(required * 2, MAX_SCRYPT_MAXMEM)
            if maxmem < required * 2:
                raise RuntimeError(
                    "Scrypt-Fallback nicht sicher (Speicherlimit). Bitte 'cryptography' installieren oder KDF‑Parameter reduzieren."
                )
            dk = hashlib.scrypt(
                password=master_pw,
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=dklen,
                maxmem=maxmem,
            )
    aes_key = dk[0:32]
    chacha_key = dk[32:64]
    mac_key = dk[64:96]
    try:
        del dk
    except Exception:
        pass
    return aes_key, chacha_key, mac_key

def hmac_sha512(mac_key: bytes, data: bytes) -> bytes:
    """HMAC-SHA512 über data mit mac_key."""
    return hmac.new(mac_key, data, hashlib.sha512).digest()

def pad_stream_from_mac(mac_key: bytes, nonce_pad: bytes, length: int) -> bytes:
    """
    Erzeuge deterministischen Pad-Stream aus mac_key und nonce_pad per HMAC-CTR.
    Der Stream hat die Länge 'length'.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        ctr = counter.to_bytes(4, "big")
        block = hmac.new(mac_key, nonce_pad + ctr, hashlib.sha512).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR zweier Byte-Strings gleicher Länge."""
    return bytes(x ^ y for x, y in zip(a, b))

# -----------------------------------------------------------------------------
# Erweiterte KDF-Vorverarbeitung: Keyfile-Unterstützung und Gerätebindung
# -----------------------------------------------------------------------------
def _load_keyfile_bytes(path: str) -> bytes:
    """
    Lade bis zu 1 MiB aus einer Schlüsseldatei und gib den SHA512-Hash zurück.

    Dieser Hash wird als "Pepper" in die KDF eingemischt.  Eine leere
    Rückgabe bedeutet, dass kein Keyfile geladen wird.  Fehler beim Lesen
    führen zu einem leeren Ergebnis.
    """
    try:
        if not path:
            return b""
        import pathlib
        p = pathlib.Path(path)
        if not p.exists() or not p.is_file():
            return b""
        data = p.read_bytes()[:1024 * 1024]
        import hashlib
        return hashlib.sha512(data).digest()
    except Exception:
        return b""

def _load_device_id() -> bytes:
    """
    Liefert einen Hash eines gerätespezifischen Identifiers zur Gerätebindung.

    Unter Linux wird /etc/machine-id verwendet, falls vorhanden. Auf Windows
    wird der Hostname herangezogen. Als Fallback wird der Plattform-Node
    (Hostname) verwendet.  Fehler resultieren in einem leeren Byte-String.
    """
    try:
        import os, hashlib, platform
        # Versuche, /etc/machine-id zu lesen (Linux)
        machine_id_path = "/etc/machine-id"
        if os.path.exists(machine_id_path):
            try:
                with open(machine_id_path, "rb") as f:
                    mid = f.read().strip()
                return hashlib.sha512(mid).digest()
            except Exception:
                pass
        # Fallback: Hostname
        node = platform.node()
        if node:
            return hashlib.sha512(node.encode("utf-8", errors="ignore")).digest()
    except Exception:
        pass
    return b""

def _pre_kdf(master_pw: bytes) -> bytes:
    """
    Kombiniere das Master-Passwort mit optionalem Keyfile-Hash und Geräte-ID.

    Wenn KEYFILE_PATH gesetzt ist, wird der Hash der Schlüsseldatei als Pepper
    verwendet. Bei aktivierter Gerätebindung wird zusätzlich ein
    gerätespezifischer Hash einbezogen.  Die Kombination erfolgt mittels
    HMAC-SHA512, sodass aus Master-Passwort und Pepper deterministisch ein
    neues Material entsteht.  Ohne Keyfile/Device-Bind wird das Passwort
    unverändert zurückgegeben.
    """
    pepper = b""

    # Prüfe, ob die Verwendung des Keyfiles erzwungen wird und der Pfad existiert.
    kpath = str(globals().get("KEYFILE_PATH", ""))
    require = bool(globals().get("REQUIRE_KEYFILE", False))

    if require and kpath:
        # Wenn der Pfad gesetzt ist, aber die Datei fehlt, breche ab
        import pathlib
        p = pathlib.Path(kpath)
        if not p.exists() or not p.is_file():
            # Lokalisierte Fehlermeldung ausgeben    
            raise FileNotFoundError(
                tr(
                    "Keyfile erforderlich, aber nicht gefunden. "
                    "Bitte überprüfe REQUIRE_KEYFILE und KEYFILE_PATH in der Konfiguration.",
                    "Keyfile required but not found. "
                    "Please check REQUIRE_KEYFILE and KEYFILE_PATH in your configuration.",
                )
            )


    # Versuche, das Keyfile zu laden. Fehler führen zu einem leeren Pepper.
    try:
        if kpath:
            pepper = _load_keyfile_bytes(kpath)
        else:
            pepper = b""
    except Exception:
        # _load_keyfile_bytes gibt bei Fehlern normalerweise leere Bytes zurück;
        # alle Fehler resultieren hier in der Verwendung eines leeren Peppers.
        pepper = b""

    # Gerätebindung
    if globals().get("DEVICE_BIND", False):
        try:
            dev = _load_device_id()
            if dev:
                if pepper:
                    pepper = hmac.new(dev, pepper, hashlib.sha512).digest()
                else:
                    pepper = dev
        except Exception:
            # Gerät kann nicht ermittelt werden → einfach ohne Device-Pepper weitermachen.
            pass

    if pepper:
        # Kombiniere Master-Passwort und Pepper deterministisch zu neuem Material
        return hmac.new(pepper or b"keyfile:absent", master_pw, hashlib.sha512).digest()

    # Kein Keyfile/kein Device-Bind aktiv → Master-Passwort unverändert verwenden.
    return master_pw


# Passwort-Richtlinie für das Master-Passwort
MIN_MASTER_LEN = 14
def _check_master_policy(pw: str) -> tuple[bool, str]:
    """
    Überprüft, ob das angegebene Passwort den Mindestanforderungen genügt.

    Es wird geprüft, ob das Passwort lang genug ist und jeweils mindestens
    einen Großbuchstaben, einen Kleinbuchstaben, eine Ziffer und ein
    Sonderzeichen enthält.  Rückgabe ist (True, "OK") bei Erfolg oder
    (False, Grund) bei Nichterfüllung.
    """
    import re
    if pw is None:
        return False, "Leer"
    if len(pw) < MIN_MASTER_LEN:
        return False, f"Mind. {MIN_MASTER_LEN} Zeichen"
    if not re.search(r"[A-Z]", pw):
        return False, "Mind. 1 Großbuchstabe"
    if not re.search(r"[a-z]", pw):
        return False, "Mind. 1 Kleinbuchstabe"
    if not re.search(r"\d", pw):
        return False, "Mind. 1 Ziffer"
    if not re.search(r"[^\w]", pw):
        return False, "Mind. 1 Sonderzeichen"
    return True, "OK"

# Best-effort Wiping-Funktion: setzt Bytes in bytearray oder bytes auf 0
def wipe_bytes(b: 'bytearray | bytes') -> None:
    """
    Überschreibt die übergebenen Bytes nach Möglichkeit mit Nullen.

    Bei bytes wird ein temporärer Buffer angelegt und überschrieben, bei
    bytearray wird das Array direkt manipuliert.  Fehler werden ignoriert.
    """
    import ctypes
    try:
        if isinstance(b, bytes):
            m = ctypes.create_string_buffer(len(b))
            ctypes.memset(ctypes.addressof(m), 0, len(b))
        else:
            for i in range(len(b)):
                b[i] = 0
    except Exception:
        pass

# ---------------------------------------------------------------------------
# POSIX-Dateirechte sicher setzen
# ---------------------------------------------------------------------------
def secure_chmod_600(p: 'Path') -> None:
    """
    Setzt die Dateirechte der übergebenen Datei best‑effort auf 0600 (rw-------).

    Diese Funktion wirkt nur auf POSIX‑Systemen.  Unter Windows werden die
    Dateirechte nicht verändert.  Fehler beim Setzen der Rechte werden
    stillschweigend ignoriert.

    Args:
        p (Path): Pfad der Datei, deren Rechte angepasst werden sollen.
    """
    try:
        import os, stat
        if os.name == "posix":
            os.chmod(str(p), stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        # Fehler beim Setzen der Rechte sind nicht kritisch
        pass


# ---- KDF-Metadaten als TLV (für self-describing Tresore, Version 3) ----
# KDF_MODE: "argon2" oder "scrypt"
def _build_kdf_tlv() -> bytes:
    mode = (str(KDF_MODE).lower() if "KDF_MODE" in globals() else "scrypt")
    if mode == "argon2":
        # DATA: time(4)|memKiB(4)|parallel(4)|dklen(2)
        t  = int(ARGON2_TIME)
        mem = int(ARGON2_MEMORY)
        par = int(ARGON2_PARALLELISM)
        dk  = int(KDF_DKLEN)
        payload = struct.pack(">IIIH", t, mem, par, dk)
        mode_byte = b"\x02"
    else:
        # scrypt
        n = int(KDF_N); r = int(KDF_R); p = int(KDF_P); dk = int(KDF_DKLEN)
        payload = struct.pack(">IIIH", n, r, p, dk)
        mode_byte = b"\x01"
    return mode_byte + struct.pack(">H", len(payload)) + payload

def _parse_kdf_tlv(blob: bytes, off: int):
    kdf_mode_byte = blob[off]; off += 1
    (length,) = struct.unpack_from(">H", blob, off); off += 2
    payload = blob[off:off+length]; off += length
    if kdf_mode_byte == 1:  # scrypt
        n, r, p, dk = struct.unpack_from(">IIIH", payload, 0)
        params = {"mode":"scrypt","n":int(n),"r":int(r),"p":int(p),"dklen":int(dk)}
    elif kdf_mode_byte == 2:  # argon2
        t, mem, par, dk = struct.unpack_from(">IIIH", payload, 0)
        params = {"mode":"argon2","time":int(t),"memory":int(mem),"parallel":int(par),"dklen":int(dk)}
    else:
        raise ValueError("Unbekannter KDF-Modus im TLV")
    return params, off
# ====================================
# SECTION E — Dateiformat & Verschlüsselung (Triple-Layer)
# ====================================
# Dateiformat – Versionen 2 bis N (dynamisch über EXTRA_ENCRYPTION_LAYERS)
#
# **Version 2:**
# ``[MAGIC(4)][VER=2(1)][salt(16)][nonce_aes(12)][nonce_pad(12)][nonce_chacha(12)][ciphertext_chacha…][hmac(64)]``
#
# **Version 3:**
# ``[MAGIC(4)][VER=3(1)][KDF-TLV(var)][salt(16)][nonce_aes(12)][nonce_pad(12)][nonce_chacha(12)][ciphertext_chacha…][hmac(64)]``
#  – der Header (MAGIC+VER+TLV) wird als Associated Data (AAD) in AES/ChaCha verwendet.  Die HMAC
#    deckt Header und Body ab.
#
# **Version ≥4:**
# Für Dateiformate mit Versionsnummer ≥4 werden zusätzliche Schichten angewendet.
# Die allgemeine Struktur lautet:
# ``[MAGIC][VER][KDF-TLV][salt₀][nonce₀]…[saltₙ₋₁][nonceₙ₋₁][xorⁿ(v3_blob) …][hmac₀]…[hmacₙ₋₁]``
#  – Zunächst wird ein v3‑Blob wie oben erzeugt (MAGIC+3+TLV+…+HMAC).  Anschließend wird für
#    jede zusätzliche Schicht (``n = VER − 3``) ein eigenes Salt und Nonce generiert, aus dem
#    mithilfe des Master‑Passworts ein One‑Time‑Pad und eine HMAC abgeleitet werden.  Diese
#    Schichten verschleiern den v3‑Blob n‑fach.  Bei der Entschlüsselung werden die HMACs
#    in umgekehrter Reihenfolge überprüft, die Pads entfernt und danach der innere v3‑Blob
#    verarbeitet.
#
# Die ursprüngliche Schrittfolge der Triple‑Verschlüsselung bleibt unverändert:
# ``plaintext -> AES‑GCM -> XOR‑Pad -> ChaCha20‑Poly1305 -> HMAC``.  Jede weitere Schicht
# fügt ``-> XOR‑Pad_i -> HMAC_i`` hinzu.

def encrypt_vault_bytes(plaintext: bytes, master_pw: bytes) -> bytes:
    """
    Verschlüsselt ``plaintext`` mit ``master_pw`` und liefert den kompletten Tresor‑Blob.

    **Schichtaufbau:** Zunächst wird der Klartext mittels Triple‑Verschlüsselung verarbeitet
    (AES‑GCM → XOR‑Pad → ChaCha20‑Poly1305 → HMAC), wie sie in Dateiformat‑Version 3 definiert
    ist.  Optional können anschließend weitere Verschlüsselungsschichten angewendet werden.  Die
    Anzahl dieser zusätzlichen Schichten wird durch die globale Variable
    ``EXTRA_ENCRYPTION_LAYERS`` bestimmt.  ``0`` bedeutet, dass nur die Triple‑Verschlüsselung
    angewendet wird (keine Zusatzschicht), ``1`` fügt eine weitere XOR/HMAC‑Schicht hinzu,
    ``2`` fügt zwei Schichten hinzu und so weiter.  Es gibt kein festes Maximum –
    jede zusätzliche Schicht erhöht den Rechenaufwand und die Dateigröße.  Für jede
    Zusatzschicht werden ein eigenes ``salt`` und ``nonce`` aus dem Master‑Passwort abgeleitet,
    ein One‑Time‑Pad erzeugt und eine HMAC gebildet.  Die Datei enthält alle
    Salt/Nonce‑Paare sowie die HMACs in der Reihenfolge ihrer Erzeugung.

    Die Dateiformat‑Version im Header wird dynamisch berechnet als ``version = 3 +
    EXTRA_ENCRYPTION_LAYERS``.  Beim Entschlüsseln liest die Funktion diese Versionsnummer
    aus und entfernt die Schichten entsprechend.
    """
    # Generiere das primäre Salt für die inneren Schlüssel
    salt = secrets.token_bytes(SALT_LEN)
    # Erzeuge den KDF‑TLV, der die aktuellen KDF‑Parameter enthält
    kdf_tlv = _build_kdf_tlv()
    # Bestimme die Anzahl zusätzlicher Schichten.  Verwende den konfigurierbaren Wert
    # EXTRA_ENCRYPTION_LAYERS, wobei negative Eingaben als 0 behandelt werden.
    try:
        layers = int(EXTRA_ENCRYPTION_LAYERS)
    except Exception:
        layers = 0
    layers = max(0, layers)
    # Dateiformat-Version: 3 (nur Triple‑Layer) + Anzahl der zusätzlichen Schichten.
    file_version = 3 + layers
    # Finale Header-Konstruktion mit dynamischer Version.
    final_header = MAGIC + file_version.to_bytes(1, "big") + kdf_tlv
    # Für die innere Triple‑Encryption wird Version 3 verwendet, wenn mindestens eine
    # zusätzliche Schicht vorhanden ist.  Andernfalls wird die Dateiversion verwendet.
    inner_version = 3 if file_version >= 4 else file_version
    inner_header = MAGIC + inner_version.to_bytes(1, "big") + kdf_tlv

    # Leite die drei Basisschlüssel aus dem (ggf. gepepperten) Master-Passwort und dem primären Salt ab
    aes_key, chacha_key, mac_key = derive_three_keys(master_pw, salt)
    # Leite die Schlüssel für die Triple‑Verschlüsselung aus dem MAC‑Key ab
    pad_key = hmac_sha512(mac_key, b"pad")
    hmac_key = hmac_sha512(mac_key, b"hmac")
    # Lösche MAC‑Key, er wird nicht weiter benötigt
    try:
        del mac_key
    except Exception:
        pass

    # === Triple‑Verschlüsselung (Version 3) ===
    # AES‑GCM: verschlüsselt den Klartext mit einem zufälligen Nonce und inner_header als AAD
    nonce_aes = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(aes_key)
    ciphertext_aes = aesgcm.encrypt(nonce_aes, plaintext, inner_header)
    # XOR‑Pad: generiere Pad aus pad_key und neuem Nonce
    nonce_pad = secrets.token_bytes(NONCE_LEN)
    pad = pad_stream_from_mac(pad_key, nonce_pad, len(ciphertext_aes))
    obf = xor_bytes(ciphertext_aes, pad)
    # ChaCha20‑Poly1305: verschlüsselt obf mit neuem Nonce, inner_header als AAD
    nonce_chacha = secrets.token_bytes(NONCE_LEN)
    chacha = ChaCha20Poly1305(chacha_key)
    ciphertext_chacha = chacha.encrypt(nonce_chacha, obf, inner_header)
    # Körper des Triple‑Blobs: Salt + Nonces + Ciphertext
    triple_body = salt + nonce_aes + nonce_pad + nonce_chacha + ciphertext_chacha
    # HMAC über inner_header||triple_body
    triple_hmac = hmac_sha512(hmac_key, inner_header + triple_body)
    # Vollständiger v3‑Blob
    triple_blob = inner_header + triple_body + triple_hmac

    # === Optionale äußere Schichten ===
    if layers > 0:
        # Beginn mit dem v3-Blob, der weiter verschleiert wird
        blob = triple_blob
        salts: list[bytes] = []
        nonces: list[bytes] = []
        hmacs: list[bytes] = []
        # Verwende das vorbereitete Master-Material für alle äußeren Schichten
        try:
            _mm = _pre_kdf(master_pw)
        except FileNotFoundError:
            # REQUIRE_KEYFILE aktiv + Keyfile fehlt -> harter Abbruch,
            # damit der Nutzer die Fehlkonfiguration bemerkt.
            raise
        except Exception:
            # In allen anderen Fällen auf das reine Master-Passwort zurückfallen,
            # wie bisher.
            _mm = master_pw
        for i in range(layers):
            salt_extra = secrets.token_bytes(SALT_LEN)
            nonce_extra = secrets.token_bytes(NONCE_LEN)
            # Layer-spezifische Schlüssel ableiten
            pad_key_i = hmac_sha512(_mm, salt_extra + f"layer{i}_pad".encode())
            hmac_key_i = hmac_sha512(_mm, salt_extra + f"layer{i}_hmac".encode())
            pad_i = pad_stream_from_mac(pad_key_i, nonce_extra, len(blob))
            cipher_i = xor_bytes(blob, pad_i)
            hmac_i = hmac_sha512(hmac_key_i, final_header + salt_extra + nonce_extra + cipher_i)
            salts.append(salt_extra)
            nonces.append(nonce_extra)
            hmacs.append(hmac_i)
            blob = cipher_i
            # Sensitive data cleanup per layer
            try:
                del pad_key_i, hmac_key_i, pad_i
            except Exception:
                pass
        # Final zusammenbauen: Header, alle Salt/Nonce-Paare, Cipher und HMACs
        final_cipher = blob
        out = final_header
        for s, n in zip(salts, nonces):
            out += s + n
        out += final_cipher
        for hm in hmacs:
            out += hm
        try:
            del salts, nonces, hmacs, final_cipher, blob
        except Exception:
            pass
    else:
        # Keine zusätzlichen Schichten: Triple‑Blob als Ganzes zurückgeben
        out = triple_blob

    # Bereinige Schlüssel und temporäre Daten
    try:
        del aes_key, chacha_key, pad_key, hmac_key, pad, obf, ciphertext_aes, ciphertext_chacha, triple_body, triple_hmac, triple_blob
    except Exception:
        pass
    return out


def decrypt_vault_bytes(blob: bytes, master_pw: bytes) -> bytes:
    """
    Entschlüsselt einen verschlüsselten Tresor‑Blob mit ``master_pw`` und gibt den Klartext zurück.

    Diese Funktion unterstützt alle bislang definierten Dateiformate (Version 2 bis N).  Die
    Dateiversion befindet sich nach dem ``MAGIC``‑Prefix.  Je nach Versionsnummer werden
    unterschiedliche Strukturen erwartet:

    * **Version 2** – Altes Format ohne KDF‑TLV und ohne Verwendung von Associated Data.  Die HMAC
      deckt nur den Datenkörper ab.

    * **Version 3** – Fügt ein KDF‑TLV hinzu und nutzt den Header (MAGIC + Version + TLV) als
      Associated Data für AES und ChaCha.  Eine HMAC schützt Header und Körper.

    * **Version ≥4** – Für jede zusätzliche Verschlüsselungsschicht (``layers = version − 3``)
      werden ein eigenes Salt und Nonce vor dem verschleierten v3‑Blob gespeichert.  Nach dem
      Ciphertext folgen ``layers`` HMACs, jeweils 64 Bytes lang, die den Header sowie das
      entsprechende Salt/Nonce und den verschleierten Blob schützen.  Beim Entschlüsseln wird
      zunächst der äußere HMAC überprüft, das XOR‑Pad entfernt, dann der nächste HMAC usw., bis
      der innere v3‑Blob übrig bleibt.  Die Schlüssel für die Pads und HMACs werden aus dem
      Master‑Passwort, dem jeweiligen Salt und einem Schicht‑Index abgeleitet.  Diese Logik
      erlaubt beliebig viele zusätzliche Schichten (abhängig von der Versionsnummer).  Für
      Kompatibilität mit älteren Version‑4‑Dateien wird beim Entschlüsseln mit einer einzelnen
      Schicht zusätzlich eine alternative Ableitung (``extra_pad``/``extra_hmac``) versucht.
    """
    # Mindestlänge sicherstellen: MAGIC (4) + VER (1) + (mindestens 3 Nonces, Salt und HMAC)
    # Die genaue Größe wird je nach Version weiter unten geprüft.
    if len(blob) < 4 + 1 + SALT_LEN + NONCE_LEN * 3 + 64:
        raise ValueError("Datei zu klein oder beschädigt")
    off = 0
    magic = blob[off:off + 4]; off += 4
    if magic != MAGIC:
        raise ValueError("Ungültiges Dateiformat (magic mismatch)")
    version = blob[off]; off += 1


    if version >= 4:
        # ===== Entschlüsselung für Versionen ≥ 4 =====
        # Lese den KDF‑TLV wie in Version 3.  Der Header besteht aus MAGIC + Version + TLV.
        kdf_params, off = _parse_kdf_tlv(blob, off)
        header = blob[:off]
        # Anzahl der zusätzlichen Schichten: version - 3
        layers = version - 3
        # Für jede Schicht sind ein Salt und ein Nonce gespeichert.  Berechne die Länge dieses Bereichs.
        salts: list[bytes] = []
        nonces: list[bytes] = []
        for i in range(layers):
            if len(blob) < off + SALT_LEN + NONCE_LEN:
                raise ValueError("Datei beschädigt – unvollständige Salt/Nnonce‑Daten")
            salt_i = blob[off:off + SALT_LEN]; off += SALT_LEN
            nonce_i = blob[off:off + NONCE_LEN]; off += NONCE_LEN
            salts.append(salt_i)
            nonces.append(nonce_i)
        # Danach folgt der verschleierte v3‑Blob gefolgt von layers HMACs.  Prüfe, dass genug Daten vorhanden sind.
        hmac_area_len = 64 * layers
        if len(blob) < off + hmac_area_len:
            raise ValueError("Datei beschädigt – HMAC‑Bereich fehlt")
        cipher_end = len(blob) - hmac_area_len
        final_cipher = blob[off:cipher_end]
        # Extrahiere die HMACs in derselben Reihenfolge wie beim Verschlüsseln
        hmacs: list[bytes] = []
        for i in range(layers):
            hmac_start = cipher_end + 64 * i
            hmac_end = hmac_start + 64
            hmacs.append(blob[hmac_start:hmac_end])
        # Entschlüsselung von außen nach innen: initialisiere current_blob mit dem äußersten verschlüsselten Bereich
        current_blob = final_cipher
        # Flag zur Kompatibilität mit historischen Version-4-Dateien
        fallback_used = False
        try:
            # Bereite das Master-Passwort vor: Mischung aus Master-Passwort, Keyfile und Geräte-ID.
            try:
                _mm = _pre_kdf(master_pw)
            except FileNotFoundError:
                # Wenn ein Keyfile zwingend erforderlich ist und fehlt,
                # soll der Entschlüsselungsvorgang abbrechen, damit der
                # Nutzer eine klare Fehlermeldung bekommt.
                raise
            except Exception:
                # Alle anderen Fehler führen wie bisher dazu, dass wir
                # mit dem reinen Master-Passwort weiterarbeiten.
                _mm = master_pw
            # Bearbeite die Schichten in umgekehrter Reihenfolge
            for i in reversed(range(layers)):
                salt_i = salts[i]; nonce_i = nonces[i]; hmac_i = hmacs[i]
                # Leite die Pad- und HMAC-Schlüssel aus dem vorbereiteten Master-Material, dem Salt
                # und dem Layer-Index ab
                pad_key_i = hmac_sha512(_mm, salt_i + f"layer{i}_pad".encode())
                hmac_key_i = hmac_sha512(_mm, salt_i + f"layer{i}_hmac".encode())
                # Berechne die erwartete HMAC und vergleiche mit dem gespeicherten Wert
                expected_hmac = hmac_sha512(hmac_key_i, header + salt_i + nonce_i + current_blob)
                if not hmac.compare_digest(expected_hmac, hmac_i):
                    raise ValueError("HMAC-Überprüfung fehlgeschlagen")
                # Entferne das XOR‑Pad
                pad_i = pad_stream_from_mac(pad_key_i, nonce_i, len(current_blob))
                # Entschlüsselte Nutzdaten für die nächste Schicht (oder innere v3‑Blob)
                current_blob = xor_bytes(current_blob, pad_i)
                # Aufräumen
                try:
                    del pad_key_i, hmac_key_i, pad_i, expected_hmac
                except Exception:
                    pass
        except ValueError:
            # Wenn eine HMAC fehlschlägt und es sich um eine Version‑4‑Datei mit nur einer Schicht handelt,
            # versuchen wir zur Wahrung der Abwärtskompatibilität die alten Schlüsselbezeichnungen
            # (extra_pad/extra_hmac). Dies gilt für Tresore, die mit Version 4 der ursprünglichen
            # Implementierung erstellt wurden.
            if version == 4 and layers == 1:
                salt_i = salts[0]; nonce_i = nonces[0]; hmac_i = hmacs[0]
                # Auch im Fallback wird das vorbereitete Master-Material verwendet, um
                # die Kompatibilität mit der Keyfile/Device-Bind-Funktion zu wahren.
                try:
                    _mm_fallback = _pre_kdf(master_pw)
                except FileNotFoundError:
                    # Auch im Fallback gilt: wenn ein Keyfile zwingend gefordert
                    # ist und fehlt, brechen wir mit einer klaren Fehlermeldung ab.
                    raise
                except Exception:
                    # Alle anderen Fehler: wie bisher auf das reine Master-Passwort
                    # zurückfallen.
                    _mm_fallback = master_pw
                extra_pad_key = hmac_sha512(_mm_fallback, salt_i + b"extra_pad")
                extra_hmac_key = hmac_sha512(
                    _mm_fallback, salt_i + b"extra_hmac"
                )
                expected2 = hmac_sha512(extra_hmac_key, header + salt_i + nonce_i + current_blob)
                if not hmac.compare_digest(expected2, hmac_i):
                    raise ValueError("HMAC-Überprüfung fehlgeschlagen – falsches Passwort oder manipulierte Datei")
                pad_extra = pad_stream_from_mac(extra_pad_key, nonce_i, len(current_blob))
                current_blob = xor_bytes(current_blob, pad_extra)
                fallback_used = True
                try:
                    del extra_pad_key, extra_hmac_key, pad_extra, expected2
                except Exception:
                    pass
            else:
                # Fehler in einer der HMACs bei mehrschichtigen Dateien bedeutet falsches Passwort oder Manipulation
                raise
        # current_blob enthält nun den inneren v3‑Blob, der rekursiv entschlüsselt wird
        triple_blob = current_blob
        # Bereinige temporäre Listen und Daten
        try:
            del salts, nonces, hmacs, current_blob, final_cipher
        except Exception:
            pass
        # Entschlüssle den inneren Blob mit demselben Master‑Passwort
        return decrypt_vault_bytes(triple_blob, master_pw)

    if version == 3:
        # Parse the KDF TLV from the file and retain the associated parameters.  Note: _parse_kdf_tlv
        # advances the offset to point just after the TLV.  We capture the header exactly as it
        # appears in the file (MAGIC + version byte + TLV bytes) rather than reconstructing it
        # from current configuration.  This ensures that even if the global KDF parameters change
        # after a vault is created, the file can still be decrypted correctly.
        kdf_params, off = _parse_kdf_tlv(blob, off)
        # The header spans the beginning of the blob up to the new offset (exclusive).
        header = blob[:off]
        salt = blob[off:off+SALT_LEN]; off += SALT_LEN
        nonce_aes = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        nonce_pad = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        nonce_chacha = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        if len(blob) < off + 64:
            raise ValueError("HMAC fehlt/Datei beschädigt")
        ciphertext_chacha = blob[off:-64]
        file_hmac = blob[-64:]

        # Derive keys using the parameters stored within the file.  We intentionally ignore
        # the global KDF settings here so that vaults encrypted with historic parameters
        # remain decryptable after configuration changes.
        aes_key, chacha_key, mac_key = _derive_three_keys_with_params(master_pw, salt, kdf_params)
        pad_key = hmac_sha512(mac_key, b"pad"); hmac_key = hmac_sha512(mac_key, b"hmac")
        try: del mac_key
        except Exception: pass

        calc = hmac_sha512(hmac_key, header + (salt + nonce_aes + nonce_pad + nonce_chacha + ciphertext_chacha))
        if not hmac.compare_digest(calc, file_hmac):
            raise ValueError("HMAC-Überprüfung fehlgeschlagen — falsches Passwort oder manipulierte Datei")

        chacha = ChaCha20Poly1305(chacha_key)
        obf = chacha.decrypt(nonce_chacha, ciphertext_chacha, header)

        pad = pad_stream_from_mac(pad_key, nonce_pad, len(obf))
        ciphertext_aes = xor_bytes(obf, pad)

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce_aes, ciphertext_aes, header)
        # Cleanup
        try: del aes_key, chacha_key, pad_key, hmac_key, pad, obf, ciphertext_aes
        except Exception: pass
        return plaintext

    elif version == 2:
        # Alte Logik beibehalten (kein AAD, HMAC nur über file_body)
        salt = blob[off:off+SALT_LEN]; off += SALT_LEN
        nonce_aes = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        nonce_pad = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        nonce_chacha = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        ciphertext_chacha = blob[off:-64]
        file_hmac = blob[-64:]

        aes_key, chacha_key, mac_key = derive_three_keys(master_pw, salt)
        pad_key = hmac_sha512(mac_key, b"pad"); hmac_key = hmac_sha512(mac_key, b"hmac")
        try: del mac_key
        except Exception: pass

        body = salt + nonce_aes + nonce_pad + nonce_chacha + ciphertext_chacha
        calc = hmac_sha512(hmac_key, body)
        if not hmac.compare_digest(calc, file_hmac):
            raise ValueError("HMAC-Überprüfung fehlgeschlagen — falsches Passwort oder manipulierte Datei")

        chacha = ChaCha20Poly1305(chacha_key)
        obf = chacha.decrypt(nonce_chacha, ciphertext_chacha, None)
        pad = pad_stream_from_mac(pad_key, nonce_pad, len(obf))
        ciphertext_aes = xor_bytes(obf, pad)
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce_aes, ciphertext_aes, None)
        try: del aes_key, chacha_key, pad_key, hmac_key, pad, obf, ciphertext_aes
        except Exception: pass
        return plaintext

    else:
        raise ValueError(f"Nicht unterstützte Version: {version}")


def decrypt_hidden_payload(stego_path: Path, master_pw_str: str) -> Tuple[str, bytes]:
    """Lädt eine Datei mit verstecktem Inhalt, entschlüsselt die Nutzlast und gibt
    den ursprünglichen Dateinamen sowie die reinen Nutzdaten zurück.

    Diese Funktion wird genutzt, um vor dem Schreiben den ursprünglichen
    Dateinamen (inklusive Endung) zu bestimmen. Das ursprüngliche Dateiformat
    wird innerhalb der verschlüsselten Nutzlast als Zwei-Byte-Längenfeld
    gefolgt vom Dateinamen (UTF-8) und anschließend den eigentlichen
    Nutzdaten gespeichert. Falls keine solche Struktur vorliegt (ältere
    versteckte Dateien), wird ein generischer Name zurückgegeben.
    """
    # Lese komplette Datei ein
    full = Path(stego_path).read_bytes()
    # Datei muss mindestens Marker + Längenfeld enthalten
    if len(full) < len(STEGO_MARKER) + STEGO_LENGTH_LEN:
        raise ValueError("Datei enthält keine versteckten Daten (zu kurz)")
    # Prüfe Marker am Dateiende
    if full[-len(STEGO_MARKER):] != STEGO_MARKER:
        raise ValueError("Kein versteckter Inhalt gefunden (Marker fehlt)")
    # Lese die Länge des verschlüsselten Segments, die vor dem Marker gespeichert ist
    # Position des Längenfelds: direkt vor dem Marker
    len_field_start = len(full) - len(STEGO_MARKER) - STEGO_LENGTH_LEN
    enc_len = int.from_bytes(full[len_field_start:len_field_start + STEGO_LENGTH_LEN], "big")
    # Validitätsprüfung: Die verschlüsselte Länge muss positiv sein und innerhalb des
    # durch das Dateiende und den Marker definierten Bereichs liegen. Ist die Länge
    # größer als der Bereich, in dem die Nutzlast liegen kann, ist die Datei
    # beschädigt oder nicht korrekt formatiert.
    max_payload_len = len(full) - len(STEGO_MARKER) - STEGO_LENGTH_LEN
    if enc_len <= 0 or enc_len > max_payload_len:
        raise ValueError("Ungültige Länge des versteckten Inhalts")
    # Start- und Endposition des verschlüsselten Segments bestimmen.
    # Das verschlüsselte Segment endet direkt vor dem Längenfeld.
    enc_end = len(full) - len(STEGO_MARKER) - STEGO_LENGTH_LEN
    enc_start = enc_end - enc_len
    if enc_start < 0 or enc_start > enc_end:
        raise ValueError("Versteckter Inhalt beschädigt")
    enc = full[enc_start:enc_end]
    master_pw = bytearray(master_pw_str.encode("utf-8"))
    try:
        decrypted = decrypt_vault_bytes(enc, bytes(master_pw))
    finally:
        # zeroize password
        for i in range(len(master_pw)):
            master_pw[i] = 0
        del master_pw
    # Versuche, Header mit ursprünglichem Dateinamen zu parsen.
    orig_name = "extracted.bin"
    data = decrypted
    if len(decrypted) >= 2:
        name_len = int.from_bytes(decrypted[:2], "big")
        if 0 < name_len <= len(decrypted) - 2:
            name_bytes = decrypted[2:2 + name_len]
            try:
                orig_name_decoded = name_bytes.decode("utf-8")
                orig_name = orig_name_decoded
                data = decrypted[2 + name_len:]
            except Exception:
                # Fallback: treat entire decrypted blob as data
                data = decrypted
    return orig_name, data

def encrypt_file_data(in_path: Path, master_pw_str: str, out_path: Path) -> None:
    """Liest eine beliebige Datei ein, verschlüsselt deren Inhalt und schreibt ihn in ``out_path``.

    Die Verschlüsselung verwendet denselben Triple-Layer-Algorithmus wie der Tresor
    (AES‑GCM → XOR‑Pad → ChaCha20‑Poly1305). Vor der Verschlüsselung sollte das
    Passwort vom Benutzer **zweimal eingegeben** werden, um Tippfehler zu
    vermeiden (diese Abfrage erfolgt in der Benutzeroberfläche, nicht hier).
    Das Passwort wird in ein ``bytearray`` überführt, nach der Verwendung
    aus dem Speicher überschrieben und anschließend freigegeben, um die
    Verweildauer im Speicher zu minimieren.
    """
    data = Path(in_path).read_bytes()
    master_pw = bytearray(master_pw_str.encode("utf-8"))
    try:
        blob = encrypt_vault_bytes(data, bytes(master_pw))
    finally:
        # lösche Passwort aus Speicher
        for i in range(len(master_pw)):
            master_pw[i] = 0
        del master_pw
    atomic_write(Path(out_path), blob)

def decrypt_file_data(in_path: Path, master_pw_str: str, out_path: Path) -> None:
    """Entschlüsselt eine zuvor mit ``encrypt_file_data`` erzeugte Datei.

    Das Ergebnis wird in ``out_path`` geschrieben. Bei falschem Passwort oder
    beschädigter Datei wird eine Exception ausgelöst. Da für das Entschlüsseln
    lediglich ein Passwort benötigt wird, erfolgt hier keine doppelte
    Passwortabfrage.
    """
    blob = Path(in_path).read_bytes()
    master_pw = bytearray(master_pw_str.encode("utf-8"))
    try:
        data = decrypt_vault_bytes(blob, bytes(master_pw))
    finally:
        for i in range(len(master_pw)):
            master_pw[i] = 0
        del master_pw
    atomic_write(Path(out_path), data)

def hide_file_in_file(cover_path: Path, data_path: Path, master_pw_str: str, out_path: Path) -> None:
    """Versteckt eine Datei ``data_path`` in einer anderen Datei ``cover_path``.

    Zunächst wird der Name der zu versteckenden Datei (zwei Byte Länge und der
    UTF‑8‑kodierte Name) als Header vorangestellt. Anschließend werden dieser
    Header und die Nutzdaten mithilfe des Triple‑Layer‑Algorithmus
    verschlüsselt. Die verschlüsselten Daten werden an das Ende der Cover-Datei
    angehängt, gefolgt von der Länge der Nutzlast (8 Byte big‑endian) und dem
    Marker ``STEGO_MARKER``. Beim Extrahieren dient diese Kennzeichnung dazu,
    die Position der Nutzlast zu finden. Der Benutzer sollte das Passwort zum
    Verstecken **zweimal** eingeben (siehe Aufrufe in GUI/CLI), um Eingabefehler
    auszuschließen.
    """
    cover_bytes = Path(cover_path).read_bytes()
    # Mindestgröße für Cover-Datei, um triviale Erkennung zu erschweren
    MIN_COVER_BYTES = 1 * 1024 * 1024
    if len(cover_bytes) < MIN_COVER_BYTES:
        raise ValueError("Cover-Datei zu klein (min. 1 MiB empfohlen).")
    data_bytes = Path(data_path).read_bytes()
    # Füge den ursprünglichen Dateinamen (mit Erweiterung) in die Nutzdaten ein.
    # Wir speichern die Länge (2 Bytes) des Namens sowie den Namen selbst
    name_bytes = Path(data_path).name.encode("utf-8", errors="ignore")
    if len(name_bytes) > 65535:
        raise ValueError("Dateiname zu lang zum Verstecken (max 65535 Bytes)")
    header = len(name_bytes).to_bytes(2, "big") + name_bytes + data_bytes
    # Verschlüsseln des Headers + Nutzdaten
    master_pw = bytearray(master_pw_str.encode("utf-8"))
    try:
        enc = encrypt_vault_bytes(header, bytes(master_pw))
    finally:
        for i in range(len(master_pw)):
            master_pw[i] = 0
        del master_pw
    length_bytes = len(enc).to_bytes(STEGO_LENGTH_LEN, "big")
    # Neues File: cover + verschlüsselter Inhalt + Länge + Marker
    new_bytes = cover_bytes + enc + length_bytes + STEGO_MARKER
    atomic_write(Path(out_path), new_bytes)

def extract_hidden_file_to_path(stego_path: Path, master_pw_str: str, out_path: Path) -> None:
    """Extrahiert eine zuvor versteckte Datei aus ``stego_path`` und schreibt sie nach ``out_path``.

    Die Funktion liest am Ende der Stego-Datei den Marker ``STEGO_MARKER`` und das
    Längenfeld ein, ermittelt die verschlüsselte Nutzlast und entschlüsselt sie
    mithilfe des angegebenen Passworts. Enthält die Nutzlast einen
    eingebetteten Dateinamen (2‑Byte-Länge + Name), wird dieser entfernt und
    nur die eigentlichen Nutzdaten werden geschrieben. Bei falschem Passwort
    oder fehlender Kennzeichnung wird eine Exception ausgelöst. Den ursprünglichen
    Dateinamen erhältst du über ``decrypt_hidden_payload``, die diese
    Metainformation zurückliefert.
    """
    # Verwende decrypt_hidden_payload, um den ursprünglichen Dateinamen und die
    # Nutzdaten zu erhalten. Wir ignorieren den Namen hier und schreiben nur
    # die Nutzdaten nach out_path.
    orig_name, payload = decrypt_hidden_payload(stego_path, master_pw_str)
    atomic_write(Path(out_path), payload)

# ====================================
# SECTION F — Dateispeicher / Backup / Atomic Write
# ====================================
def atomic_write(path: Path, data: bytes) -> None:
    """
    Führe einen atomaren Schreibvorgang aus. Es wird eine zufällige temporäre
    Datei im selben Verzeichnis erstellt, die Daten werden geschrieben und
    synchronisiert und anschließend per ``os.replace`` in die Zieldatei
    verschoben. Dadurch werden „Time-of-check/Time-of-use“-Angriffe vermieden.
    Auf POSIX-Systemen wird die temporäre Datei mit restriktiven
    Zugriffsrechten (0600) angelegt.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Erzeuge sichere temporäre Datei im Zielverzeichnis
    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # set restrictive perms on POSIX
        try:
            if os.name == "posix":
                os.chmod(tmp_path, 0o600)
        except Exception:
            pass
        # Atomarer Austausch der Zieldatei
        os.replace(tmp_path, path)
        # Setze restriktive Rechte auf der endgültigen Datei (Best-effort)
        try:
            secure_chmod_600(Path(path))
        except Exception:
            pass
    finally:
        # Stelle sicher, dass die temporäre Datei entfernt wird, falls os.replace fehlschlägt
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass

def rotate_backups(path: Path, keep: int = BACKUP_KEEP) -> None:
    """
    Behalte eine bestimmte Anzahl von Backups (mit Zeitstempel).
    Backup-Name: path.name + .bak.YYYYMMDDhhmmss
    """
    bakdir = path.parent
    base = path.name
    # remove old backups beyond keep
    files = sorted([p for p in bakdir.iterdir() if p.name.startswith(base + ".bak.")], key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except Exception:
            pass

def backup_before_overwrite(path: Path) -> None:
    """
    Wenn path existiert, lege Backup mit Zeitstempel an.
    """
    if not path.exists():
        return
    t = time.strftime("%Y%m%d%H%M%S", time.localtime())
    bak = path.with_name(path.name + f".bak.{t}")
    try:
        shutil.copy2(path, bak)
    except Exception:
        try:
            shutil.copy(path, bak)
        except Exception:
            pass
    # Setze restriktive Dateirechte für Backups auf POSIX
    try:
        if os.name == "posix":
            os.chmod(bak, 0o600)
    except Exception:
        pass
    rotate_backups(path, BACKUP_KEEP)

# ====================================
# SECTION G — Serialisierung / speichern & laden
# ====================================
def save_vault(path: Path, vault: Vault, master_pw_str: str, make_backup: bool = True) -> None:
    """
    Serialisiert vault -> JSON -> bytes -> encrypt_vault_bytes -> atomic_write.
    Re-randomize: bei jedem save werden random salt/nonces/pad erzeugt.
    """
    # Baue das Objekt für die Serialisierung. Die Metadaten enthalten Zeitstempel
    # und optionale Flags über die Nutzung von Keyfile und Gerätebindung. Die
    # Flags speichern eine Bitmaske: Bit 0 steht für die Nutzung eines
    # Keyfiles, Bit 1 für die Nutzung der Gerätebindung. Dies erleichtert es
    # beim Laden festzustellen, ob der Tresor mit anderen Sicherheitsoptionen
    # erstellt wurde als aktuell konfiguriert.
    flags = 0
    try:
        if globals().get("KEYFILE_PATH"):
            flags |= 1
        if globals().get("DEVICE_BIND"):
            flags |= 2
    except Exception:
        pass
    obj = {
        "meta": {
            "created_at": vault.created_at,
            "updated_at": time.time(),
            "flags": flags,
        },
        "entries": {eid: asdict(e) for eid, e in vault.entries.items()}
    }
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    # Optionales Dateigrößen-Padding: Wenn ``MIN_VAULT_SIZE_KB`` größer als 0 ist,
    # wird später geprüft, ob die verschlüsselte Datei eine Mindestgröße unterschreitet.
    # In diesem Fall fügen wir zufällige Daten als base64-codiertes Feld
    # ``pad`` in den Metadaten hinzu und verschlüsseln erneut.
    min_size = globals().get("MIN_VAULT_SIZE_KB", 0)
    try:
        desired_bytes = int(min_size) * 1024
    except Exception:
        desired_bytes = 0

    # master_pw als bytearray zum späteren Löschen
    master_pw = bytearray(master_pw_str.encode("utf-8"))
    try:
        blob = encrypt_vault_bytes(plaintext, bytes(master_pw))
        # Padding falls erforderlich hinzufügen. Wir prüfen die resultierende
        # Blob-Größe erst nach der ersten Verschlüsselung, um den tatsächlichen
        # Overhead (Nonces, HMAC) zu berücksichtigen. Wenn die Datei zu klein
        # ist, generieren wir zufällige Bytes und fügen diese als Feld
        # ``pad`` hinzu. Anschließend wird erneut verschlüsselt. Bei Bedarf
        # versuchen wir es ein zweites Mal, falls das Ergebnis noch zu klein ist.
        if desired_bytes > 0 and len(blob) < desired_bytes:
            import os
            import base64
            missing = desired_bytes - len(blob)
            if missing < 0:
                missing = 0
            # Generiere Zufallsbytes. Die Länge entspricht der fehlenden Größe.
            pad_bytes = os.urandom(missing)
            pad_b64 = base64.b64encode(pad_bytes).decode("ascii")
            # Füge Padding in die Metadaten ein
            obj["meta"]["pad"] = pad_b64
            # Serialisiere neu und verschlüssele erneut
            plaintext2 = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            blob = encrypt_vault_bytes(plaintext2, bytes(master_pw))
            # Prüfe erneut, ob das Ziel erreicht wurde; falls nicht, versuche ein zweites Mal
            if len(blob) < desired_bytes:
                extra = desired_bytes - len(blob)
                if extra < 0:
                    extra = 0
                pad2 = os.urandom(extra)
                pad_b64_2 = base64.b64encode(pad2).decode("ascii")
                obj["meta"]["pad"] = obj["meta"].get("pad", "") + "." + pad_b64_2
                plaintext3 = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                blob = encrypt_vault_bytes(plaintext3, bytes(master_pw))
    finally:
        # wipe master password from memory (best-effort)
        for i in range(len(master_pw)):
            master_pw[i] = 0
        del master_pw

    # Backup vor dem Überschreiben nur erstellen, wenn globale Backups erlaubt sind
    # und der Aufrufer nicht explizit Backups deaktiviert hat (make_backup=False).
    if BACKUPS_ENABLED and make_backup:
        backup_before_overwrite(path)
    atomic_write(path, blob)

    # attempt to wipe plaintext variable
    try:
        z = bytearray(len(plaintext))
        del z
    except Exception:
        pass

def load_vault(path: Path, master_pw_str: str) -> Vault:
    """
    Läd die Datei, entschlüsselt mit master_pw und baut Vault Objekt auf.
    """
    with open(path, "rb") as f:
        blob = f.read()
    master_pw = bytearray(master_pw_str.encode("utf-8"))
    try:
        plaintext = decrypt_vault_bytes(blob, bytes(master_pw))
    finally:
        for i in range(len(master_pw)):
            master_pw[i] = 0
        del master_pw
    obj = json.loads(plaintext.decode("utf-8"))
    # Prüfe optionale Flags aus dem Meta-Bereich des Tresors und vergleiche mit
    # den aktuellen Konfigurationen. Bit 0 = Keyfile verwendet, Bit 1 = Gerätebindung verwendet.
    try:
        meta = obj.get("meta", {}) if isinstance(obj, dict) else {}
        flags = meta.get("flags")
        if flags is not None:
            try:
                fl = int(flags)
            except Exception:
                fl = 0
            used_keyfile = bool(fl & 1)
            used_device = bool(fl & 2)
            # Vergleiche die gespeicherten Flags mit den aktuellen globalen Einstellungen
            try:
                # Warnung, wenn der Tresor ohne Gerätebindung erstellt wurde, aber DEVICE_BIND aktiv ist
                if globals().get("DEVICE_BIND") and not used_device:
                    msg = tr(
                        "Dieser Tresor wurde ohne Gerätebindung erstellt, aber DEVICE_BIND ist aktiv.",
                        "This vault was created without device binding, but DEVICE_BIND is active."
                    )
                    try:
                        print(msg)
                    except Exception:
                        pass
                    try:
                        from tkinter import messagebox
                        messagebox.showwarning(tr("Hinweis", "Note"), msg)
                    except Exception:
                        pass
                # Warnung, wenn KEYFILE_PATH gesetzt, aber der Tresor ohne Keyfile erstellt wurde
                if globals().get("KEYFILE_PATH") and not used_keyfile:
                    msg2 = tr(
                        "Dieser Tresor wurde ohne Keyfile erstellt, aber KEYFILE_PATH ist gesetzt. Das Keyfile wird ignoriert.",
                        "This vault was created without a keyfile, but KEYFILE_PATH is set. The keyfile will be ignored."
                    )
                    try:
                        print(msg2)
                    except Exception:
                        pass
                    try:
                        from tkinter import messagebox
                        messagebox.showwarning(tr("Hinweis", "Note"), msg2)
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    v = Vault.empty()
    v.created_at = obj.get("meta", {}).get("created_at", time.time())
    v.updated_at = obj.get("meta", {}).get("updated_at", time.time())
    for eid, ed in obj.get("entries", {}).items():
        e = Entry(
            id=eid,
            label=ed.get("label", ""),
            username=ed.get("username", ""),
            email=ed.get("email", ""),
            password=ed.get("password", ""),
            info=ed.get("info", ""),
            website=ed.get("website", ""),
            created_at=ed.get("created_at", time.time()),
            updated_at=ed.get("updated_at", time.time())
        )
        v.entries[eid] = e
    # wipe plaintext
    try:
        tmp = bytearray(len(plaintext))
        del tmp
    except Exception:
        pass
    try:
        import gc
        gc.collect()
    except Exception:
        pass
    return v

# ====================================
# SECTION H — Export Funktionen (TXT / CSV) & Clipboard

def _cli_set_clipboard_temporarily(text: str, seconds: int = CLI_CLIPBOARD_CLEAR_SECONDS) -> None:
    """
    Copy the provided text to the clipboard for a limited amount of time.

    When ``pyperclip`` is available the function copies ``text`` into the
    system clipboard and spawns a background thread that clears it after
    ``seconds`` seconds.  If ``pyperclip`` is not installed a note is
    printed and the clipboard is not modified.
    """
    if not _HAS_PYPERCLIP:
        print(
            tr(
                "[Hinweis] pyperclip nicht verfügbar – kein Clipboard gesetzt.",
                "[Note] pyperclip not available – clipboard not set.",
            )
        )
        return
    try:
        pyperclip.copy(text)
        print(
            tr(
                f"[OK] In Zwischenablage kopiert. Wird in {seconds}s gelöscht.",
                f"[OK] Copied to clipboard. Will be cleared in {seconds}s.",
            )
        )
        def _wipe() -> None:
            try:
                time.sleep(max(1, int(seconds)))
                pyperclip.copy("")
            except Exception:
                pass
        t = threading.Thread(target=_wipe, daemon=True)
        t.start()
    except Exception:
        print(
            tr(
                "[Fehler] Clipboard konnte nicht gesetzt werden.",
                "[Error] Could not set clipboard.",
            )
        )

def _confirm_dangerous_export_cli() -> bool:
    if not REQUIRE_EXPLICIT_EXPORT_CONFIRM:
        return True
    try:
        ans = input(
            "\n[WARNUNG] Du bist dabei, Passwörter im KLARTEXT zu exportieren.\n"
            "Die Datei ist UNVERSCHLÜSSELT, jeder mit Dateizugriff kann sie lesen.\n"
            "Tippe genau 'JA' zum Fortfahren: "
        ).strip()
        return ans == "JA"
    except Exception:
        return False
# ====================================


# Duplicate definition of export_entry_txt removed

def export_entry_txt(v: Vault, eid: str, outpath: Optional[Path] = None) -> Path:
    if REQUIRE_EXPLICIT_EXPORT_CONFIRM and not _confirm_dangerous_export_cli():
        raise RuntimeError("Export vom Nutzer abgebrochen.")
    if eid not in v.entries:
        raise KeyError("Eintrag nicht gefunden")
    e = v.entries[eid]
    fname = outpath if outpath else Path(f"export_{safe_filename(e.label)}.txt")
    banner = (
        "############################### GEHEIM ###############################\n"
        "# KLARTEXT-EXPORT – Passwörter sind unverschlüsselt in dieser Datei #\n"
        "#####################################################################\n\n"
    )
    content = textwrap.dedent(f"""\
Label       : {e.label}
Benutzer    : {e.username}
Email       : {e.email}
Passwort    : {e.password}
Info        : {e.info}
Webseite/IP : {e.website}
Erstellt    : {fmt_de(e.created_at)}
Geändert    : {fmt_de(e.updated_at)}
""")
    _secure_write_text(fname, banner + content)
    write_audit("export_entry", f"{eid}|{e.label}")
    return fname

def export_all_txt(v: Vault, outpath: Optional[Path] = None) -> Path:
    if REQUIRE_EXPLICIT_EXPORT_CONFIRM and not _confirm_dangerous_export_cli():
        raise RuntimeError("Export vom Nutzer abgebrochen.")
    fname = outpath if outpath else Path("export_all_entries.txt")
    import io
    buf = io.StringIO()
    buf.write(
        "############################### GEHEIM ###############################\n"
        "# KLARTEXT-EXPORT – Passwörter sind unverschlüsselt in dieser Datei #\n"
        "#####################################################################\n\n"
    )
    for e in v.entries.values():
        buf.write(textwrap.dedent(f"""\
=== {e.label} ({e.id}) ===
Benutzer    : {e.username}
Email       : {e.email}
Passwort    : {e.password}
Info        : {e.info}
Webseite/IP : {e.website}
Erstellt    : {fmt_de(e.created_at)}
Geändert    : {fmt_de(e.updated_at)}

"""))
    _secure_write_text(fname, buf.getvalue())
    write_audit("export_all", f"{len(v.entries)} entries (txt)")
    return fname
def export_all_csv(v: Vault, outpath: Optional[Path] = None) -> Path:
    import io, csv
    fname = outpath if outpath else Path("export_all_entries.csv")
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(["ID", "Label", "Benutzer", "Email", "Passwort", "Info", "Webseite/IP", "Erstellt", "Geändert"])
    for e in v.entries.values():
        writer.writerow([e.id, e.label, e.username, e.email, e.password, e.info, e.website,
                         fmt_de(e.created_at), fmt_de(e.updated_at)])
    _secure_write_text(fname, buf.getvalue(), newline=True)
    return fname

def import_entries_from_csv(v: Vault, csv_path: Path) -> int:
    """Importiert Einträge aus einer CSV‑Datei in den angegebenen Tresor.

    Die CSV‑Datei muss die gleiche Struktur wie der Export enthalten (Spalten:
    ID, Label, Benutzer, Email, Passwort, Info, Webseite/IP, Erstellt, Geändert).
    Für jeden Datensatz wird eine neue eindeutige ID generiert, damit keine
    Konflikte mit bestehenden Einträgen auftreten. Die Felder "Erstellt" und
    "Geändert" werden versucht, aus dem Zeitstempel zu parsen; bei Fehlern
    wird der aktuelle Zeitpunkt verwendet.

    :param v: Der Tresor, in den importiert werden soll.
    :param csv_path: Pfad zur zu importierenden CSV‑Datei.
    :return: Anzahl erfolgreich importierter Einträge.
    """
    imported = 0
    # Öffne CSV‑Datei und lese Zeilen mit csv.DictReader
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # Prüfe, ob die erwarteten Spalten vorhanden sind
        expected = {"ID", "Label", "Benutzer", "Email", "Passwort", "Info", "Webseite/IP", "Erstellt", "Geändert"}
        if reader.fieldnames is None or not expected.issubset(set(reader.fieldnames)):
            raise ValueError("CSV-Header entspricht nicht dem erwarteten Format.")
        for row in reader:
            try:
                # Erzeuge neue ID, um Konflikte zu vermeiden
                eid = generate_entry_id(v.entries)
                # Lese Felder; fallback auf leere Strings
                label = row.get("Label", "").strip()
                username = row.get("Benutzer", "").strip()
                email = row.get("Email", "").strip()
                password = row.get("Passwort", "").strip()
                info = row.get("Info", "").strip()
                website = row.get("Webseite/IP", "").strip()
                # Parse Zeitstempel (falls möglich)
                def parse_time(val: str) -> float:
                    try:
                        return time.mktime(time.strptime(val.strip(), "%a %b %d %H:%M:%S %Y"))
                    except Exception:
                        return time.time()
                created_at = parse_time(row.get("Erstellt", ""))
                updated_at = parse_time(row.get("Geändert", ""))
                # Füge Entry hinzu
                v.entries[eid] = Entry(
                    id=eid,
                    label=label,
                    username=username,
                    email=email,
                    password=password,
                    info=info,
                    website=website,
                    created_at=created_at,
                    updated_at=updated_at,
                )
                imported += 1
            except Exception:
                # Überspringe Zeilen mit Fehlern
                continue
    # Aktualisiere Tresor-Timestamp
    if imported:
        v.updated_at = time.time()
    return imported

def cli_copy_to_clipboard(text: str) -> None:
    # Um Clipboard‑Operationen zu vereinheitlichen, definieren wir eine interne
    # Funktion, die je nach Plattform versucht, einen String in die
    # Zwischenablage zu kopieren. Sie gibt True zurück, wenn das Kopieren
    # erfolgreich war.
    def _copy(payload: str) -> bool:
        if _HAS_PYPERCLIP:
            try:
                pyperclip.copy(payload)
                return True
            except Exception:
                return False
        try:
            if sys.platform.startswith("linux"):
                p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
                p.communicate(payload.encode("utf-8"))
                return True
            elif sys.platform == "darwin":
                p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
                p.communicate(payload.encode("utf-8"))
                return True
            elif os.name == "nt":
                # Windows-Fallback: nutze PowerShell zum Setzen der Zwischenablage
                # (Set-Clipboard in neueren PowerShell-Versionen)
                cmd = "Set-Clipboard -Value $args[0]"
                subprocess.run(["powershell", "-NoProfile", "-Command", cmd, payload], check=True)
                return True
        except Exception:
            return False
        return False

    success = _copy(text)
    if success:
        print(
            tr(
                "Passwort in Zwischenablage kopiert.",
                "Password copied to clipboard.",
            )
        )
        # Starte einen Hintergrund-Thread, der nach Ablauf von CLIP_CLEAR_MS die
        # Zwischenablage wieder leert. Dadurch wird das Passwort nach einer
        # bestimmten Zeit automatisch entfernt.
        def _clear_clipboard() -> None:
            time.sleep(CLIP_CLEAR_MS / 1000.0)
            try:
                _copy("")
            except Exception:
                pass
        try:
            t = threading.Thread(target=_clear_clipboard, daemon=True)
            t.start()
        except Exception:
            pass
    else:
        print(
            tr(
                "Clipboard nicht verfügbar. Installiere 'pyperclip' oder native Tools.",
                "Clipboard not available. Install 'pyperclip' or native tools.",
            )
        )

# ====================================
# SECTION I — Passwortstärkeprüfung (optional, informativ)
# ====================================
def password_strength(password: str) -> Tuple[str, int]:
    """
    Einfache Heuristik: bewertet Passwort auf 0-100 und Kategorie.
    Dient nur als Richtwert; nicht als absolute Sicherheit.
    """
    score = 0
    length = len(password)
    if length >= 8:
        score += min(10, (length - 7) * 2)  # kleine Gewichtung für Länge
    # variety
    if any(c.islower() for c in password): score += 20
    if any(c.isupper() for c in password): score += 20
    if any(c.isdigit() for c in password): score += 20
    if any(c in "!@#$_-+.^*?" for c in password): score += 20
    # penalize common patterns
    lowers = password.lower()
    commons = ["password", "1234", "qwerty", "admin", "letmein"]
    if any(s in lowers for s in commons): score = max(10, score - 30)
    score = max(0, min(100, score))
    if score < 40:
        cat = "SCHWACH"
    elif score < 70:
        cat = "MITTEL"
    else:
        cat = "STARK"
    return cat, score

# ====================================
# SECTION J — CLI (Terminal) Implementierung
# ====================================
#
# Standardmenü (deutsch) für den CLI-Modus. Dieses Menü ist der Default und wird
# verwendet, wenn die Systemsprache Deutsch ist oder keine Sprache erkannt wird.
# Für Englisch existieren separate Definitionen (siehe unten), die in
# ``init_language`` aktiviert werden. Wir merken uns das deutsche Menü in
# ``MENU_DE``, damit es in ``init_language`` wiederhergestellt werden kann.
MENU = """\n===== Passwort-Manager (CLI) =====
[1] Einträge auflisten
[2] Eintrag anzeigen
[3] Eintrag hinzufügen
[4] Eintrag ändern
[5] Eintrag löschen
[6] Export einzelner Eintrag (TXT)
[7] Export alle (TXT)
[8] Export alle (CSV)
[9] Generiere starkes Passwort
[P] Kopiere Passwort in Zwischenablage
[S] Speichern (re-randomize)
[C] Konfig-Datei erstellen
[10] Datei verschlüsseln – Beliebige Datei mit Passwort verschlüsseln (erstellt eine .enc-Datei)
[11] Datei entschlüsseln – Entschlüsselt eine zuvor verschlüsselte .enc-Datei
[12] Datei verstecken – Verschlüsselt eine Datei und hängt sie an eine Cover-Datei an (erstellt eine .hid-Datei)
[13] Verstecktes extrahieren – Extrahiert und entschlüsselt den verborgenen Inhalt aus einer .hid-Datei
[14] Import CSV – Importiert Einträge aus einer CSV-Datei in den Tresor (IDs werden neu vergeben)
[0] Beenden (speichert automatisch)
"""

# Speichere das deutsche Menü, damit es in init_language zurückgesetzt werden kann
MENU_DE = MENU

# Menü für den CLI-Start ohne geladenen Tresor. Dieses Menü erlaubt es dem
# Benutzer, einen Tresor zu öffnen oder die Datei‑Operationen (verschlüsseln,
# entschlüsseln, verstecken, extrahieren) unabhängig vom Tresor zu nutzen. Die
# Konfigurationsdatei kann ebenfalls erstellt werden. Option "0" beendet den
# CLI-Modus ohne Tresor zu laden. Die Optionen 10–13 entsprechen denselben
# Dateifunktionen wie im Hauptmenü, sodass die Bedienung konsistent bleibt.
OUTER_MENU = """\n===== Passwort-Manager (CLI) =====
[V] Tresor öffnen
[10] Datei verschlüsseln – Beliebige Datei mit Passwort verschlüsseln (erstellt eine .enc-Datei)
[11] Datei entschlüsseln – Entschlüsselt eine zuvor verschlüsselte .enc-Datei
[12] Datei verstecken – Verschlüsselt eine Datei und hängt sie an eine Cover-Datei an (erstellt eine .hid-Datei)
[13] Verstecktes extrahieren – Extrahiert und entschlüsselt den verborgenen Inhalt aus einer .hid-Datei
[C] Konfig-Datei erstellen
[0] Beenden
"""

# Speichere das deutsche Menü für den Tresorlosen Start
OUTER_MENU_DE = OUTER_MENU

# Englisches CLI-Hauptmenü. Dieses Menü wird verwendet, wenn die Sprache auf
# Englisch (``CURRENT_LANG == 'en'``) eingestellt ist.
MENU_EN = """\n===== Password Manager (CLI) =====
[1] List entries
[2] View entry
[3] Add entry
[4] Edit entry
[5] Delete entry
[6] Export single entry (TXT)
[7] Export all (TXT)
[8] Export all (CSV)
[9] Generate strong password
[P] Copy password to clipboard
[S] Save (re-randomize)
[C] Create config file
[10] Encrypt file – Encrypt any file with a password (creates a .enc file)
[11] Decrypt file – Decrypt a previously encrypted .enc file
[12] Hide file – Encrypts a file and appends it to a cover file (creates a .hid file)
[13] Extract hidden – Extracts and decrypts the hidden content from a .hid file
[14] Import CSV – Import entries from a CSV file into the vault (IDs will be reassigned)
[0] Exit (automatically saves)
"""

# Englisches CLI-Menü für den Start ohne geladenen Tresor. Entspricht dem deutschen
# OUTER_MENU_DE, jedoch auf Englisch.
OUTER_MENU_EN = """\n===== Password Manager (CLI) =====
[V] Open vault
[10] Encrypt file – Encrypt any file with a password (creates a .enc file)
[11] Decrypt file – Decrypt a previously encrypted .enc file
[12] Hide file – Encrypts a file and appends it to a cover file (creates a .hid file)
[13] Extract hidden – Extracts and decrypts the hidden content from a .hid file
[C] Create config file
[0] Exit
"""

def cli_encrypt_file() -> None:
    """Hilfsfunktion für CLI: Beliebige Datei verschlüsseln.

    Fordert den Benutzer interaktiv nach Eingabe-, Ausgabe- und Passwortdaten.
    Bei erfolgreicher Verschlüsselung wird eine Meldung ausgegeben und ein Audit-Eintrag
    geschrieben. Fehler werden abgefangen und dem Benutzer gemeldet.
    """
    inp = input(tr("Pfad der zu verschlüsselnden Datei: ", "Path of the file to encrypt: ")).strip()
    if not inp:
        print(tr("Abbruch: kein Pfad.", "Abort: no path."))
        return
    in_path = Path(inp)
    if not in_path.is_file():
        print(tr("Datei nicht gefunden:", "File not found:"), inp)
        return
    default_out = in_path.with_suffix(in_path.suffix + ".enc")
    outp = input(tr(f"Ausgabedatei [{default_out}]: ", f"Output file [{default_out}]: ")).strip()
    if not outp:
        outp = str(default_out)
    # Passwort doppelt abfragen, um Tippfehler zu vermeiden
    pw1 = getpass.getpass(tr("Passwort für Verschlüsselung: ", "Password for encryption: "))
    if not pw1:
        print(tr("Abbruch: kein Passwort.", "Abort: no password."))
        return
    pw2 = getpass.getpass(tr("Passwort erneut eingeben: ", "Re-enter password: "))
    if pw1 != pw2:
        print(tr("Passwörter stimmen nicht überein. Abbruch.", "Passwords do not match. Abort."))
        return
    try:
        encrypt_file_data(in_path, pw1, Path(outp))
        write_audit("encrypt_file", f"{inp}->{outp}")
        print(tr(f"Datei verschlüsselt und gespeichert: {outp}", f"File encrypted and saved: {outp}"))
    except Exception as e:
        print(tr("Fehler:", "Error:"), e)


def cli_decrypt_file() -> None:
    """Hilfsfunktion für CLI: Entschlüsselt eine mit encrypt_file_data erzeugte Datei."""
    inp = input(tr("Pfad der verschlüsselten Datei: ", "Path of the encrypted file: ")).strip()
    if not inp:
        print(tr("Abbruch: kein Pfad.", "Abort: no path."))
        return
    in_path = Path(inp)
    if not in_path.is_file():
        print(tr("Datei nicht gefunden:", "File not found:"), inp)
        return
    default_out = str(in_path.with_suffix(""))
    outp = input(tr(f"Ausgabedatei [{default_out}]: ", f"Output file [{default_out}]: ")).strip()
    if not outp:
        outp = default_out
    pw = getpass.getpass(tr("Passwort für Entschlüsselung: ", "Password for decryption: "))
    if not pw:
        print(tr("Abbruch: kein Passwort.", "Abort: no password."))
        return
    try:
        decrypt_file_data(in_path, pw, Path(outp))
        write_audit("decrypt_file", f"{inp}->{outp}")
        print(tr(f"Datei entschlüsselt und gespeichert: {outp}", f"File decrypted and saved: {outp}"))
    except Exception as e:
        print(tr("Fehler:", "Error:"), e)


def cli_hide_file() -> None:
    """Hilfsfunktion für CLI: Versteckt eine Datei in einer Cover-Datei."""
    data_inp = input(tr("Pfad der zu versteckenden Datei: ", "Path of the file to hide: ")).strip()
    if not data_inp:
        print(tr("Abbruch: kein Pfad.", "Abort: no path."))
        return
    data_path = Path(data_inp)
    if not data_path.is_file():
        print(tr("Datei nicht gefunden:", "File not found:"), data_inp)
        return
    cover_inp = input(tr("Pfad der Cover-Datei: ", "Path of the cover file: ")).strip()
    if not cover_inp:
        print(tr("Abbruch: kein Cover-Pfad.", "Abort: no cover path."))
        return
    cover_path = Path(cover_inp)
    if not cover_path.is_file():
        print(tr("Cover-Datei nicht gefunden:", "Cover file not found:"), cover_inp)
        return
    default_out = cover_path.with_suffix(cover_path.suffix + ".hid")
    outp = input(tr(f"Ausgabedatei [{default_out}]: ", f"Output file [{default_out}]: ")).strip()
    if not outp:
        outp = str(default_out)
    # Passwort doppelt abfragen, um Tippfehler zu vermeiden
    pw1 = getpass.getpass(tr("Passwort für Verschlüsselung: ", "Password for encryption: "))
    if not pw1:
        print(tr("Abbruch: kein Passwort.", "Abort: no password."))
        return
    pw2 = getpass.getpass(tr("Passwort erneut eingeben: ", "Re-enter password: "))
    if pw1 != pw2:
        print(tr("Passwörter stimmen nicht überein. Abbruch.", "Passwords do not match. Abort."))
        return
    try:
        hide_file_in_file(cover_path, data_path, pw1, Path(outp))
        write_audit("hide_file", f"{data_inp}@{cover_inp}->{outp}")
        print(tr(f"Datei versteckt in {outp}", f"File hidden in {outp}"))
    except Exception as e:
        print(tr("Fehler:", "Error:"), e)


def cli_extract_hidden_file() -> None:
    """Hilfsfunktion für CLI: Extrahiert versteckte Daten aus einer Datei und gibt Originalname aus."""
    stego_inp = input(tr("Pfad der Datei mit verstecktem Inhalt: ", "Path of the file with hidden content: ")).strip()
    if not stego_inp:
        print(tr("Abbruch: kein Pfad.", "Abort: no path."))
        return
    stego_path = Path(stego_inp)
    if not stego_path.is_file():
        print(tr("Datei nicht gefunden:", "File not found:"), stego_inp)
        return
    pw = getpass.getpass(tr("Passwort für Entschlüsselung: ", "Password for decryption: "))
    if not pw:
        print(tr("Abbruch: kein Passwort.", "Abort: no password."))
        return
    try:
        orig_name, payload = decrypt_hidden_payload(stego_path, pw)
    except Exception as e:
        print(tr("Fehler:", "Error:"), e)
        return
    # Informiere den Benutzer über den erkannten Namen/Typ
    print(tr(f"Versteckte Datei erkannt: {orig_name}", f"Hidden file detected: {orig_name}"))
    # Vorschlag für Ausgabedatei: gleicher Verzeichnis wie stego, aber ursprünglicher Name
    suggested_out = stego_path.with_name(orig_name)
    outp = input(tr(f"Ausgabedatei [{suggested_out}]: ", f"Output file [{suggested_out}]: ")).strip()
    if not outp:
        outp = str(suggested_out)
    try:
        atomic_write(Path(outp), payload)
        write_audit("extract_file", f"{stego_inp}->{outp}")
        print(tr(f"Versteckte Datei extrahiert: {outp}", f"Hidden file extracted: {outp}"))
    except Exception as e:
        print(tr("Fehler beim Schreiben:", "Error while writing:"), e)

def clear_screen() -> None:
    """
    Löscht den Terminalbildschirm best‑effort.

    Im CLI‑Modus soll der Bildschirm zu Beginn jedes Menüs geleert werden,
    um eine übersichtliche Darstellung zu gewährleisten.  Unter Windows wird
    ``cls`` aufgerufen, unter Unix‑Systemen ``clear``.  Fehler werden ignoriert.
    """
    try:
        import os as _os
        if _os.name == "nt":
            _os.system("cls")
        else:
            _os.system("clear")
    except Exception:
        pass


def cli_outer_loop(default_path: Path, safe_mode: bool = SAFE_CLI_DEFAULT) -> None:
    """Erste Menüschleife für den CLI-Betrieb.

    Erlaubt dem Benutzer, einen Tresor zu laden, Dateioperationen ohne Tresor
    durchzuführen oder die Konfiguration zu erstellen. Erst beim Laden des Tresors
    wird das Master-Passwort abgefragt.
    """
    # Wenn CLI-Farben aktiviert sind, setze Hintergrund- und Schriftfarbe.
    if CLI_COLOR_ENABLED:
        # ANSI-Farben für Hintergrund und Vordergrund aktivieren.
        # Ohne Zeilenumbruch, damit weitere Ausgaben farbig bleiben.
        print(f"{CLI_BG_COLOR}{CLI_FG_COLOR}", end="")
    while True:
        # Bildschirm vor der Menüdarstellung leeren, um eine klare CLI zu erhalten
        try:
            clear_screen()
        except Exception:
            pass
        print(OUTER_MENU)
        choice = input("> ").strip().lower()
        if choice == "v":
            # Tresor laden
            cli_loop(default_path, safe_mode=safe_mode)
            # Nach dem Verlassen des Tresors kehre zum Hauptmenü zurück
        elif choice == "10":
            cli_encrypt_file()
        elif choice == "11":
            cli_decrypt_file()
        elif choice == "12":
            cli_hide_file()
        elif choice == "13":
            cli_extract_hidden_file()
        elif choice == "c":
            # Konfigurationsdatei erstellen (gleiche Logik wie im Hauptmenü)
            print(tr("Konfig-Datei erstellen", "Create config file"))
            default_name = DEFAULT_CONFIG_FILENAME
            fn = input(tr(
                f"Dateiname für Konfig-Datei [{default_name}]: ",
                f"Filename for config file [{default_name}]: "
            )).strip()
            if not fn:
                fn = default_name
            cfg_path = Path(fn)
            if not cfg_path.is_absolute():
                cfg_path = exe_dir() / cfg_path
            if cfg_path.exists():
                overwrite_prompt = tr(
                    f"Datei {cfg_path} existiert bereits – überschreiben? (ja): ",
                    f"File {cfg_path} already exists – overwrite? (yes): "
                )
                response = input(overwrite_prompt).strip().lower()
                # Akzeptiere deutsch "ja/j" und englisch "yes/y" als Zustimmung
                if response not in ("ja", "j", "yes", "y"):
                    print(tr("Abbruch der Konfig-Erstellung.", "Aborting config creation."))
                    continue
            try:
                cfg = _default_config()
                write_config_with_comments(cfg_path, cfg)
                print(tr("Konfigurationsdatei erstellt:", "Configuration file created:") + f" {cfg_path}")
                print(tr(
                    "Die Datei enthält Erläuterungen zu jedem Parameter.",
                    "The file contains explanations for each parameter."
                ))
                print(tr(
                    "Bearbeite diese Datei, um Parameter wie KDF, Auto-Lock oder Audit-Logging anzupassen.",
                    "Edit this file to adjust parameters like KDF, auto-lock or audit logging."
                ))
            except Exception as e:
                print(tr("Fehler beim Erstellen der Konfig-Datei:", "Error creating config file:") , e)
        elif choice == "0":
            print(tr("Beendet.", "Exiting."))
            # CLI-Farb zurücksetzen vor dem Exit
            if CLI_COLOR_ENABLED:
                print("\033[0m", end="")
            break
        else:
            print(tr("Unbekannte Auswahl.", "Unknown choice."))
def cli_loop(path: Path, safe_mode: bool = SAFE_CLI_DEFAULT) -> None:
    """
    CLI Hauptschleife. safe_mode=True deaktiviert Klartext-Export-Funktionen.
    """
    # Wenn CLI-Farben aktiviert sind, setze Hintergrund- und Schriftfarbe fort.
    if CLI_COLOR_ENABLED:
        print(f"{CLI_BG_COLOR}{CLI_FG_COLOR}", end="")
    # Zeige dem Benutzer, welche Tresor- und Konfigurationsdatei verwendet werden.
    print_cli_status(path)
    master_pw = getpass.getpass(tr("Master-Passwort: ", "Master password: "))
    if not master_pw:
        print(tr("Abbruch: kein Passwort.", "Abort: no password."))
        return
    if path.exists():
        try:
            vault = load_vault(path, master_pw)
        except Exception as e:
            print(tr("Fehler beim Laden:", "Error loading:"), e)
            return
    else:
        # Korrigierter Hinweis auf fehlende Tresor-Datei
        print(tr(f"Tresor-Datei nicht gefunden. Neuer Tresor wird erstellt: {path}",
                 f"Vault file not found. A new vault will be created: {path}"))
        if len(master_pw) < MIN_MASTER_PW_LEN:
            print(tr(
                f"Warnung: Master-Passwort sollte >= {MIN_MASTER_PW_LEN} Zeichen haben.",
                f"Warning: master password should be >= {MIN_MASTER_PW_LEN} characters."
            ))
        vault = Vault.empty()
        save_vault(path, vault, master_pw)
        print(tr("Leerer Tresor erstellt und gespeichert.", "Empty vault created and saved."))
    # Führe ggf. automatische Schlüsselrotation durch
    try:
        rotated = auto_rotate_if_due(path, vault, master_pw)
        if rotated:
            print(tr(
                "Tresor wurde automatisch neu verschlüsselt (Schlüsselrotation)",
                "Vault was automatically re-encrypted (key rotation)"
            ))
    except Exception:
        # Fehler bei der Rotation ignorieren; Warnung folgt ggf. separat
        pass

    # Prüfe, ob eine Schlüsselrotation empfohlen wird (Warnung in CLI ausgeben)
    maybe_warn_rotation_cli(vault)
    while True:
        # Lösche Bildschirm vor jeder Menüdarstellung, um die CLI sauber zu halten
        try:
            clear_screen()
        except Exception:
            pass
        print(MENU)
        choice = input("> ").strip().lower()
        if choice == "1":
            if not vault.entries:
                print(tr("(keine Einträge)", "(no entries)"))
            for eid, e in vault.entries.items():
                print(f"[{eid}] {e.label} — {e.username} — {e.email}")
        elif choice == "2":
            eid = input(tr("Eintrags-ID: ", "Entry ID: ")).strip()
            e = vault.entries.get(eid)
            if not e:
                print(tr("Nicht gefunden.", "Not found."))
            else:
                print(json.dumps(asdict(e), ensure_ascii=False, indent=2))
        elif choice == "3":
            # Neuer Eintrag: neben den üblichen Feldern wird auch eine Webseite/IP abgefragt.
            label = input(tr("Label: ", "Label: ")).strip()
            username = input(tr("Benutzer: ", "User: ")).strip()
            email = input(tr("Email: ", "Email: ")).strip()
            pw = input(tr("Passwort (leer = generieren): ", "Password (leave empty to generate): ")).strip()
            if not pw:
                pw = generate_password()
                print(tr("Generiertes Passwort:", "Generated password:"), pw)
            cat, score = password_strength(pw)
            print(tr("Passwortstärke:", "Password strength:") + f" {cat} ({score}/100)")
            info = input(tr("Info: ", "Info: ")).strip()
            website = input(tr("Webseite/IP: ", "Website/IP: ")).strip()
            eid = generate_entry_id(vault.entries)
            ts = time.time()
            # Legen Sie eine Kopie des Passworts als Bytearray an, um es später zu löschen
            _pw_bytes = bytearray(pw.encode("utf-8"))
            try:
                e = Entry(id=eid, label=label, username=username, email=email,
                          password=pw, info=info, website=website,
                          created_at=ts, updated_at=ts)
                vault.entries[eid] = e
                vault.updated_at = ts
                save_vault(path, vault, master_pw)
                # Audit: neuer Eintrag
                write_audit("create", f"{eid}|{label}")
                print(tr("Hinzugefügt und gespeichert:", "Added and saved:"), eid)
            finally:
                # Überschreibe das Passwort im Speicher, um seine Verweildauer zu minimieren
                for i in range(len(_pw_bytes)):
                    _pw_bytes[i] = 0
                del _pw_bytes
        elif choice == "4":
            eid = input(tr("Eintrags-ID: ", "Entry ID: ")).strip()
            e = vault.entries.get(eid)
            if not e:
                print(tr("Nicht gefunden.", "Not found."))
            else:
                label = input(tr(f"Label [{e.label}]: ", f"Label [{e.label}]: ")).strip() or e.label
                username = input(tr(f"Benutzer [{e.username}]: ", f"User [{e.username}]: ")).strip() or e.username
                email = input(tr(f"Email [{e.email}]: ", f"Email [{e.email}]: ")).strip() or e.email
                pw = input(tr("Neues Passwort (leer = unverändert): ", "New password (empty = unchanged): ")).strip()
                if pw:
                    cat, score = password_strength(pw)
                    print(tr("Passwortstärke:", "Password strength:") + f" {cat} ({score}/100)")
                    # Kopiere Passwort in Bytearray zur späteren Löschung
                    _pw_bytes2 = bytearray(pw.encode("utf-8"))
                    e.password = pw
                info = input(tr(f"Info [{e.info}]: ", f"Info [{e.info}]: ")).strip() or e.info
                website = input(tr(f"Webseite/IP [{e.website}]: ", f"Website/IP [{e.website}]: ")).strip() or e.website
                # Update der Felder
                e.website = website
                e.label, e.username, e.email, e.info = label, username, email, info
                e.updated_at = time.time()
                vault.updated_at = e.updated_at
                save_vault(path, vault, master_pw)
                # Audit: Update
                write_audit("update", f"{eid}|{e.label}")
                print(tr("Eintrag aktualisiert und gespeichert.", "Entry updated and saved."))
                # Lösche temporäres Passwort aus Speicher (falls gesetzt)
                try:
                    for i in range(len(_pw_bytes2)):
                        _pw_bytes2[i] = 0
                    del _pw_bytes2
                except Exception:
                    pass
        elif choice == "5":
            eid = input(tr("Eintrags-ID zum Löschen: ", "Entry ID to delete: ")).strip()
            if eid in vault.entries:
                confirm = input(tr(f"Wirklich löschen {vault.entries[eid].label}? (ja): ", f"Really delete {vault.entries[eid].label}? (yes): ")).strip().lower()
                # akzeptiere ja/yes
                if confirm in ("ja", "yes", "y", "j"):
                    # Audit: deletion (store label before removal)
                    lbl = vault.entries[eid].label
                    del vault.entries[eid]
                    vault.updated_at = time.time()
                    save_vault(path, vault, master_pw)
                    write_audit("delete", f"{eid}|{lbl}")
                    print(tr("Gelöscht und gespeichert.", "Deleted and saved."))
            else:
                print(tr("Nicht gefunden.", "Not found."))
        elif choice == "6":
            if safe_mode:
                print(tr("Export deaktiviert im sicheren Modus.", "Export disabled in safe mode."))
                continue
            eid = input("Eintrags-ID: ").strip()
            if eid in vault.entries:
                out = export_entry_txt(vault, eid)
                # Audit: export single entry
                write_audit("export_entry", f"{eid}|{vault.entries[eid].label}")
                print(tr("Exportiert ->", "Exported ->"), out)
            else:
                print(tr("Nicht gefunden.", "Not found."))
        elif choice == "7":
            if safe_mode:
                print("Export deaktiviert im sicheren Modus.")
                continue
            out = export_all_txt(vault)
            # Audit: export all (TXT)
            write_audit("export_all", f"{len(vault.entries)} entries (txt)")
            print("Exportiert ->", out)
        elif choice == "8":
            if safe_mode:
                print("Export deaktiviert im sicheren Modus.")
                continue
            out = export_all_csv(vault)
            # Audit: export all (CSV)
            write_audit("export_all", f"{len(vault.entries)} entries (csv)")
            print("CSV exportiert ->", out)
        elif choice == "9":
            l = input("Länge [20]: ").strip()
            try:
                n = int(l) if l else 20
            except Exception:
                n = 20
            pw = generate_password(max(8, min(128, n)))
            # Audit: generate password via CLI
            write_audit("generate_password", f"length={n}")
            print("Passwort:", pw)
        elif choice == "p":
            eid = input("Eintrags-ID: ").strip()
            e = vault.entries.get(eid)
            if not e:
                print("Nicht gefunden.")
            else:
                cli_copy_to_clipboard(e.password)
                # Audit: copy password
                write_audit("copy_password", f"{eid}|{e.label}")
        elif choice == "s":
            # re-randomize & save manually
            save_vault(path, vault, master_pw)
            # Audit: manual resave
            write_audit("rerandomize", "")
            print("Tresor neu verschlüsselt und gespeichert (re-randomized).")
        elif choice == "c":
            # Konfigurationsdatei erstellen
            print("Konfig-Datei erstellen")
            # Standard-Dateiname vorschlagen
            default_name = DEFAULT_CONFIG_FILENAME
            fn = input(f"Dateiname für Konfig-Datei [{default_name}]: ").strip()
            if not fn:
                fn = default_name
            # Verwende Skriptverzeichnis als Basis, falls kein absoluter Pfad
            cfg_path = Path(fn)
            if not cfg_path.is_absolute():
                cfg_path = exe_dir() / cfg_path
            # Warnung bei Überschreiben
            if cfg_path.exists():
                if input(f"Datei {cfg_path} existiert bereits überschreiben? (ja): ").strip().lower() != "ja":
                    print("Abbruch der Konfig-Erstellung.")
                    continue
            # Schreibe Standardkonfiguration mit Kommentaren
            try:
                cfg = _default_config()
                write_config_with_comments(cfg_path, cfg)
                print(f"Konfigurationsdatei erstellt: {cfg_path}")
                print("Die Datei enthält Erläuterungen zu jedem Parameter.")
                print("Bearbeite diese Datei, um Parameter wie KDF, Auto-Lock oder Audit-Logging anzupassen.")
            except Exception as e:
                print("Fehler beim Erstellen der Konfig-Datei:", e)
        elif choice == "10":
            # Datei verschlüsseln
            inp = input("Pfad der zu verschlüsselnden Datei: ").strip()
            if not inp:
                print("Abbruch: kein Pfad.")
            elif not Path(inp).is_file():
                print("Datei nicht gefunden:", inp)
            else:
                default_out = Path(inp).with_suffix(Path(inp).suffix + ".enc")
                outp = input(f"Ausgabedatei [{default_out}]: ").strip()
                if not outp:
                    outp = str(default_out)
                pw1 = getpass.getpass("Passwort für Verschlüsselung: ")
                if not pw1:
                    print("Abbruch: kein Passwort.")
                else:
                    pw2 = getpass.getpass("Passwort bestätigen: ")
                    if pw1 != pw2:
                        print("Abbruch: Passwörter stimmen nicht überein.")
                    else:
                        try:
                            encrypt_file_data(Path(inp), pw1, Path(outp))
                            write_audit("encrypt_file", f"{inp}->{outp}")
                            print(f"Datei verschlüsselt und gespeichert: {outp}")
                        except Exception as e:
                            print("Fehler:", e)
        elif choice == "11":
            # Datei entschlüsseln
            inp = input("Pfad der verschlüsselten Datei: ").strip()
            if not inp:
                print("Abbruch: kein Pfad.")
            elif not Path(inp).is_file():
                print("Datei nicht gefunden:", inp)
            else:
                # Standardausgabedatei: Eingabename ohne .enc-Endung
                default_out = str(Path(inp).with_suffix(""))
                outp = input(f"Ausgabedatei [{default_out}]: ").strip()
                if not outp:
                    outp = default_out
                pw = getpass.getpass("Passwort für Entschlüsselung: ")
                if not pw:
                    print("Abbruch: kein Passwort.")
                else:
                    try:
                        decrypt_file_data(Path(inp), pw, Path(outp))
                        write_audit("decrypt_file", f"{inp}->{outp}")
                        print(f"Datei entschlüsselt und gespeichert: {outp}")
                    except Exception as e:
                        print("Fehler:", e)
        elif choice == "12":
            # Datei verstecken
            data_inp = input("Pfad der zu versteckenden Datei: ").strip()
            if not data_inp:
                print("Abbruch: kein Pfad.")
            elif not Path(data_inp).is_file():
                print("Datei nicht gefunden:", data_inp)
            else:
                cover_inp = input("Pfad der Cover-Datei: ").strip()
                if not cover_inp:
                    print("Abbruch: kein Cover-Pfad.")
                elif not Path(cover_inp).is_file():
                    print("Cover-Datei nicht gefunden:", cover_inp)
                else:
                    default_out = Path(cover_inp).with_suffix(Path(cover_inp).suffix + ".hid")
                    outp = input(f"Ausgabedatei [{default_out}]: ").strip()
                    if not outp:
                        outp = str(default_out)
                    pw1 = getpass.getpass("Passwort für Verschlüsselung: ")
                    if not pw1:
                        print("Abbruch: kein Passwort.")
                    else:
                        pw2 = getpass.getpass("Passwort bestätigen: ")
                        if pw1 != pw2:
                            print("Abbruch: Passwörter stimmen nicht überein.")
                        else:
                            try:
                                hide_file_in_file(Path(cover_inp), Path(data_inp), pw1, Path(outp))
                                write_audit("hide_file", f"{data_inp}@{cover_inp}->{outp}")
                                print(f"Datei versteckt in {outp}")
                            except Exception as e:
                                print("Fehler:", e)
        elif choice == "13":
            # Versteckte Datei extrahieren
            stego_inp = input("Pfad der Datei mit verstecktem Inhalt: ").strip()
            if not stego_inp:
                print("Abbruch: kein Pfad.")
            elif not Path(stego_inp).is_file():
                print("Datei nicht gefunden:", stego_inp)
            else:
                pw = getpass.getpass("Passwort für Entschlüsselung: ")
                if not pw:
                    print("Abbruch: kein Passwort.")
                    continue
                try:
                    orig_name, payload = decrypt_hidden_payload(Path(stego_inp), pw)
                except Exception as e:
                    print("Fehler:", e)
                    continue
                # Vorschlag für Ausgabedatei: ursprünglicher Name im gleichen Verzeichnis
                suggested = Path(stego_inp).with_name(orig_name)
                outp = input(f"Ausgabedatei [{suggested}]: ").strip()
                if not outp:
                    outp = str(suggested)
                try:
                    atomic_write(Path(outp), payload)
                    write_audit("extract_file", f"{stego_inp}->{outp}")
                    print(f"Versteckte Datei extrahiert nach: {outp}")
                except Exception as e:
                    print("Fehler beim Schreiben:", e)
        elif choice == "14":
            # CSV-Import: Lese Einträge aus einer CSV-Datei und füge sie dem Tresor hinzu
            csv_inp = input("Pfad der CSV-Datei zum Importieren: ").strip()
            if not csv_inp:
                print("Abbruch: kein Pfad angegeben.")
            elif not Path(csv_inp).is_file():
                print("Datei nicht gefunden:", csv_inp)
            else:
                try:
                    count = import_entries_from_csv(vault, Path(csv_inp))
                    if count:
                        save_vault(path, vault, master_pw)
                        write_audit("import_csv", f"{count} entries")
                        print(f"{count} Einträge importiert und gespeichert.")
                    else:
                        print("Keine Einträge importiert (Datei enthielt keine gültigen Zeilen).")
                except Exception as e:
                    print("Fehler beim Import:", e)
        elif choice == "0":
            save_vault(path, vault, master_pw)
            print("Gespeichert. Bye.")
            # CLI-Farb zurücksetzen vor dem Exit
            if CLI_COLOR_ENABLED:
                print("\033[0m", end="")
            break
        else:
            print("Unbekannte Auswahl.")

# ====================================
# SECTION K — GUI Implementation (Tkinter)
# ====================================
def import_tk():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, simpledialog, filedialog
        return tk, ttk, messagebox, simpledialog, filedialog
    except Exception:
        return None, None, None, None, None

tk, ttk, messagebox, simpledialog, filedialog = import_tk()

def launch_gui(path: Path) -> None:
    """
    Startet die Tkinter GUI. Falls Tk nicht vorhanden, wird eine Meldung ausgegeben.
    """
    if tk is None:
        print("Tkinter nicht verfügbar. Starte CLI mit --cli.")
        return

    class App:
        def __init__(self, root, path: Path):
            self.root = root
            # Originales Theme merken, um nach dem Umschalten von Hell/Dunkel
            # wieder darauf zurückschalten zu können. Sollte das Abrufen
            # fehlschlagen, wird einfach ein leerer String gespeichert.
            try:
                self._orig_theme = ttk.Style().theme_use()
            except Exception:
                self._orig_theme = ""
            # Wende GUI-Farben nur an, wenn entsprechende Parameter gesetzt sind. Andernfalls
            # bleibt das Systemdesign erhalten. Die Farbparameter können über die
            # Konfigurationsdatei angepasst werden. Leere Strings bedeuten: keine Anpassung.
                if GUI_BG_COLOR or GUI_FG_COLOR or GUI_BUTTON_COLOR:
                    try:
                        # Setze den Hintergrund der Root auf die konfigurierte Farbe
                        if GUI_BG_COLOR:
                            self.root.configure(bg=GUI_BG_COLOR)
                        # Erstelle ein Style‑Objekt und merke das ursprüngliche Tk‑Theme
                        style = ttk.Style()
                        try:
                            self._orig_theme = style.theme_use()
                        except Exception:
                            self._orig_theme = ""
                        # Wähle ein Theme, das Farbänderungen erlaubt
                        try:
                            # Theme nicht mehr auf 'clam' umschalten, da Theme-Wechsel
                            # auf manchen Systemen zu Darstellungsfehlern führt.
                            # style.theme_use('clam')
                            pass
                        except Exception:
                            pass
                        # Wende Farben für Frames, Labels und Buttons an (nur wenn definiert)
                        if GUI_BG_COLOR:
                            style.configure('TFrame', background=GUI_BG_COLOR)
                            style.configure('TLabel', background=GUI_BG_COLOR)
                            style.configure('TLabelframe', background=GUI_BG_COLOR)
                            style.configure('TLabelframe.Label', background=GUI_BG_COLOR, foreground=GUI_FG_COLOR or None)
                        if GUI_FG_COLOR:
                            style.configure('TLabel', foreground=GUI_FG_COLOR)
                        if GUI_BUTTON_COLOR or GUI_FG_COLOR:
                            fg = GUI_FG_COLOR if GUI_FG_COLOR else None
                            bg = GUI_BUTTON_COLOR if GUI_BUTTON_COLOR else None
                            style.configure('TButton', background=bg, foreground=fg)
                        # Setze Hintergründe für Eingabefelder und Comboboxen
                        style.configure('TEntry', fieldbackground=ENTRY_BG_COLOR, background=ENTRY_BG_COLOR)
                        style.configure('TCombobox', fieldbackground=ENTRY_BG_COLOR, background=ENTRY_BG_COLOR)
                        # Definiere Hover- und Press-Zustände für Buttons im hellen Modus
                        hover_bg = "#e5e5e5"
                        pressed_bg = "#d5d5d5"
                        style.map('TButton',
                                  background=[('active', hover_bg), ('pressed', pressed_bg)],
                                  foreground=[('active', GUI_FG_COLOR or None), ('pressed', GUI_FG_COLOR or None)])
                    except Exception:
                        # Bei Fehlermeldungen nichts tun – Standardfarben werden beibehalten
                        pass
            self.path = path
            # Zustand für Hell/Dunkel‑Modus.  Standardmäßig wird das vom Skript bzw.
            # der Konfiguration vorgegebene Farbschema verwendet.  Beim ersten
            # Umschalten speichern wir die ursprünglichen Farben, damit wir sie
            # später wiederherstellen können.
            self.dark_mode = False
            # Merke die ursprünglichen Farbschemas, um sie nach dem Ausschalten
            # des dunklen Modus wiederherzustellen.  Leere Strings werden zu
            # None gewandelt, damit wir bei der Revertierung korrekt auf das
            # Standardschema zurückfallen können.
            self._orig_gui_bg_color = GUI_BG_COLOR or ""
            self._orig_gui_fg_color = GUI_FG_COLOR or ""
            self._orig_gui_button_color = GUI_BUTTON_COLOR or ""
            self.vault: Optional[Vault] = None
            self.master_pw: Optional[str] = None
            self.last_activity = time.time()
            root.title("pwmanager")
            # Größeres Standardfenster: Breite 1200px, Höhe 900px. Bei Bedarf
            # kann der Benutzer das Fenster verkleinern; mit den Scrollleisten
            # bleiben alle Inhalte erreichbar.
            root.geometry("1200x900")
            # Mindestgröße setzen, damit alle Bedienelemente (insbesondere der
            # "Konfig bearbeiten"-Knopf) vollständig sichtbar bleiben. Der
            # Benutzer kann das Fenster darüber hinaus vergrößern, aber
            # nicht kleiner als diese Werte ziehen.
            root.minsize(1000, 800)
            # Versuche, ein eigenes Icon zu setzen. Falls dies fehlschlägt (z. B. auf
            # Plattformen ohne PhotoImage-Support), bleibt das Standard-Icon bestehen.
            try:
                import base64
                import tkinter as tk  # Import hier erneut, falls oben nicht geladen
                _icon_data = ICON_PNG_BASE64
                # Tk akzeptiert Base64-kodierte PNG-Bilder direkt im data-Parameter.
                icon_image = tk.PhotoImage(data=_icon_data)
                # Die Referenz wird in der Instanz gespeichert, um sie vor dem
                # Garbage Collector zu schützen.
                self._icon_image = icon_image
                self.root.iconphoto(True, icon_image)
            except Exception:
                pass
            root.protocol("WM_DELETE_WINDOW", self.on_close)
            self.root.after(1000, self._autolock_check)
            # Variablen für erweiterte Datei-Operationen (verstecken/extrahieren)
            # Hier werden die ausgewählten Pfade gespeichert und in der GUI angezeigt.
            # Diese Variablen müssen definiert sein, bevor build_login_ui aufgerufen wird,
            # damit die GUI auf sie zugreifen kann.
            try:
                import tkinter as tk  # Lokaler Import, falls Tkinter deaktiviert ist
                self.hide_data_path = tk.StringVar(value="")
                self.hide_cover_path = tk.StringVar(value="")
                self.hide_output_path = tk.StringVar(value="")
                self.extract_stego_path = tk.StringVar(value="")
                # Zielpfad für die extrahierte Datei
                self.extract_output_path = tk.StringVar(value="")
            except Exception:
                # Falls Tk nicht verfügbar ist, initialisiere Strings normal
                self.hide_data_path = ""
                self.hide_cover_path = ""
                self.hide_output_path = ""
                self.extract_stego_path = ""
                self.extract_output_path = ""
            # Baue nun die Login-UI auf. Die vorher definierten Variablen werden von
            # build_login_ui verwendet.
            self.build_login_ui()

        def toggle_dark_mode(self) -> None:
            """
            Schaltet zwischen hellem und dunklem Farbschema um, ohne das
            zugrunde liegende ttk-Theme zu wechseln. Stattdessen werden nur die
            globalen Farben und Style-Einstellungen aktualisiert, um
            Darstellungsfehler bei Theme-Wechseln zu vermeiden.
            """
            # Globale Farbkonstanten anpassen
            global GUI_BG_COLOR, GUI_FG_COLOR, GUI_BUTTON_COLOR, ENTRY_BG_COLOR, TABLE_BG_COLOR

            try:
                if not getattr(self, "dark_mode", False):
                    # Dunklen Modus aktivieren
                    self.dark_mode = True
                    GUI_BG_COLOR = "#2e2e2e"
                    GUI_FG_COLOR = "#f0f0f0"
                    GUI_BUTTON_COLOR = "#444444"
                    ENTRY_BG_COLOR = "#3c3c3c"
                    TABLE_BG_COLOR = "#3a3a3a"
                else:
                    # Dunklen Modus deaktivieren – ursprüngliche Farben wiederherstellen
                    self.dark_mode = False
                    GUI_BG_COLOR = self._orig_gui_bg_color or ""
                    GUI_FG_COLOR = self._orig_gui_fg_color or ""
                    GUI_BUTTON_COLOR = self._orig_gui_button_color or ""
                    # Standard-Hintergründe für Eingabe/Tabelle im hellen Modus
                    ENTRY_BG_COLOR = "#f5f5f5"
                    TABLE_BG_COLOR = "#f9f9f9"
            except Exception:
                # Falls irgendwas mit den Attributen schief geht, lieber gar
                # nichts tun als das Layout zu zerstören.
                pass

            # Änderungen auf Tkinter-Styles und Widgets anwenden
            try:
                import tkinter as tk
                from tkinter import ttk

                # Hintergrund des Hauptfensters
                if GUI_BG_COLOR:
                    self.root.configure(bg=GUI_BG_COLOR)
                else:
                    # leere Farbe = System-Standard
                    self.root.configure(bg="")

                style = ttk.Style()

                # Theme je nach Modus wählen: im Dunkelmodus "clam", im hellen
                # Modus wieder das ursprüngliche Theme, falls bekannt.
                try:
                    if getattr(self, "dark_mode", False):
                        # Ursprüngliches Theme ggf. einmalig merken
                        if not getattr(self, "_orig_theme", ""):
                            try:
                                self._orig_theme = style.theme_use()
                            except Exception:
                                self._orig_theme = ""
                        # style.theme_use("clam")  # deaktiviert, um Render-Probleme zu vermeiden
                        pass  # Block darf nicht leer sein
                    else:
                        orig = getattr(self, "_orig_theme", "")
                        if orig:
                            # style.theme_use(orig)  # deaktiviert, um Render-Probleme zu vermeiden
                            pass  # Block darf nicht leer sein
                        else:
                            # Wenn nichts bekannt ist, nicht am Theme drehen –
                            # das verhindert viele Darstellungsfehler.
                            pass
                except Exception:
                    pass

                # ---- ttk-Styles anpassen ----
                # Frames / Labels / Labelframes
                if GUI_BG_COLOR:
                    style.configure("TFrame", background=GUI_BG_COLOR)
                    style.configure("TLabel", background=GUI_BG_COLOR)
                    style.configure("TLabelframe", background=GUI_BG_COLOR)
                    style.configure(
                        "TLabelframe.Label",
                        background=GUI_BG_COLOR,
                        foreground=GUI_FG_COLOR or None,
                    )
                else:
                    # explizite Farben entfernen → System-Standard
                    style.configure("TFrame", background="")
                    style.configure("TLabel", background="")
                    style.configure("TLabelframe", background="")
                    style.configure("TLabelframe.Label", background="", foreground="")

                # Schriftfarbe
                if GUI_FG_COLOR:
                    style.configure("TLabel", foreground=GUI_FG_COLOR)
                else:
                    style.configure("TLabel", foreground="")

                # Button-Farben
                if GUI_BUTTON_COLOR or GUI_FG_COLOR:
                    fg = GUI_FG_COLOR if GUI_FG_COLOR else None
                    bg = GUI_BUTTON_COLOR if GUI_BUTTON_COLOR else None
                    style.configure("TButton", foreground=fg, background=bg)
                else:
                    style.configure("TButton", foreground="", background="")

                # Hover/pressed für Buttons – je nach Modus andere Töne
                try:
                    hover_bg = "#555555" if getattr(self, "dark_mode", False) else "#e5e5e5"
                    pressed_bg = "#666666" if getattr(self, "dark_mode", False) else "#d5d5d5"
                    style.map(
                        "TButton",
                        background=[("active", hover_bg), ("pressed", pressed_bg)],
                        foreground=[
                            ("active", GUI_FG_COLOR or None),
                            ("pressed", GUI_FG_COLOR or None),
                        ],
                    )
                except Exception:
                    pass

                # Entry / Combobox
                try:
                    style.configure("TEntry", fieldbackground=ENTRY_BG_COLOR, background=ENTRY_BG_COLOR)
                    style.configure("TCombobox", fieldbackground=ENTRY_BG_COLOR, background=ENTRY_BG_COLOR)
                except Exception:
                    pass

                # Treeview
                try:
                    style.configure(
                        "Treeview",
                        background=TABLE_BG_COLOR,
                        fieldbackground=TABLE_BG_COLOR,
                        foreground=GUI_FG_COLOR or None,
                    )
                    style.configure(
                        "Treeview.Heading",
                        background=GUI_BG_COLOR or "",
                        foreground=GUI_FG_COLOR or None,
                    )
                except Exception:
                    pass

                # ---- klassische Tk-Widgets (Canvas, Text usw.) nachfärben ----
                def _apply_widget_theme(widget):
                    try:
                        if isinstance(widget, tk.Text):
                            widget.configure(background=ENTRY_BG_COLOR)
                            if GUI_FG_COLOR:
                                widget.configure(foreground=GUI_FG_COLOR)
                        elif isinstance(widget, tk.Canvas):
                            if GUI_BG_COLOR:
                                widget.configure(background=GUI_BG_COLOR)
                            else:
                                widget.configure(background=self.root.cget("bg"))
                    except Exception:
                        pass
                    # Rekursiv auf alle Kinder anwenden
                    for child in widget.winfo_children():
                        _apply_widget_theme(child)

                _apply_widget_theme(self.root)

            except Exception:
                # Falls Tkinter hier irgendwas wirft, lieber leise ignorieren,
                # als die Anwendung zu crashen.
                pass

            # Nach dem Umschalten Oberfläche neu aufbauen, damit alle Widgets
            # sauber mit dem neuen Farbschema erzeugt werden. Das vermeidet
            # Darstellungsfehler wie beim Zurückwechseln von dunkel zu hell.
            try:
                # Je nach Tresorstatus die passende Oberfläche aufbauen
                if getattr(self, "vault", None) is None:
                    # Kein Tresor geöffnet → Login-UI neu aufbauen
                    self.build_login_ui()
                else:
                    # Tresor geöffnet → Haupt-UI neu aufbauen
                    self.build_main_ui()
            except Exception:
                # Bei Fehlern hier nicht crashen – Layout soll stabil bleiben
                pass


        def touch(self):
            self.last_activity = time.time()

        def run_with_progress(self, title: str, message: str,
                              func, args: tuple = (), kwargs: Optional[dict] = None,
                              on_success: Optional[Callable] = None,
                              on_error: Optional[Callable[[Exception], None]] = None) -> None:
            """
            Führe eine rechenintensive Funktion in einem Hintergrund‑Thread aus und
            zeige währenddessen einen modalen Fortschrittsdialog an.

            Diese Methode öffnet ein kleines TopLevel‑Fenster mit einer
            Überschrift und einem animierten Fortschrittsbalken. Die übergebene
            Funktion ``func`` wird in einem separaten Thread ausgeführt. Nach
            Abschluss ruft der Hauptthread entweder ``on_success`` oder
            ``on_error`` auf und schließt den Dialog. Dadurch bleibt die GUI
            responsiv und der Benutzer erhält visuelles Feedback, dass die
            Anwendung arbeitet. Das Fenster wird als oberstes Fenster
            (`-topmost`) geöffnet, so dass es nicht hinter anderen Fenstern
            verschwindet.

            :param title: Fenstertitel des Fortschrittsdialogs
            :param message: Text, der unter der Überschrift angezeigt wird
            :param func: Funktion, die ausgeführt werden soll
            :param args: Argumente für ``func``
            :param kwargs: Keyword‑Argumente für ``func``
            :param on_success: Callback mit dem Rückgabewert von ``func`` bei Erfolg
            :param on_error: Callback bei Ausnahme; erhält die Exception
            """
            import tkinter as tk
            if kwargs is None:
                kwargs = {}

            # Erstelle modales Fenster mit Fortschrittsbalken
            progress = tk.Toplevel(self.root)
            progress.title(title)
            # Setze Fenster als Kind des Hauptfensters und immer im Vordergrund
            progress.transient(self.root)
            try:
                progress.attributes("-topmost", True)
            except Exception:
                pass
            progress.grab_set()
            ttk.Label(progress, text=message, wraplength=400).pack(padx=20, pady=(20, 10))
            bar = ttk.Progressbar(progress, mode="indeterminate")
            bar.pack(fill="x", padx=20, pady=(0, 20))
            bar.start(10)

            def worker():
                """Führt die übergebene Funktion im Hintergrund aus."""
                try:
                    result = func(*args, **kwargs)
                    # Erfolgreich; Abschluss im UI‑Thread planen
                    progress.after(0, lambda: finish(result))
                except Exception as exc:
                    # Die Exception in einem Default-Argument an die Lambda binden.
                    # Ohne diese Bindung würde ``exc`` beim Ausführen der Lambda
                    # nicht mehr im Gültigkeitsbereich sein, was zu einem
                    # ``NameError`` führt. Durch ``exc=exc`` bleibt die
                    # ursprüngliche Exception erhalten und wird korrekt
                    # an handle_error übergeben.
                    progress.after(0, lambda exc=exc: handle_error(exc))

            def finish(res):
                # Stoppe Balken, gib den Grab frei und zerstöre den Dialog
                try:
                    bar.stop()
                except Exception:
                    pass
                try:
                    progress.grab_release()
                except Exception:
                    pass
                try:
                    progress.destroy()
                except Exception:
                    pass
                # Callback aufrufen
                if on_success:
                    try:
                        on_success(res)
                    except Exception:
                        pass

            def handle_error(exc: Exception):
                # Stoppe Balken, gib den Grab frei und schließe den Dialog
                try:
                    bar.stop()
                except Exception:
                    pass
                try:
                    progress.grab_release()
                except Exception:
                    pass
                try:
                    progress.destroy()
                except Exception:
                    pass
                # Callback für Fehler
                if on_error:
                    try:
                        on_error(exc)
                    except Exception:
                        pass
                else:
                    # Wenn kein Callback, zeige die Exception in der gewählten Sprache an
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr("Operation fehlgeschlagen:", "Operation failed:") + f"\n{exc}",
                        parent=self.root,
                    )

            # Starte Hintergrund‑Thread
            t = threading.Thread(target=worker, daemon=True)
            t.start()

        def toggle_language(self) -> None:
            """
            Umschalten der Sprache zwischen Deutsch und Englisch.

            Diese Methode wechselt die globale Spracheinstellung und baut
            anschließend die aktuelle GUI neu auf. Zusätzlich wird
            init_language() aufgerufen, um die CLI-Menüs zu aktualisieren.
            """
            try:
                cur = globals().get('CURRENT_LANG', 'de')
                # Toggle Sprachvariable
                if cur == 'de':
                    globals()['CURRENT_LANG'] = 'en'
                else:
                    globals()['CURRENT_LANG'] = 'de'
                # Setze FORCE_LANG, damit init_language() die neue Sprache übernimmt. Ohne dies
                # würde init_language() ggf. die Systemsprache oder die vorherige Sprache
                # beibehalten und das Umschalten hätte keinen Effekt.
                try:
                    globals()['FORCE_LANG'] = globals().get('CURRENT_LANG', 'de')
                except Exception:
                    pass
                # Reinitialisiere Sprachabhängige Konstanten
                try:
                    init_language()
                except Exception:
                    pass
                # Baue die Oberfläche abhängig vom Tresorstatus neu auf
                if self.vault is None:
                    self.build_login_ui()
                else:
                    self.build_main_ui()
            except Exception:
                pass

        def build_login_ui(self):
            """Erstellt die Login-Oberfläche mit Scrollleisten.

            Diese Methode baut das Login-Fenster vollständig neu auf. Der gesamte
            Inhalt wird in einem scrollbaren Canvas untergebracht, sodass
            Benutzer mit kleineren Bildschirmauflösungen vertikal und
            horizontal scrollen können. Am unteren Rand befindet sich ein
            separater Bereich für den Werbehinweis mit einem klickbaren
            Telegram-Link.
            """
            # Vorhandene Widgets entfernen
            for w in self.root.winfo_children():
                w.destroy()
            # Lokaler Import: Tkinter bereitstellen
            import tkinter as tk
            # Hauptcontainer mit Canvas und Scrollleisten
            container = ttk.Frame(self.root)
            container.pack(fill="both", expand=True)
            canvas = tk.Canvas(container, highlightthickness=0)
            vscroll = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
            hscroll = ttk.Scrollbar(container, orient="horizontal", command=canvas.xview)
            canvas.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
            vscroll.pack(side="right", fill="y")
            hscroll.pack(side="bottom", fill="x")
            canvas.pack(side="left", fill="both", expand=True)
            # Innerer Frame im Canvas für Inhalte
            frm = ttk.Frame(canvas, padding=12)
            canvas_window = canvas.create_window((0, 0), window=frm, anchor="nw")
            # Scrollregion aktualisieren, wenn sich der Frame ändert
            def on_frame_configure(event):
                canvas.configure(scrollregion=canvas.bbox("all"))
            frm.bind("<Configure>", on_frame_configure)
            # Breite des inneren Frames an die Canvasbreite anpassen
            def on_canvas_resize(event):
                canvas.itemconfig(canvas_window, width=event.width)
            canvas.bind("<Configure>", on_canvas_resize)
            # Mausrad für vertikales Scrollen binden
            def _on_mousewheel(event):
                # Windows/Mac: event.delta, Linux: event.num
                if hasattr(event, "delta"):
                    if event.delta > 0:
                        canvas.yview_scroll(-1, "units")
                    elif event.delta < 0:
                        canvas.yview_scroll(1, "units")
                else:
                    if event.num == 4:
                        canvas.yview_scroll(-1, "units")
                    elif event.num == 5:
                        canvas.yview_scroll(1, "units")
            # Binde global an Canvas
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)
            # Oberer Bereich: Master-Passwort und Buttons
            # Überschrift für das Master-Passwort – übersetzt je nach Sprache
            ttk.Label(frm, text=tr("Master-Passwort", "Master Password"), font=("TkDefaultFont", 14)).pack(pady=(10, 6))
            self.pw_entry = ttk.Entry(frm, show="*", width=44)
            self.pw_entry.pack()
            self.pw_entry.focus()
            # Enter-Taste entsperrt Tresor
            self.pw_entry.bind("<Return>", lambda event: self.gui_unlock())
            # Schaltflächenzeile
            btns = ttk.Frame(frm)
            btns.pack(pady=10, fill="x")
            # Schaltflächen mit übersetzten Beschriftungen
            ttk.Button(btns, text=tr("Öffnen", "Open"), command=self.gui_unlock).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("Neuer Tresor", "New Vault"), command=self.gui_create).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("Tresor-Datei wählen", "Select vault file"), command=self.gui_select_file).pack(side="left", padx=6)
            # Konfig laden: ermöglicht Auswahl einer Konfigurationsdatei
            ttk.Button(btns, text=tr("Konfig laden", "Load config"), command=self.gui_select_config).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("Konfig erstellen", "Create config"), command=self.gui_create_config).pack(side="left", padx=6)
            # Zusätzliche Schaltfläche, um die geladene Konfiguration direkt im Programm zu bearbeiten
            ttk.Button(btns, text=tr("Konfig bearbeiten", "Edit config"), command=self.gui_edit_config).pack(side="left", padx=6)
            # Sprachen-Schaltfläche zum Umschalten der UI-Sprache
            ttk.Button(btns, text=tr("Sprache wechseln", "Switch language"), command=self.toggle_language).pack(side="left", padx=6)
            # Hell/Dunkel‑Schalter auf dem Login‑Bildschirm hinzufügen.  Damit kann
            # der Benutzer schon vor dem Öffnen eines Tresors das Farbschema
            # umschalten.  Der Schalter wird nur angezeigt, wenn
            # SHOW_LIGHT_DARK_TOGGLE aktiviert ist.
            if SHOW_LIGHT_DARK_TOGGLE:
                ttk.Button(btns, text=tr("Hell/Dunkel", "Light/Dark"), command=self.toggle_dark_mode).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("Hilfe", "Help"), command=self.show_help).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("Beenden", "Exit"), command=self.root.destroy).pack(side="left", padx=6)
            # Der Hinweis zum deaktivierten Farbschema-Umschalter wird weiter unten im Statusbereich angezeigt.
            # Berechne Tresor- und Konfigurationsstatus zur Anzeige
            try:
                def_vault = default_vault_path()
            except Exception:
                def_vault = None
            # Neuer Tresorstatus: deutliche Formulierung und Farbcodierung
            is_default = bool(def_vault and Path(self.path).resolve() == Path(def_vault).resolve())
            if self.path.exists():
                if is_default:
                    vault_msg = tr(f"Standard-Tresor-Datei gefunden oder geladen: {self.path}",
                                   f"Default vault file found or loaded: {self.path}")
                else:
                    vault_msg = tr(f"Externe Tresor-Datei gefunden oder geladen: {self.path}",
                                   f"External vault file found or loaded: {self.path}")
                vault_color = "green"
            else:
                if is_default:
                    vault_msg = tr(
                        "Keine Standard-Tresor-Datei gefunden oder kein Tresor-Datei geladen, es wird ein neuer Tresor erstellt.",
                        "No default vault file found or no vault file loaded, a new vault will be created."
                    )
                else:
                    vault_msg = tr(
                        "Keine Tresor-Datei gefunden oder geladen, es wird ein neuer Tresor erstellt.",
                        "No vault file found or loaded, a new vault will be created."
                    )
                vault_color = "red"
            # Konfigstatus bestimmen
            try:
                active_cfg = globals().get("ACTIVE_CONFIG_PATH")
                default_cfg = exe_dir() / DEFAULT_CONFIG_FILENAME
                if not active_cfg:
                    if default_cfg.exists():
                        cfg_msg = tr(
                            "Keine gültige externe Konfiguration geladen – Standardwerte werden verwendet.",
                            "No valid external configuration loaded – default values are used."
                        )
                        cfg_color = "black"
                    else:
                        cfg_msg = tr(
                            "Keine Konfiguration gefunden – es werden die im Skript hinterlegten Werte verwendet.",
                            "No configuration found – using values embedded in the script."
                        )
                        cfg_color = "black"
                elif Path(active_cfg).resolve() == default_cfg.resolve():
                    cfg_msg = tr(
                        f"Standard-Konfigurationsdatei geladen: {active_cfg}",
                        f"Default configuration file loaded: {active_cfg}"
                    )
                    cfg_color = "blue"
                else:
                    cfg_msg = tr(
                        f"Externe Konfigurationsdatei geladen: {active_cfg}",
                        f"External configuration file loaded: {active_cfg}"
                    )
                    cfg_color = "green"
            except Exception:
                cfg_msg = tr(
                    "Konfigurationsstatus konnte nicht ermittelt werden.",
                    "Could not determine configuration status."
                )
                cfg_color = "black"
            # Hinweistext
            # Erklärt die Dateiendung .pwm und das Laden der Konfiguration. Für die englische
            # Version werden die Hinweise übersetzt und in das f-String eingebettet. Die
            # Variablen für Dateinamen werden dynamisch eingesetzt.
            info_text = tr(
                f"Hinweis: Tresor-Dateien haben die Endung .pwm. Existiert die Datei nicht, wird sie beim Speichern automatisch angelegt.\n"
                f"Die Konfiguration wird, falls vorhanden, automatisch aus '{DEFAULT_CONFIG_FILENAME}' geladen. Über den Button 'Konfig laden' kannst du eine andere Datei auswählen.\n",
                f"Note: Vault files have the .pwm extension. If the file does not exist, it will be created when saving.\n"
                f"The configuration, if present, is automatically loaded from '{DEFAULT_CONFIG_FILENAME}'. Use the 'Load config' button to select a different file.\n"
            )
            ttk.Label(frm, text=info_text, wraplength=700, justify="left").pack(pady=(6, 2), anchor="w")
            # Statusausgabe mit Übersetzung
            ttk.Label(frm, text=tr("Status:", "Status:"), foreground="blue").pack(anchor="w")
            ttk.Label(frm, text=vault_msg, foreground=vault_color).pack(anchor="w")
            ttk.Label(frm, text=cfg_msg, foreground=cfg_color).pack(anchor="w", pady=(0, 6))
            # Hinweis zum Farbschema-Umschalter wurde in die Hilfe verschoben.
            # Frühere Versuchs-Hinweise (leere Zeile, „Versuchsweise:“, ausführliche Meldung)
            # werden nicht mehr im Hauptfenster angezeigt.
            # Datei-Operationen für beliebige Dateien
            file_ops = ttk.LabelFrame(frm, text=tr("Datei-Operationen", "File operations"), padding=8)
            file_ops.pack(fill="x", pady=(8, 8))
            ttk.Label(file_ops,
                      text=tr(
                          "Hier können Sie beliebige Dateien verschlüsseln, entschlüsseln oder in andere Dateien verstecken.\nDiese Funktionen arbeiten unabhängig von Ihrem Tresor.",
                          "Here you can encrypt, decrypt or hide arbitrary files.\nThese functions operate independently of your vault."
                      ),
                      wraplength=700,
                      justify="left").pack(anchor="w", pady=(0, 6))
            enc_frame = ttk.Frame(file_ops)
            enc_frame.pack(fill="x", pady=(0, 4))
            ttk.Button(enc_frame, text=tr("Datei verschlüsseln", "Encrypt file"), command=self.gui_encrypt_any_file).pack(fill="x", pady=2)
            ttk.Button(enc_frame, text=tr("Datei entschlüsseln", "Decrypt file"), command=self.gui_decrypt_any_file).pack(fill="x", pady=2)
            steg_frame = ttk.LabelFrame(file_ops, text=tr("Datei verstecken und extrahieren", "Hide and extract file"), padding=6)
            steg_frame.pack(fill="x", pady=(6, 0))
            ttk.Label(steg_frame,
                      text=tr(
                          "Datei verstecken: Wählen Sie zunächst die zu versteckende Datei, dann die Cover-Datei (Träger) und anschließend einen Ausgabepfad.\nDer Inhalt wird verschlüsselt und ans Ende der Cover-Datei angehängt.",
                          "Hide file: First select the file to hide, then the cover file (carrier), and finally an output path.\nThe content will be encrypted and appended to the end of the cover file."
                      ),
                      wraplength=700,
                      justify="left").pack(anchor="w", pady=(0, 4))
            hide_ops = ttk.Frame(steg_frame)
            hide_ops.pack(fill="x", pady=(0, 8))
            ttk.Button(hide_ops, text=tr("Zu versteckende Datei", "File to hide"), command=self.gui_select_hide_data).grid(row=0, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_data_path, wraplength=500).grid(row=0, column=1, sticky="w", padx=6)
            ttk.Button(hide_ops, text=tr("Cover-Datei", "Cover file"), command=self.gui_select_hide_cover).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_cover_path, wraplength=500).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(hide_ops, text=tr("Ziel (.hid)", "Target (.hid)"), command=self.gui_select_hide_output).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_output_path, wraplength=500).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(hide_ops, text=tr("Verstecken", "Hide"), command=self.gui_do_hide).grid(row=3, column=0, sticky="w", pady=(4, 6))
            ttk.Label(steg_frame,
                      text=tr(
                          "Verstecktes extrahieren: Wählen Sie die .hid-Datei mit verstecktem Inhalt und anschließend einen\nAusgabepfad. Der versteckte Inhalt wird entschlüsselt und als separate Datei gespeichert.",
                          "Extract hidden: Select the .hid file with hidden content and then an output path.\nThe hidden content is decrypted and saved as a separate file."
                      ),
                      wraplength=700,
                      justify="left").pack(anchor="w", pady=(0, 4))
            extract_ops = ttk.Frame(steg_frame)
            extract_ops.pack(fill="x")
            ttk.Button(extract_ops, text=tr(".hid-Datei", ".hid file"), command=self.gui_select_extract_stego).grid(row=0, column=0, sticky="w", pady=2)
            ttk.Label(extract_ops, textvariable=self.extract_stego_path, wraplength=500).grid(row=0, column=1, sticky="w", padx=6)
            ttk.Button(extract_ops, text=tr("Ziel-Datei", "Target file"), command=self.gui_select_extract_output).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(extract_ops, textvariable=self.extract_output_path, wraplength=500).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(extract_ops, text=tr("Extrahieren", "Extract"), command=self.gui_do_extract).grid(row=2, column=0, sticky="w", pady=(4, 6))
            # Werbebereich unten: zwei Zeilen, zweiter Link ist klickbar
            # Telegram‑Hinweis am unteren Rand des Login‑Fensters.  Die Anzeige
            # erfolgt nur, wenn SHOW_TELEGRAM_AD aktiv ist.  Der Link öffnet
            # TELEGRAM_TARGET, nicht nur den angezeigten Text.
            if SHOW_TELEGRAM_AD:
                adv_frame = ttk.Frame(self.root, padding=(6, 4))
                adv_frame.pack(fill="x")
                # Werbetext im unteren Bereich des Login-Fensters; der Zeilenumbruch
                # (wraplength) sorgt dafür, dass der gesamte Text bei schmaler
                # Fensterbreite sichtbar bleibt.
                # Werbetext übersetzen: deutsch und englisch
                adv_msg = ttk.Label(adv_frame, text=tr(TELEGRAM_MESSAGE, "Check out my Telegram channel:"), wraplength=500)
                adv_msg.pack(anchor="w")
                link_lbl = ttk.Label(adv_frame, text=TELEGRAM_LINK, foreground="blue", cursor="hand2")
                link_lbl.pack(anchor="w")
                # Klick öffnet den Link mit Protokoll; falls User vollen Link angegeben hat, ergänze ggf. https://
                def _open_link(event=None):
                    # Öffne den hinterlegten Telegram-Link (TELEGRAM_TARGET), nicht nur den sichtbaren Text.
                    url = TELEGRAM_TARGET
                    # Ergänze https://, falls nicht vorhanden (obwohl die Ziel-URL bereits mit https beginnt)
                    if not url.startswith("http://") and not url.startswith("https://"):
                        url = "https://" + url
                    try:
                        webbrowser.open(url)
                    except Exception:
                        pass
                link_lbl.bind("<Button-1>", _open_link)

        def gui_create(self):
            if self.path.exists():
                # Warnung bei vorhandener Datei mit übersetztem Titel und Text
                if not messagebox.askyesno(
                    tr("Existiert", "Exists"),
                    tr("Datei existiert bereits — überschreiben?", "File already exists — overwrite?"),
                    parent=self.root,
                ):
                    return
            # Passwort zweimal abfragen, jeweils Titel und Prompt übersetzen
            pw1 = simpledialog.askstring(
                tr("Neues Master-Passwort", "New master password"),
                tr("Master-Passwort:", "Master password:"),
                show="*",
                parent=self.root,
            )
            if not pw1:
                return
            pw2 = simpledialog.askstring(
                tr("Bestätigen", "Confirm"),
                tr("Bestätigen:", "Confirm:"),
                show="*",
                parent=self.root,
            )
            if pw1 != pw2:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Passwörter stimmen nicht überein.", "Passwords do not match."),
                )
                return
            # Überprüfe das Passwort mit der erweiterten Policy
            try:
                ok_policy, reason = _check_master_policy(pw1)
            except Exception:
                ok_policy, reason = (len(pw1) >= MIN_MASTER_PW_LEN), ""
            if not ok_policy:
                if not messagebox.askyesno(
                    tr("Schwaches Master-Passwort", "Weak master password"),
                    reason + ". " + tr("Fortfahren?", "Continue?"),
                    parent=self.root,
                ):
                    return
                try:
                    time.sleep(1.5)
                except Exception:
                    pass
            # Arbeiterfunktion zur Erstellung und Speicherung des neuen Tresors
            def do_create_work(new_pw: str) -> Vault:
                vlt = Vault.empty()
                save_vault(self.path, vlt, new_pw)
                write_audit("create_vault", f"{self.path}")
                return vlt
            # Callback bei Erfolg
            def on_create_success(vlt: Vault):
                self.vault = vlt
                self.master_pw = pw1
                messagebox.showinfo(tr("Fertig", "Done"), tr("Leerer Tresor erstellt.", "Empty vault created."), parent=self.root)
                self.build_main_ui()
            # Callback bei Fehler
            def on_create_error(exc: Exception):
                messagebox.showerror(tr("Fehler", "Error"), tr("Tresor konnte nicht erstellt werden:", "Vault could not be created:") + f"\n{exc}", parent=self.root)
            # Starte Fortschrittsdialog
            self.run_with_progress(
                tr("Tresor erstellen", "Create vault"),
                tr("Neuer Tresor wird angelegt. Bitte warten...", "A new vault is being created. Please wait..."),
                do_create_work,
                args=(pw1,),
                on_success=on_create_success,
                on_error=on_create_error,
            )

        def gui_unlock(self):
            pw = self.pw_entry.get()
            # Prüfe, ob die Tresor-Datei existiert
            if not self.path.exists():
                messagebox.showerror(tr("Fehler", "Error"), tr("Tresor-Datei existiert nicht. Erzeuge neuen Tresor.", "Vault file does not exist. Creating a new vault."), parent=self.root)
                return
            # Definiere die Entsperrlogik als Arbeiterfunktion für den Fortschrittsdialog
            def do_unlock_work(pw_str: str) -> Vault:
                # Lädt den Tresor im Hintergrund. Wir geben das Vault-Objekt zurück.
                vlt = load_vault(self.path, pw_str)
                return vlt

            # Callback nach erfolgreichem Laden
            def on_unlock_success(vlt: Vault):
                # Setze Vault und Master-Passwort
                self.vault = vlt
                self.master_pw = pw
                # Audit: vault unlocked
                write_audit("unlock", f"{self.path}")
                # Prüfe automatische Schlüsselrotation (still, Fehler ignorieren)
                try:
                    rotated = auto_rotate_if_due(self.path, self.vault, self.master_pw)
                    if rotated:
                        pass
                except Exception:
                    pass
                # Warnung ggf. anzeigen
                maybe_warn_rotation_gui(self.vault)
                # Aktivitätszeit zurücksetzen und Hauptansicht aufbauen
                self.last_activity = time.time()
                self.build_main_ui()

            # Callback bei Fehler
            def on_unlock_error(exc: Exception):
                # Fehler anzeigen mit übersetztem Titel und Text
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Entschlüsselung fehlgeschlagen:", "Decryption failed:") + f"\n{exc}",
                    parent=self.root,
                )
                # Passwortfeld leeren und Fokus setzen
                try:
                    self.pw_entry.delete(0, 'end')
                    self.pw_entry.focus_set()
                except Exception:
                    pass

            # Starte den Fortschrittsdialog zum Laden des Tresors
            # Fortschrittsdialog mit übersetzten Titel- und Statuszeilen
            self.run_with_progress(
                tr("Tresor laden", "Load vault"),
                tr("Tresor wird geladen. Bitte warten...", "Vault is being loaded. Please wait..."),
                do_unlock_work,
                args=(pw,),
                on_success=on_unlock_success,
                on_error=on_unlock_error,
            )

        def gui_select_file(self):
            """Dateiauswahldialog für den Tresor. Ermöglicht dem Benutzer, eine andere
            Tresor-Datei auszuwählen. Nach Auswahl wird die Login-UI neu aufgebaut,
            sodass der neue Pfad angezeigt wird."""
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Tresor-Datei auswählen", "Select vault file"),
                defaultextension=".pwm",
                filetypes=[
                    (tr("Vault-Dateien", "Vault files"), "*.pwm"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if f:
                self.path = Path(f)
                # Neuaufbau der Login-UI, damit der neue Pfad angezeigt wird und
                # eventuelle Eingaben zurückgesetzt werden.
                self.build_login_ui()

        def gui_select_config(self):
            """Dialog zum Laden oder Erstellen einer Konfigurationsdatei.

            Der Benutzer kann eine JSON-Datei auswählen. Wenn sie nicht existiert,
            wird sie automatisch mit den aktuellen Standardwerten angelegt.
            Anschließend werden die Parameter angewendet. Diese Funktion kann
            genutzt werden, um nach der Kompilierung zu einer EXE weiterhin
            Einstellungen zu ändern, ohne den Quellcode anzupassen.
            """
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Konfigurationsdatei auswählen", "Select configuration file"),
                defaultextension=".json",
                filetypes=[
                    (tr("JSON Dateien", "JSON files"), "*.json"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if f:
                cfg_path = Path(f)
                existed = cfg_path.exists()
                cfg = load_config_file(cfg_path)
                apply_config(cfg)
                # Merke den Pfad der geladenen Konfiguration
                globals()["ACTIVE_CONFIG_PATH"] = cfg_path
                if not existed:
                    # Neu erstellte Konfiguration
                    messagebox.showinfo(
                        tr("Konfiguration", "Configuration"),
                        tr("Konfigurationsdatei", "Configuration file") + f" '{f}' " +
                        tr("wurde neu erstellt mit Standardwerten.", "has been created with default values.") + "\n" +
                        tr(
                            "Du kannst diese Datei jetzt in einem Texteditor bearbeiten, um Parameter anzupassen.",
                            "You can edit this file in a text editor to adjust parameters.",
                        ),
                    )
                else:
                    messagebox.showinfo(
                        tr("Konfiguration", "Configuration"),
                        tr("Konfiguration aus", "Configuration from") + f" '{f}' " +
                        tr("geladen. Änderungen gelten sofort für neue Operationen.", "loaded. Changes take effect immediately for new operations."),
                    )
                # Aktualisiere Auto-Lock basierend auf neuer Konfiguration
                self.last_activity = time.time()
                # UI neu aufbauen, um den Konfigurationsstatus anzuzeigen
                if self.vault is None:
                    self.build_login_ui()
                else:
                    self.build_main_ui()

        def gui_create_config(self):
            """Erstelle eine neue Konfigurationsdatei mit Standardwerten.

            Der Benutzer wählt einen Speicherort, und die Konfiguration wird mit
            den derzeitigen Standardwerten gespeichert. Nach dem Erstellen
            wird keine automatische Anwendung der Konfiguration vorgenommen,
            damit der Nutzer die Datei zunächst bearbeiten kann.
            """
            cfg_path_str = filedialog.asksaveasfilename(
                parent=self.root,
                title="Konfigurationsdatei speichern",
                initialfile=DEFAULT_CONFIG_FILENAME,
                defaultextension=".json",
                filetypes=[("JSON Dateien", "*.json"), ("Alle Dateien", "*.*")],
            )
            if not cfg_path_str:
                return
            cfg_path = Path(cfg_path_str)
            try:
                cfg = _default_config()
                # Schreibe Konfiguration mit Kommentaren
                write_config_with_comments(cfg_path, cfg)
                messagebox.showinfo(
                    tr("Konfig erstellt", "Config created"),
                    tr("Standard-Konfiguration wurde gespeichert unter:", "Default configuration saved at:") + f"\n{cfg_path}\n" +
                    tr("Die Datei enthält Kommentare zu jedem Parameter.", "The file contains comments for each parameter.") + "\n" +
                    tr("Bearbeite diese Datei und lade sie anschließend über den Konfig-Button.", "Edit this file and then load it via the config button."),
                )
            except Exception as e:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Konfiguration konnte nicht erstellt werden: ", "Configuration could not be created: ") + f"{e}",
                )

        def gui_edit_config(self):
            """
            Öffnet einen Dialog zum Bearbeiten der aktuell geladenen Konfiguration.

            Es werden alle in ``CONFIG_KEYS`` definierten Parameter zusammen mit
            ihren Erklärungen angezeigt. Der Benutzer kann die Werte ändern
            und sie anschließend speichern. Bei Erfolg wird die geänderte
            Konfiguration sowohl im Speicher angewendet als auch in die
            bestehende Konfigurationsdatei geschrieben. Falls keine
            Konfigurationsdatei geladen ist, wird der Benutzer aufgefordert,
            zunächst eine Konfiguration zu laden oder zu erstellen.
            """
            from tkinter import messagebox
            import tkinter as tk
            from tkinter import ttk
            from pathlib import Path
            # Prüfe, ob eine Konfig geladen ist
            cfg_path = globals().get("ACTIVE_CONFIG_PATH")
            if not cfg_path or not Path(cfg_path).exists():
                messagebox.showerror(
                    tr("Keine Konfiguration", "No configuration"),
                    tr(
                        "Es ist keine Konfigurationsdatei geladen.\nBitte lade oder erstelle zunächst eine Konfiguration.",
                        "No configuration file is loaded.\nPlease load or create a configuration first.",
                    ),
                    parent=self.root,
                )
                return
            # Aktuelle Werte aus globalen Variablen ermitteln
            current_values = {k: globals().get(k) for k in CONFIG_KEYS}
            # Fenster erstellen
            win = tk.Toplevel(self.root)
            # Übersetze den Fenstertitel
            win.title(tr("Konfiguration bearbeiten", "Edit configuration"))
            # Größeres Fenster für bessere Übersichtlichkeit und Scrollbarkeiten
            try:
                # Setze eine vernünftige Startgröße, damit lange Beschreibungen sichtbar bleiben.
                win.geometry("800x600")
            except Exception:
                pass
            win.transient(self.root)
            try:
                win.grab_set()
            except Exception:
                pass
            # In diesem Dialog verwenden wir klassische tk.Entry-Widgets mit hellem Hintergrund,
            # damit alle Eingabefelder auch bei dunklem GUI-Hintergrund gut lesbar sind.
            # Canvas mit vertikaler und horizontaler Scrollbar für viele Parameter
            canvas = tk.Canvas(win)
            scrollbar_v = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
            scrollbar_h = ttk.Scrollbar(win, orient="horizontal", command=canvas.xview)
            scrollable_frame = ttk.Frame(canvas)
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar_v.pack(side="right", fill="y")
            # horizontale Scrollbar unten platzieren
            scrollbar_h.pack(side="bottom", fill="x")
            # Ermögliche Scrollen mit dem Mausrad. Wir binden sowohl an das Canvas als
            # auch an das Fenster, damit das Rad in diesem Dialog funktioniert.
            try:
                # Setze den Fokus auf das Canvas, wenn die Maus darüber ist, damit das Scrollen
                # auf dieses Widget beschränkt bleibt. Dies verhindert unerwünschtes Scrollen
                # des gesamten Fensters.
                canvas.bind("<Enter>", lambda _ev: canvas.focus_set())
                canvas.bind("<Leave>", lambda _ev: win.focus_set())
                def _on_mousewheel(event):
                    # event.delta liefert je nach Plattform unterschiedliche Werte.
                    delta = event.delta
                    if delta:
                        # Normalisiere das Vorzeichen: negative Werte scrollen nach unten.
                        canvas.yview_scroll(int(-1 * (delta / abs(delta))), "units")
                # Windows/macOS verwenden <MouseWheel>; Linux X11 nutzt Button-4/5.
                canvas.bind("<MouseWheel>", _on_mousewheel)
                canvas.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
                canvas.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
                # Binde zusätzlich an das Fenster (Toplevel), da auf manchen Plattformen
                # das Rad-Ereignis nicht direkt an das Canvas geht.
                win.bind("<MouseWheel>", lambda event: _on_mousewheel(event))
                win.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
                win.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
            except Exception:
                # Fallback: Scrollleisten können weiterhin genutzt werden.
                pass
            # Entry-Widgets pro Key speichern
            # Mapping von Konfigurationsnamen zu den zugehörigen Eingabefeldern
            entries = {}
            for idx, key in enumerate(CONFIG_KEYS):
                val = current_values.get(key, "")
                expl = CONFIG_EXPLANATIONS.get(key, "")
                ttk.Label(scrollable_frame, text=key + ":").grid(row=2*idx, column=0, sticky="w", padx=4, pady=(6 if idx == 0 else 2, 0))
                # Verwende einen klassischen tk.Entry mit hellgrauem Hintergrund für gute Lesbarkeit
                ent = tk.Entry(scrollable_frame, width=40)
                # Setze den Hintergrund anhand der globalen Eingabefarbe.  Die
                # Schriftfarbe bleibt Standard, damit sie bei beliebigen
                # GUI_FG_COLOR-Einstellungen lesbar bleibt.
                try:
                    ent.configure(background=ENTRY_BG_COLOR)
                except Exception:
                    pass
                ent.insert(0, str(val))
                ent.grid(row=2*idx, column=1, sticky="w", padx=4, pady=(6 if idx == 0 else 2, 0))
                entries[key] = ent
                if expl:
                    ttk.Label(
                        scrollable_frame,
                        text=expl,
                        wraplength=500,
                        foreground="grey"
                    ).grid(row=2*idx+1, column=0, columnspan=2, sticky="w", padx=4, pady=(0, 4))
            # Schaltflächenleiste
            btn_frame = ttk.Frame(win)
            btn_frame.pack(fill="x", pady=8)
            def on_save():
                # Neues Konfig-Dict aus Eingaben bauen
                new_cfg: Dict[str, object] = {}
                for k, ent in entries.items():
                    txt = ent.get().strip()
                    cur = current_values.get(k)
                    if isinstance(cur, bool):
                        new_cfg[k] = True if txt.lower() in ("1", "true", "ja", "yes", "wahr") else False
                    elif isinstance(cur, int):
                        try:
                            new_cfg[k] = int(txt)
                        except Exception:
                            new_cfg[k] = cur
                    elif isinstance(cur, float):
                        try:
                            new_cfg[k] = float(txt)
                        except Exception:
                            new_cfg[k] = cur
                    else:
                        new_cfg[k] = txt
                # Konfiguration anwenden
                try:
                    apply_config(new_cfg)
                except Exception as e:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr("Konfiguration konnte nicht angewendet werden:", "Configuration could not be applied:") + f"\n{e}",
                        parent=win,
                    )
                    return
                # Neue Werte zusammenstellen und Datei schreiben
                try:
                    cfg_all = _default_config()
                    for key2 in cfg_all.keys():
                        cfg_all[key2] = globals().get(key2)
                    write_config_with_comments(Path(cfg_path), cfg_all)
                except Exception as e:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr("Konfiguration konnte nicht gespeichert werden:", "Configuration could not be saved:") + f"\n{e}",
                        parent=win,
                    )
                    return
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Konfiguration wurde gespeichert und angewendet.", "Configuration has been saved and applied."),
                    parent=win,
                )
                self.last_activity = time.time()
                try:
                    if self.vault is None:
                        self.build_login_ui()
                    else:
                        self.build_main_ui()
                except Exception:
                    pass
                try:
                    win.grab_release()
                except Exception:
                    pass
                win.destroy()
            def on_cancel():
                try:
                    win.grab_release()
                except Exception:
                    pass
                win.destroy()
            # Schaltflächen mit übersetzten Beschriftungen
            ttk.Button(btn_frame, text=tr("Speichern", "Save"), command=on_save).pack(side="right", padx=4)
            ttk.Button(btn_frame, text=tr("Abbrechen", "Cancel"), command=on_cancel).pack(side="right", padx=4)

        def build_main_ui(self):
            """Erstellt die Hauptansicht nach dem erfolgreichen Entsperren des Tresors.

            In dieser Ansicht werden oben die aktuellen Statusinformationen
            (Tresor-Datei und Konfiguration) zusammen mit den Aktionsschaltflächen
            angezeigt. Darunter befinden sich die Tabelle der Einträge und
            die seitliche Menüleiste. Durch die horizontale Anordnung der
            Statusinformationen und der Buttons wird deutlich, dass beide
            Bereiche zusammengehören.
            """
            # Räumt das Fenster auf und erstellt neue Widgets
            for w in self.root.winfo_children():
                w.destroy()
            # Oberer Container für Statusinformationen und Schaltflächen
            top = ttk.Frame(self.root)
            top.pack(fill="x", padx=6, pady=6)
            # Ermittele Status für Tresor und Konfiguration
            try:
                def_vault = default_vault_path()
            except Exception:
                def_vault = None
            # Formuliere Statusmeldung zum Tresor mit klareren Texten und Übersetzung
            is_default = bool(def_vault and Path(self.path).resolve() == Path(def_vault).resolve())
            if self.path.exists():
                if is_default:
                    vault_msg = tr(f"Standard-Tresor-Datei gefunden oder geladen: {self.path}",
                                   f"Default vault file found or loaded: {self.path}")
                else:
                    vault_msg = tr(f"Externe Tresor-Datei gefunden oder geladen: {self.path}",
                                   f"External vault file found or loaded: {self.path}")
            else:
                if is_default:
                    vault_msg = tr(
                        "Keine Standard-Tresor-Datei gefunden oder kein Tresor-Datei geladen, es wird ein neuer Tresor erstellt.",
                        "No default vault file found or no vault file loaded, a new vault will be created."
                    )
                else:
                    vault_msg = tr(
                        "Keine Tresor-Datei gefunden oder geladen, es wird ein neuer Tresor erstellt.",
                        "No vault file found or loaded, a new vault will be created."
                    )
            # Formuliere Statusmeldung zur Konfiguration
            try:
                active_cfg = globals().get("ACTIVE_CONFIG_PATH")
                default_cfg = exe_dir() / DEFAULT_CONFIG_FILENAME
                if not active_cfg:
                    if default_cfg.exists():
                        cfg_msg = tr(
                            "Keine gültige externe Konfiguration geladen – Standardwerte werden verwendet.",
                            "No valid external configuration loaded – default values are used."
                        )
                    else:
                        cfg_msg = tr(
                            "Keine Konfiguration gefunden – es werden die im Skript hinterlegten Werte verwendet.",
                            "No configuration found – using values embedded in the script."
                        )
                elif Path(active_cfg).resolve() == default_cfg.resolve():
                    cfg_msg = tr(
                        f"Standard-Konfigurationsdatei geladen: {active_cfg}",
                        f"Default configuration file loaded: {active_cfg}"
                    )
                else:
                    cfg_msg = tr(
                        f"Externe Konfigurationsdatei geladen: {active_cfg}",
                        f"External configuration file loaded: {active_cfg}"
                    )
            except Exception:
                cfg_msg = tr(
                    "Konfigurationsstatus konnte nicht ermittelt werden.",
                    "Could not determine configuration status."
                )
            # Erstelle zwei Container innerhalb des oberen Bereichs.
            # Der buttons_frame wird über den Statusmeldungen platziert, damit die Schaltflächen
            # eine eigene Zeile erhalten und oberhalb der Statusinformationen erscheinen.
            buttons_frame = ttk.Frame(top)
            buttons_frame.pack(side="top", fill="x", pady=(0, 2))
            status_frame = ttk.Frame(top)
            status_frame.pack(side="top", fill="x", expand=True)
            # Statuszeilen anzeigen. Jede Information steht in einer eigenen Label-Zeile.
            # Farbige Darstellung: grün für gefundene Tresor-Datei, rot wenn nicht vorhanden.
            vault_color_main = "green" if self.path.exists() else "red"
            ttk.Label(status_frame, text=vault_msg, foreground=vault_color_main).pack(side="top", anchor="w")
            # Konfigstatus einfärben: blau für Standardkonfiguration, grün für externe, schwarz bei keiner
            cfg_color_main = "black"
            try:
                active_cfg = globals().get("ACTIVE_CONFIG_PATH")
                default_cfg = exe_dir() / DEFAULT_CONFIG_FILENAME
                if not active_cfg:
                    cfg_color_main = "black"
                elif Path(active_cfg).resolve() == default_cfg.resolve():
                    cfg_color_main = "blue"
                else:
                    cfg_color_main = "green"
            except Exception:
                cfg_color_main = "black"
            ttk.Label(status_frame, text=cfg_msg, foreground=cfg_color_main).pack(side="top", anchor="w")
            # Hinweis zum Farbschema-Umschalter wurde in die Hilfe verschoben.
            # Bei deaktiviertem Schalter werden keine zusätzlichen Zeilen im Statusrahmen eingefügt.
            # Aktionsschaltflächen: Sperren (verschlüsseln und schließen), Hilfe, Konfig anlegen/laden
            # Die Export‑Funktion (CSV) wird erst nach dem Öffnen des Tresors in der Seitenleiste angeboten.
            # Buttons im oberen Bereich des Hauptfensters mit Übersetzung
            ttk.Button(buttons_frame, text=tr("Lock (verschlüsseln und schließen)", "Lock (encrypt and close)"), command=self.lock).pack(side="left", padx=4)
            # Umschalten der Sprache
            ttk.Button(buttons_frame, text=tr("Sprache wechseln", "Switch language"), command=self.toggle_language).pack(side="left", padx=4)
            ttk.Button(buttons_frame, text=tr("Hilfe", "Help"), command=self.show_help).pack(side="left", padx=4)
            ttk.Button(buttons_frame, text=tr("Konfig erstellen", "Create config"), command=self.gui_create_config).pack(side="left", padx=4)
            ttk.Button(buttons_frame, text=tr("Konfig laden", "Load config"), command=self.gui_select_config).pack(side="left", padx=4)
            # Schaltfläche zum Bearbeiten der aktuellen Konfiguration
            ttk.Button(buttons_frame, text=tr("Konfig bearbeiten", "Edit config"), command=self.gui_edit_config).pack(side="left", padx=4)
            # Hell/Dunkel‑Umschalter: ermöglicht das schnelle Umschalten zwischen
            # hellem und dunklem Farbschema während der Laufzeit.  Die Beschriftung
            # wird je nach Sprache angepasst.  Der Schalter wird nur angezeigt, wenn
            # SHOW_LIGHT_DARK_TOGGLE aktiviert ist.
            if SHOW_LIGHT_DARK_TOGGLE:
                ttk.Button(buttons_frame, text=tr("Hell/Dunkel", "Light/Dark"), command=self.toggle_dark_mode).pack(side="left", padx=4)
            # Hauptbereich für Liste und Seitenmenü
            main = ttk.Frame(self.root)
            main.pack(fill="both", expand=True, padx=6, pady=6)

            self.tree = ttk.Treeview(main, columns=("id", "label", "user", "email"), show="headings")
            # Leichte Tabellenstruktur durch abwechselnde Zeilenfarben.
            # Konfiguriere zwei Tags für gerade und ungerade Zeilen.  Diese
            # Tags verwenden die globalen Farbkons­tan­ten TABLE_BG_COLOR und
            # ENTRY_BG_COLOR.  So erhält die Hauptliste einen dezenten
            # Hintergrundwechsel zwischen den Zeilen ("Striping"), was die
            # Lesbarkeit verbessert.  Die Farben passen sich bei
            # Umschalten des Dark‑Modes dynamisch an, da sie aus den
            # globalen Variablen stammen.
            try:
                self.tree.tag_configure("evenrow", background=TABLE_BG_COLOR)
                self.tree.tag_configure("oddrow", background=ENTRY_BG_COLOR)
            except Exception:
                # Falls tag_configure nicht verfügbar sein sollte, ignoriere den Fehler.
                pass
            # Tabellenspaltenüberschriften übersetzen. "ID" bleibt identisch in beiden Sprachen.
            # Spaltenüberschriften mit Sortierfunktion: Klick auf die Überschrift sortiert die Tabelle.
            self.tree.heading("id", text=tr("ID", "ID"), command=lambda: self.sort_main_tree("id"))
            self.tree.heading("label", text=tr("Label:", "Label:"), command=lambda: self.sort_main_tree("label"))
            self.tree.heading("user", text=tr("Benutzer:", "User:"), command=lambda: self.sort_main_tree("user"))
            self.tree.heading("email", text=tr("Email:", "Email:"), command=lambda: self.sort_main_tree("email"))
            self.tree.column("id", width=140); self.tree.column("label", width=300)
            self.tree.column("user", width=200); self.tree.column("email", width=260)
            self.tree.pack(fill="both", expand=True, side="left")
            # Ergänze Gitterlinien in der Hauptliste
            try:
                add_grid_to_treeview(self.tree)
            except Exception:
                pass
            self.tree.bind("<Double-1>", lambda e: self.gui_view())

            # Rechte Menüleiste breiter anlegen, damit die Beschriftungen der Buttons lesbar sind.
            # Erhöhe die Breite deutlich, da Labels wie "Neu verschlüsseln (save)" viel Platz benötigen.
            side = ttk.Frame(main, width=300)
            side.pack(fill="y", side="right", padx=6)
            # Verhindere automatisches Anpassen der Größe, damit die festgelegte Breite erhalten bleibt.
            side.pack_propagate(False)
            ttk.Button(side, text=tr("Anzeigen", "View"), command=self.gui_view).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Hinzufügen", "Add"), command=self.gui_add).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Ändern", "Edit"), command=self.gui_edit).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Löschen", "Delete"), command=self.gui_delete).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Export (Entry .txt)", "Export (entry .txt)"), command=self.gui_export_entry).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Export (Alle .txt)", "Export (all .txt)"), command=self.gui_export_all).pack(fill="x", pady=3)
            # CSV‑Export und Import zusammen, damit alle Datei‑Im-/Export‑Funktionen gruppiert sind.
            ttk.Button(side, text=tr("Export CSV", "Export CSV"), command=self.gui_export_csv).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Import CSV", "Import CSV"), command=self.gui_import_csv).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Generiere Passwort", "Generate password"), command=self.gui_gen_pw).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Master-PW ändern", "Change master PW"), command=self.gui_change_master_pw).pack(fill="x", pady=3)
            ttk.Button(side, text=tr("Neu verschlüsseln (save)", "Re-encrypt (save)"), command=self.gui_resave).pack(fill="x", pady=6)
            # Dateibezogene Operationen
            # Ein Button für alle Datei-Operationen (Verschlüsseln, Entschlüsseln, Verstecken, Extrahieren).
            # Dieser öffnet ein separates Fenster mit detaillierten Optionen und erklärt, wie die
            # jeweiligen Dateien ausgewählt werden. So bleibt die Seitenleiste übersichtlich.
            ttk.Button(side, text=tr("Datei-Operationen", "File operations"), command=self.gui_open_file_ops_dialog).pack(fill="x", pady=6)

            # Werbehinweis am unteren Rand der Seitenleiste (zweizeilig).  Die Anzeige
            # erfolgt nur, wenn SHOW_TELEGRAM_AD aktiv ist.  Der Link öffnet den
            # hinterlegten Telegram-Kanal.
            if SHOW_TELEGRAM_AD:
                adv_frame = ttk.Frame(side)
                adv_frame.pack(fill="x", pady=(10, 0))
                # Werbetext am unteren Rand der Seitenleiste; durch den geringeren
                # Platzbedarf wird eine kürzere Zeilenlänge gewählt, damit ein
                # Zeilenumbruch erzwungen wird und der Text nicht abgeschnitten wird.
                # Werbetext übersetzen: deutsch und englisch
                adv_msg = ttk.Label(adv_frame, text=tr(TELEGRAM_MESSAGE, "Check out my Telegram channel:"), wraplength=200)
                adv_msg.pack(anchor="w")
                adv_link = ttk.Label(adv_frame, text=TELEGRAM_LINK, foreground="blue", cursor="hand2")
                adv_link.pack(anchor="w")
                def _open_adv_link(event=None):
                    # Öffne den hinterlegten Telegram-Link (TELEGRAM_TARGET), nicht nur den sichtbaren Text
                    url = TELEGRAM_TARGET
                    if not url.startswith("http://") and not url.startswith("https://"):
                        url = "https://" + url
                    try:
                        webbrowser.open(url)
                    except Exception:
                        pass
                adv_link.bind("<Button-1>", _open_adv_link)

            self.status = ttk.Label(self.root, text="Unlocked", relief="sunken", anchor="w")
            self.status.pack(fill="x", side="bottom")
            self.refresh_tree()

        def refresh_tree(self):
            for r in self.tree.get_children(): self.tree.delete(r)
            if not self.vault: return
            for idx, e in enumerate(sorted(self.vault.entries.values(), key=lambda x: x.label.lower())):
                # Wechsle den Zeilenhintergrund zwischen TABLE_BG_COLOR und
                # ENTRY_BG_COLOR anhand des Index.  Dadurch entsteht eine
                # leichte Tabellenstruktur (Striping) für die Hauptliste.
                tag_name = "evenrow" if idx % 2 == 0 else "oddrow"
                self.tree.insert("", "end", values=(e.id, e.label, e.username, e.email), tags=(tag_name,))

        def sort_main_tree(self, col: str) -> None:
            """
            Sortiert die Hauptliste im GUI anhand der angegebenen Spalte.  Beim erneuten
            Aufruf derselben Spalte wird die Sortierreihenfolge umgekehrt.  Spalten,
            die numerische Werte enthalten, werden numerisch sortiert, andernfalls
            lexikographisch (case‑insensitive).

            Args:
                col: Der Name der Treeview‑Spalte ("id", "label", "user" oder "email").
            """
            try:
                # Initialisiere Sortierstatus, falls nicht vorhanden
                if not hasattr(self, "_sort_state"):
                    self._sort_state = {}
                rev = self._sort_state.get(col, False)
                # Extrahiere Werte und Zeilen-IDs
                items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
                # Versuche numerische Sortierung
                try:
                    items.sort(key=lambda x: float(x[0]), reverse=rev)
                except Exception:
                    items.sort(key=lambda x: (x[0] or "").lower(), reverse=rev)
                for idx, (_, iid) in enumerate(items):
                    self.tree.move(iid, "", idx)
                # Toggle
                self._sort_state[col] = not rev
            except Exception:
                pass

        def gui_view(self):


            """Zeigt die Details des ausgewählten Eintrags in einem eigenen Fenster an.

            Das Passwort ist standardmäßig maskiert und wird nach dem Anzeigen automatisch

            nach AUTO_MASK_REVEAL_MS wieder maskiert."""

            import tkinter as tk

            from tkinter import ttk

            

            self.touch()

            sel = self.tree.selection()

            if not sel:

                return

            iid = str(self.tree.item(sel[0])["values"][0])

            e = self.vault.entries.get(iid)

            if not e:

                return

            top = tk.Toplevel(self.root)

            top.title(f"Details: {e.label}")

            frm = ttk.Frame(top, padding=8)

            frm.grid(row=0, column=0, sticky="nsew")

            top.columnconfigure(0, weight=1); top.rowconfigure(0, weight=1)

            frm.columnconfigure(1, weight=1)

            info_row_idx = 5

            frm.rowconfigure(info_row_idx, weight=1)

            ttk.Label(frm, text=tr("Label:", "Label:")).grid(row=0, column=0, sticky="w", pady=2)

            ttk.Label(frm, text=e.label).grid(row=0, column=1, sticky="w", pady=2, padx=(4,0))

            ttk.Label(frm, text=tr("Benutzer:", "User:")).grid(row=1, column=0, sticky="w", pady=2)

            ttk.Label(frm, text=e.username).grid(row=1, column=1, sticky="w", pady=2, padx=(4,0))

            ttk.Label(frm, text=tr("Email:", "Email:")).grid(row=2, column=0, sticky="w", pady=2)

            ttk.Label(frm, text=e.email).grid(row=2, column=1, sticky="w", pady=2, padx=(4,0))

            ttk.Label(frm, text=tr("Webseite/IP:", "Website/IP:")).grid(row=3, column=0, sticky="w", pady=2)

            # Wenn eine Website/IP vorhanden ist, erstelle einen klickbaren Link anstelle eines statischen Labels.
            if e.website:
                link_label = ttk.Label(frm, text=e.website, foreground="blue", cursor="hand2")
                link_label.grid(row=3, column=1, sticky="w", pady=2, padx=(4,0))
                def _open_website(_ev=None, url_str=e.website):
                    target = url_str.strip()
                    if target and not target.lower().startswith(("http://", "https://")):
                        target = "https://" + target
                    try:
                        webbrowser.open(target)
                    except Exception:
                        pass
                link_label.bind("<Button-1>", _open_website)
            else:
                ttk.Label(frm, text="").grid(row=3, column=1, sticky="w", pady=2, padx=(4,0))

            # Passwortzeile mit Auto-Hide

            ttk.Label(frm, text=tr("Passwort:", "Password:")).grid(row=4, column=0, sticky="w", pady=2)

            masked_pw = "•" * max(6, len(e.password or ""))

            pw_var = tk.StringVar(value=masked_pw)

            ttk.Label(frm, textvariable=pw_var).grid(row=4, column=1, sticky="w", pady=2, padx=(4,0))

            self._pw_hide_timer_id = None

            def _cancel_timer():

                if self._pw_hide_timer_id is not None:

                    try:

                        top.after_cancel(self._pw_hide_timer_id)

                    except Exception:

                        pass

                    self._pw_hide_timer_id = None

            def _mask_now():

                pw_var.set(masked_pw)

                self._pw_hide_timer_id = None

            def _schedule_rehide():

                try:

                    delay = int(globals().get("AUTO_MASK_REVEAL_MS", 3000))

                except Exception:

                    delay = 3000

                if delay and delay > 0:

                    _cancel_timer()

                    self._pw_hide_timer_id = top.after(delay, _mask_now)

            def reveal_or_hide():

                if pw_var.get() == masked_pw:

                    pw_var.set(e.password)

                    _schedule_rehide()

                else:

                    _cancel_timer()

                    pw_var.set(masked_pw)

            btn_pw = ttk.Frame(frm)

            btn_pw.grid(row=4, column=2, sticky="w", padx=(8,0))

            ttk.Button(btn_pw, text=tr("Anzeigen", "Show"), command=reveal_or_hide).pack(side="left", padx=2)

            ttk.Button(btn_pw, text=tr("Kopiere Passwort", "Copy password"), command=lambda: self.copy_pw_and_clear(e.password)).pack(side="left", padx=2)

            # Info-Feld

            ttk.Label(frm, text=tr("Info:", "Info:")).grid(row=info_row_idx, column=0, sticky="nw", pady=2)

            info_frame = ttk.Frame(frm)
            info_frame.grid(row=info_row_idx, column=1, columnspan=3, sticky="nsew", pady=2)
            # Info‑Frame soll sich mit dem Fenster mit vergrößern
            info_frame.rowconfigure(0, weight=1)
            info_frame.columnconfigure(0, weight=1)

            # Versuche zu erkennen, ob die Info als Tabelle gespeichert wurde und diese darstellen
            import json as _json
            is_table = False
            table_data = None
            try:
                parsed = _json.loads(e.info)
                if isinstance(parsed, dict) and "__table__" in parsed:
                    table_data = parsed["__table__"]
                    if isinstance(table_data, dict) and "headers" in table_data and "rows" in table_data:
                        is_table = True
            except Exception:
                pass

            if is_table:
                # Tabellenansicht anzeigen
                table_headers = table_data["headers"]
                table_rows = table_data["rows"]
                table_sort_state = {}
                table_tree = None

                def sort_table(col: str) -> None:
                    """Sortiere die Tabellenzeilen anhand der angegebenen Spalte."""
                    nonlocal table_tree, table_sort_state
                    if not table_tree:
                        return
                    # Erstelle Liste aus Wert und Zeilen-ID
                    items = [(table_tree.set(iid, col), iid) for iid in table_tree.get_children("")]
                    # Versuche numerisch, dann lexikographisch zu sortieren
                    try:
                        items.sort(key=lambda x: float(x[0]), reverse=table_sort_state.get(col, False))
                    except Exception:
                        # Strings normalisieren zu Kleinbuchstaben
                        items.sort(key=lambda x: x[0].lower() if isinstance(x[0], str) else str(x[0]).lower(),
                                   reverse=table_sort_state.get(col, False))
                    for index, (_, iid) in enumerate(items):
                        table_tree.move(iid, "", index)
                    table_sort_state[col] = not table_sort_state.get(col, False)

                # Treeview erzeugen
                tv = ttk.Treeview(info_frame, columns=table_headers, show="headings")
                # Hintergrund für die Tabelle setzen.  Verwende den globalen
                # Tabellen‑Hintergrund (TABLE_BG_COLOR), damit sich das
                # Farbschema beim Umschalten des Dark‑Modes ändert.
                try:
                    style = ttk.Style()
                    style.configure("View.Table", background=TABLE_BG_COLOR, fieldbackground=TABLE_BG_COLOR)
                    if GUI_FG_COLOR:
                        style.configure("View.Table", foreground=GUI_FG_COLOR)
                    tv.configure(style="View.Table")
                except Exception:
                    pass
                # Definiere Tags für abwechselnde Zeilenfarben, um eine leichte
                # Tabellenstruktur zu erzeugen.  Die Tags nutzen die globalen
                # Farbkonstanten, sodass sie sich beim Umschalten des Farbschemas
                # automatisch anpassen.
                try:
                    tv.tag_configure("evenrow", background=TABLE_BG_COLOR)
                    tv.tag_configure("oddrow", background=ENTRY_BG_COLOR)
                except Exception:
                    pass

                for h in table_headers:
                    # Nutze lambda mit default arg, damit jede Spalte korrekt sortiert wird
                    tv.heading(h, text=h, command=lambda col=h: sort_table(col))
                    tv.column(h, width=100, anchor="w")
                # Zeilen einfügen; falls zu wenige/zu viele Werte, anpassen.  Jede
                # Zeile erhält einen Tag ("evenrow" oder "oddrow"), um den
                # Hintergrund abwechselnd zu gestalten.  Dadurch wirkt die
                # Tabelle strukturiert ohne explizite Gitterlinien.
                for idx, row in enumerate(table_rows):
                    if isinstance(row, list):
                        values = list(row) + ["" for _ in range(len(table_headers) - len(row))]
                        values = values[:len(table_headers)]
                    else:
                        values = [str(row)] + ["" for _ in range(len(table_headers) - 1)]
                    tag_name = "evenrow" if idx % 2 == 0 else "oddrow"
                    tv.insert("", "end", values=values, tags=(tag_name,))
                sb_y = ttk.Scrollbar(info_frame, orient="vertical", command=tv.yview)
                sb_x = ttk.Scrollbar(info_frame, orient="horizontal", command=tv.xview)
                tv.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
                tv.grid(row=0, column=0, sticky="nsew")
                sb_y.grid(row=0, column=1, sticky="ns")
                sb_x.grid(row=1, column=0, sticky="ew")
    
                # >>> NEU: senkrechte Spaltentrenner für die Detail-Tabelle
                try:
                    add_vertical_grid_to_treeview(tv)
                except Exception:
                    pass

                info_frame.rowconfigure(0, weight=1)
                info_frame.columnconfigure(0, weight=1)
                table_tree = tv

            else:
                # Textansicht anzeigen
                txt_info = tk.Text(info_frame, wrap="word")
                txt_info.insert("1.0", e.info or "")
                txt_info.configure(state="disabled")
                y_scroll = ttk.Scrollbar(info_frame, orient="vertical", command=txt_info.yview)
                x_scroll = ttk.Scrollbar(info_frame, orient="horizontal", command=txt_info.xview)
                txt_info.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
                txt_info.grid(row=0, column=0, sticky="nsew")
                y_scroll.grid(row=0, column=1, sticky="ns")
                x_scroll.grid(row=1, column=0, sticky="ew")
                info_frame.rowconfigure(0, weight=1)
                info_frame.columnconfigure(0, weight=1)

            # Zeiten im deutschen Format, falls fmt_de existiert

            try:

                created_str = fmt_de(e.created_at); updated_str = fmt_de(e.updated_at)

            except Exception:

                created_str = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(e.created_at))

                updated_str = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(e.updated_at))

            ttk.Label(frm, text=tr("Erstellt:", "Created:")).grid(row=info_row_idx+1, column=0, sticky="w", pady=(8,2))

            ttk.Label(frm, text=created_str).grid(row=info_row_idx+1, column=1, sticky="w", pady=(8,2), padx=(4,0))

            ttk.Label(frm, text=tr("Geändert:", "Modified:")).grid(row=info_row_idx+2, column=0, sticky="w", pady=2)

            ttk.Label(frm, text=updated_str).grid(row=info_row_idx+2, column=1, sticky="w", pady=2, padx=(4,0))

            btnf = ttk.Frame(frm)

            btnf.grid(row=info_row_idx+3, column=1, columnspan=3, sticky="e", pady=8)

            ttk.Button(btnf, text=tr("Schließen", "Close"), command=top.destroy).pack(side="right", padx=4)

            def _on_close():

                _cancel_timer()

                top.destroy()

            top.protocol("WM_DELETE_WINDOW", _on_close)


        def gui_add(self):
            self.touch()
            # Arbeiterfunktion, die den Eintrag erstellt und den Tresor speichert
            def do_add_work(label: str, username: str, email: str, website: str, info: str, pw_val: str) -> None:
                eid = generate_entry_id(self.vault.entries)
                ts = time.time()
                e = Entry(
                    id=eid,
                    label=label,
                    username=username,
                    email=email,
                    password=pw_val,
                    info=info,
                    website=website,
                    created_at=ts,
                    updated_at=ts,
                )
                self.vault.entries[eid] = e
                self.vault.updated_at = ts
                save_vault(self.path, self.vault, self.master_pw)
                write_audit("create", f"{eid}|{label}")

            # Callback nach erfolgreichem Hinzufügen
            def on_add_success(_res: None = None):
                self.refresh_tree()
                top.destroy()
                messagebox.showinfo(tr("Erfolg", "Success"), tr("Eintrag gespeichert.", "Entry saved."), parent=self.root)

            # Callback bei Fehlern
            def on_add_error(exc: Exception):
                messagebox.showerror(tr("Fehler", "Error"), tr("Speichern fehlgeschlagen:", "Saving failed:") + f"\n{exc}", parent=self.root)

            # Handler für die Schaltfläche "Hinzufügen"
            def on_add_click():
                label = ent_label.get().strip()
                if not label:
                    messagebox.showerror(tr("Fehler", "Error"), tr("Label erforderlich", "Label is required"), parent=top)
                    return
                username = ent_user.get().strip()
                email = ent_email.get().strip()
                pw_val = ent_pw.get().strip()
                # Generiere Passwort, falls keines eingegeben wurde
                if not pw_val:
                    pw_val = generate_password()
                cat, score = password_strength(pw_val)
                if score < 40:
                    if not messagebox.askyesno(
                        tr("Schwaches Passwort", "Weak password"),
                        tr("Passwortstärke", "Password strength") + f" {cat} ({score}). " + tr("Fortfahren?", "Continue?"),
                        parent=top,
                    ):
                        return
                # Ermittele den Inhalt des Info-Feldes abhängig vom gewählten Format.
                if info_format_var.get() == tr("Tabelle", "Table"):
                    try:
                        import json as _j
                        table_data = {"headers": table_headers, "rows": []}
                        # Alle Zeilen und Spalten des Treeviews extrahieren
                        if isinstance(table_tree, ttk.Treeview):
                            for iid_row in table_tree.get_children(""):
                                table_data["rows"].append([table_tree.set(iid_row, h) for h in table_headers])
                        info = _j.dumps({"__table__": table_data}, ensure_ascii=False)
                    except Exception:
                        info = ""
                else:
                    info = txt_info.get("1.0", "end").strip()
                website = ent_web.get().strip()
                # Startet den Fortschrittsdialog
                self.run_with_progress(
                    tr("Eintrag speichern", "Save entry"),
                    tr("Eintrag wird gespeichert. Bitte warten...", "Entry is being saved. Please wait..."),
                    do_add_work,
                    args=(label, username, email, website, info, pw_val),
                    on_success=on_add_success,
                    on_error=on_add_error,
                )
            top = tk.Toplevel(self.root)
            top.title(tr("Hinzufügen", "Add"))
            # Verwende ein Grid-Layout, bei dem Spalte 1 und die Info-Zeile sich mit dem Fenster
            # ausdehnen. So passen sich die Eingabefelder automatisch an die Fenstergröße an.
            frm = ttk.Frame(top, padding=8)
            frm.grid(row=0, column=0, sticky="nsew")
            top.columnconfigure(0, weight=1)
            top.rowconfigure(0, weight=1)
            frm.columnconfigure(1, weight=1)
            # Die Zeile für den Info-Container ist Zeile 6; diese sollte sich mit dem Fenster ausdehnen.
            frm.rowconfigure(6, weight=1)
            # Eingabefelder für Label, Benutzer, Email
            ttk.Label(frm, text=tr("Label:", "Label:")).grid(row=0, column=0, sticky="w", pady=2)
            ent_label = ttk.Entry(frm)
            ent_label.grid(row=0, column=1, sticky="ew", pady=2)
            ttk.Label(frm, text=tr("Benutzer:", "User:")).grid(row=1, column=0, sticky="w", pady=2)
            ent_user = ttk.Entry(frm)
            ent_user.grid(row=1, column=1, sticky="ew", pady=2)
            ttk.Label(frm, text=tr("Email:", "Email:")).grid(row=2, column=0, sticky="w", pady=2)
            ent_email = ttk.Entry(frm)
            ent_email.grid(row=2, column=1, sticky="ew", pady=2)
            # Passwortfeld mit optionalem Generieren
            ttk.Label(frm, text=tr("Passwort (leer=generieren):", "Password (leave empty to generate):")).grid(row=3, column=0, sticky="w", pady=2)
            ent_pw = ttk.Entry(frm)
            ent_pw.grid(row=3, column=1, sticky="ew", pady=2)
            def do_gen_pw_add():
                ent_pw.delete(0, tk.END)
                ent_pw.insert(0, generate_password())
            ttk.Button(frm, text=tr("Generieren", "Generate"), command=do_gen_pw_add).grid(row=3, column=2, padx=6, pady=2)
            # Webseite/IP
            ttk.Label(frm, text=tr("Webseite/IP:", "Website/IP:")).grid(row=4, column=0, sticky="w", pady=2)
            ent_web = ttk.Entry(frm)
            ent_web.grid(row=4, column=1, sticky="ew", pady=2)

            # ----------------------------------------------------------
            # Info‑Format Auswahl (Text oder Tabelle) und Container
            # ----------------------------------------------------------
            # Variable zur Auswahl des Info‑Formats. Voreinstellung ist "Text".
            info_format_var = tk.StringVar(value=tr("Text", "Text"))
            ttk.Label(frm, text=tr("Format:", "Format:")).grid(row=5, column=0, sticky="w", pady=2)
            fmt_combo = ttk.Combobox(frm, textvariable=info_format_var, state="readonly",
                                     values=[tr("Text", "Text"), tr("Tabelle", "Table")])
            fmt_combo.grid(row=5, column=1, sticky="w", pady=2)
            # Container für das Info‑Feld: entweder Text‑Editor oder Tabelle.
            info_container = ttk.Frame(frm)
            info_container.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=2)
            # Erlaube, dass die Info‑Zeile mit dem Fenster wächst.
            frm.rowconfigure(6, weight=1)
            # Sorgt dafür, dass der Inhalt des Containers (Text oder Tabelle) die volle
            # Breite und Höhe nutzt.
            info_container.rowconfigure(0, weight=1)
            info_container.columnconfigure(0, weight=1)

            # Text‑Frame mit Scrollbars
            text_frame = ttk.Frame(info_container)
            # Textwidget für Info in Textform. Hintergrund leicht grau für bessere Lesbarkeit.
            txt_info = tk.Text(text_frame, wrap="word")
            try:
                # Der Hintergrund des Textfelds wird abhängig vom aktuellen
                # Farbschema gesetzt.  Dadurch bleibt der Kontrast im
                # Dunkelmodus erhalten.
                txt_info.configure(background=ENTRY_BG_COLOR)
            except Exception:
                pass
            txt_scroll_y = ttk.Scrollbar(text_frame, orient="vertical", command=txt_info.yview)
            txt_scroll_x = ttk.Scrollbar(text_frame, orient="horizontal", command=txt_info.xview)
            txt_info.configure(yscrollcommand=txt_scroll_y.set, xscrollcommand=txt_scroll_x.set)
            txt_info.grid(row=0, column=0, sticky="nsew")
            txt_scroll_y.grid(row=0, column=1, sticky="ns")
            txt_scroll_x.grid(row=1, column=0, sticky="ew")
            text_frame.rowconfigure(0, weight=1)
            text_frame.columnconfigure(0, weight=1)

            # Tabelle‑Frame; Treeview wird erst erzeugt, wenn eine Tabelle angelegt wird.
            table_frame = ttk.Frame(info_container)
            # Tabellenbezogene Variablen.
            table_tree: Optional[ttk.Treeview] = None  # type: ignore[var-annotated]
            table_headers: List[str] = []
            table_sort_state: Dict[str, bool] = {}

            def sort_table(col: str) -> None:
                """Sortiere die Tabellenzeilen anhand der angegebenen Spalte."""
                nonlocal table_tree, table_sort_state
                if not table_tree:
                    return
                items = [(table_tree.set(iid, col), iid) for iid in table_tree.get_children("")]
                # Numerische Sortierung versuchen
                try:
                    items.sort(key=lambda x: float(x[0]), reverse=table_sort_state.get(col, False))
                except Exception:
                    items.sort(key=lambda x: x[0].lower(), reverse=table_sort_state.get(col, False))
                for index, (_, iid) in enumerate(items):
                    table_tree.move(iid, "", index)
                table_sort_state[col] = not table_sort_state.get(col, False)

            def edit_cell(event):
                """Ermögliche das Bearbeiten einer Tabellenzelle per Doppelklick."""
                nonlocal table_tree
                if not table_tree:
                    return
                region = table_tree.identify("region", event.x, event.y)
                if region != "cell":
                    return
                row_id = table_tree.identify_row(event.y)
                col_id = table_tree.identify_column(event.x)
                if not row_id or not col_id:
                    return
                col_idx = int(col_id.strip("#")) - 1
                current_value = table_tree.set(row_id, table_headers[col_idx])
                edit_win = tk.Toplevel(top)
                edit_win.title(tr("Zelle bearbeiten", "Edit cell"))
                ttk.Label(edit_win, text=tr("Neuer Wert:", "New value:")).pack(padx=6, pady=(6,2))
                entry = ttk.Entry(edit_win)
                entry.pack(padx=6, pady=(0,6), fill="x")
                entry.insert(0, current_value)
                entry.focus_set()
                def commit():
                    new_val = entry.get()
                    table_tree.set(row_id, table_headers[col_idx], new_val)
                    edit_win.destroy()
                # Enter bestätigt die Eingabe genau wie der OK-Button
                entry.bind("<Return>", lambda _ev: commit())
                ttk.Button(edit_win, text=tr("OK", "OK"), command=commit).pack(pady=(0,6))

            def on_right_click(event):
                """Kontextmenü: Erlaube Link‑Öffnen bei URL‑Zellen."""
                nonlocal table_tree
                if not table_tree:
                    return
                row_id = table_tree.identify_row(event.y)
                col_id = table_tree.identify_column(event.x)
                if not row_id or not col_id:
                    return
                col_idx = int(col_id.strip("#")) - 1
                cell_val = table_tree.set(row_id, table_headers[col_idx])
                if cell_val and isinstance(cell_val, str) and (cell_val.startswith("http://") or cell_val.startswith("https://") or cell_val.startswith("www.")):
                    menu = tk.Menu(table_frame, tearoff=0)
                    def open_link():
                        url = cell_val
                        if url.startswith("www."):
                            url2 = "https://" + url
                        else:
                            url2 = url
                        try:
                            webbrowser.open(url2)
                        except Exception:
                            pass
                    menu.add_command(label=tr("Link öffnen", "Open link"), command=open_link)
                    try:
                        menu.tk_popup(event.x_root, event.y_root)
                    finally:
                        menu.grab_release()

            def create_table():
                """Fordert Spalten‑ und Zeilenzahl ab und erstellt den Treeview."""
                nonlocal table_tree, table_headers, table_frame
                # Spaltenzahl abfragen
                cols = simpledialog.askinteger(tr("Spaltenzahl", "Number of columns"),
                                               tr("Wie viele Spalten?", "How many columns?"),
                                               parent=top, minvalue=1, maxvalue=20)
                if not cols:
                    return
                rows = simpledialog.askinteger(tr("Zeilenzahl", "Number of rows"),
                                               tr("Wie viele Zeilen?", "How many rows?"),
                                               parent=top, minvalue=1, maxvalue=100)
                if not rows:
                    return
                headers: List[str] = []
                for i in range(cols):
                    name = simpledialog.askstring(tr("Spaltenkopf", "Column header"),
                                                  tr("Name für Spalte", "Name for column") + f" {i+1}:", parent=top)
                    if not name:
                        name = f"Col{i+1}"
                    headers.append(name)
                table_headers[:] = headers
                # Entferne alte Tabelle
                for child in table_frame.winfo_children():
                    child.destroy()
                tv = ttk.Treeview(table_frame, columns=headers, show="headings")
                # Leicht grauer Hintergrund für die Tabelle im hellen Modus.
                try:
                    style = ttk.Style()
                    # Verwende den globalen Tabellen‑Hintergrund, der im Dunkelmodus
                    # angepasst wird.
                    style.configure("Custom.Treeview", background=TABLE_BG_COLOR, fieldbackground=TABLE_BG_COLOR)
                    # Passe die Schriftfarbe an das globale Farbschema an
                    if GUI_FG_COLOR:
                        style.configure("Custom.Treeview", foreground=GUI_FG_COLOR)
                    tv.configure(style="Custom.Treeview")
                except Exception:
                    pass
                # Konfiguriere Zeilentags für abwechselnde Hintergründe
                try:
                    tv.tag_configure("evenrow", background=TABLE_BG_COLOR)
                    tv.tag_configure("oddrow", background=ENTRY_BG_COLOR)
                except Exception:
                    pass
                for h in headers:
                    tv.heading(h, text=h, command=lambda col=h: sort_table(col))
                    tv.column(h, width=100, anchor="w")
                # Füge die angeforderte Zahl an leeren Zeilen hinzu und weise
                # abwechselnde Tags zu, um die Lesbarkeit zu verbessern.
                for r in range(rows):
                    tag_name = "evenrow" if r % 2 == 0 else "oddrow"
                    tv.insert("", "end", values=["" for _ in headers], tags=(tag_name,))
                sb_y = ttk.Scrollbar(table_frame, orient="vertical", command=tv.yview)
                sb_x = ttk.Scrollbar(table_frame, orient="horizontal", command=tv.xview)
                tv.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
                tv.grid(row=0, column=0, sticky="nsew")
                sb_y.grid(row=0, column=1, sticky="ns")
                sb_x.grid(row=1, column=0, sticky="ew")
                # Füge dünne Gitterlinien hinzu, um eine klare Tabellenstruktur zu schaffen.
                try:
                    add_grid_to_treeview(tv)
                except Exception:
                    pass
                table_frame.rowconfigure(0, weight=1)
                table_frame.columnconfigure(0, weight=1)
                tv.bind("<Double-1>", edit_cell)
                tv.bind("<Button-3>", on_right_click)
                table_tree = tv

            def edit_columns():
                """
                Öffnet einen Dialog, um vorhandene Tabellenspalten umzubenennen, neue hinzuzufügen
                oder die letzte Spalte zu entfernen. Die Daten der bestehenden Spalten bleiben
                erhalten; neu hinzugefügte Spalten werden mit leeren Feldern gefüllt.
                """
                nonlocal table_headers, table_tree, table_frame
                if not table_headers:
                    messagebox.showinfo(tr("Info", "Info"), tr("Keine Tabelle vorhanden.", "No table exists."), parent=top)
                    return
                col_win = tk.Toplevel(top)
                col_win.title(tr("Spalten bearbeiten", "Edit columns"))
                col_win.transient(top)
                col_frame = ttk.Frame(col_win, padding=8)
                col_frame.grid(row=0, column=0, sticky="nsew")
                col_win.columnconfigure(0, weight=1)
                col_win.rowconfigure(0, weight=1)
                entries: List[ttk.Entry] = []
                # interne Funktionen zum Hinzufügen und Entfernen
                def remove_last():
                    nonlocal entries
                    if not entries:
                        return
                    idx = len(entries) - 1
                    ent = entries.pop()
                    ent.destroy()
                    # Entferne Label
                    for w in col_frame.grid_slaves(row=idx, column=0):
                        w.destroy()
                def add_col():
                    idx = len(entries)
                    ttk.Label(col_frame, text=tr("Spalte", "Column") + f" {idx+1}:").grid(row=idx, column=0, sticky="w", pady=2)
                    ent = ttk.Entry(col_frame)
                    ent.grid(row=idx, column=1, sticky="ew", pady=2)
                    col_frame.columnconfigure(1, weight=1)
                    entries.append(ent)
                # existierende Spalten einfügen
                for i, h in enumerate(table_headers):
                    ttk.Label(col_frame, text=tr("Spalte", "Column") + f" {i+1}:").grid(row=i, column=0, sticky="w", pady=2)
                    e = ttk.Entry(col_frame)
                    e.insert(0, h)
                    e.grid(row=i, column=1, sticky="ew", pady=2)
                    col_frame.columnconfigure(1, weight=1)
                    entries.append(e)
                # Buttons zum Hinzufügen/Entfernen
                btn_add = ttk.Button(col_frame, text=tr("Spalte hinzufügen", "Add column"), command=add_col)
                btn_remove = ttk.Button(col_frame, text=tr("Spalte entfernen", "Remove column"), command=remove_last)
                btn_add.grid(row=len(entries)+1, column=0, pady=(6,2), sticky="w")
                btn_remove.grid(row=len(entries)+1, column=1, pady=(6,2), sticky="w")
                # Anwenden und Abbrechen
                def apply_changes():
                    nonlocal table_headers, table_tree
                    new_headers: List[str] = []
                    for idx, ent in enumerate(entries):
                        txt = ent.get().strip()
                        new_headers.append(txt if txt else f"Col{idx+1}")
                    # Sammle vorhandene Daten
                    rows_val: List[List[str]] = []
                    if table_tree:
                        for iid in table_tree.get_children(""):
                            rows_val.append([table_tree.set(iid, h) for h in table_headers])
                    # Aktualisiere header
                    table_headers[:] = new_headers
                    # Erstelle neue Tabelle
                    for child in table_frame.winfo_children():
                        child.destroy()
                    tv_new = ttk.Treeview(table_frame, columns=new_headers, show="headings")
                    try:
                        style = ttk.Style()
                        style.configure("Custom.Rebuild.Tree", background=TABLE_BG_COLOR, fieldbackground=TABLE_BG_COLOR)
                        if GUI_FG_COLOR:
                            style.configure("Custom.Rebuild.Tree", foreground=GUI_FG_COLOR)
                        tv_new.configure(style="Custom.Rebuild.Tree")
                    except Exception:
                        pass
                    # Richtige Hintergründe für gerade und ungerade Zeilen konfigurieren
                    try:
                        tv_new.tag_configure("evenrow", background=TABLE_BG_COLOR)
                        tv_new.tag_configure("oddrow", background=ENTRY_BG_COLOR)
                    except Exception:
                        pass
                    for h in new_headers:
                        tv_new.heading(h, text=h, command=lambda col=h: sort_table(col))
                        tv_new.column(h, width=100, anchor="w")
                    # Zeilen mit abwechselnden Tags einfügen
                    for idx_row, row in enumerate(rows_val):
                        vals = row[:len(new_headers)] + [""] * (len(new_headers) - len(row))
                        tag_name = "evenrow" if idx_row % 2 == 0 else "oddrow"
                        tv_new.insert("", "end", values=vals, tags=(tag_name,))
                    sb_y_n = ttk.Scrollbar(table_frame, orient="vertical", command=tv_new.yview)
                    sb_x_n = ttk.Scrollbar(table_frame, orient="horizontal", command=tv_new.xview)
                    tv_new.configure(yscrollcommand=sb_y_n.set, xscrollcommand=sb_x_n.set)
                    tv_new.grid(row=0, column=0, sticky="nsew")
                    sb_y_n.grid(row=0, column=1, sticky="ns")
                    sb_x_n.grid(row=1, column=0, sticky="ew")
                    # Gitterlinien hinzufügen, damit Spalten‑ und Zeilenraster sichtbar sind
                    try:
                        add_grid_to_treeview(tv_new)
                    except Exception:
                        pass
                    table_frame.rowconfigure(0, weight=1)
                    table_frame.columnconfigure(0, weight=1)
                    tv_new.bind("<Double-1>", edit_cell)
                    tv_new.bind("<Button-3>", on_right_click)
                    table_tree = tv_new
                    col_win.destroy()
                def cancel_changes():
                    col_win.destroy()
                btn_save = ttk.Button(col_frame, text=tr("OK", "OK"), command=apply_changes)
                btn_cancel = ttk.Button(col_frame, text=tr("Abbrechen", "Cancel"), command=cancel_changes)
                btn_save.grid(row=len(entries)+2, column=0, pady=(6,4), sticky="w")
                btn_cancel.grid(row=len(entries)+2, column=1, pady=(6,4), sticky="w")

            # Buttons zum Anlegen einer Tabelle und zum Bearbeiten vorhandener Spalten. Diese
            # werden in einem eigenen Frame gruppiert, damit sie einheitlich ausgerichtet
            # werden können.
            btn_create_table = ttk.Button(frm, text=tr("Tabelle erstellen", "Create table"), command=create_table)
            btn_edit_columns = ttk.Button(frm, text=tr("Spalten bearbeiten", "Edit columns"), command=edit_columns)
            # Buttons befinden sich in einem Rahmen innerhalb des Info-Containers, damit sie direkt
            # unter der Tabelle angezeigt werden können.
            table_btn_frame = ttk.Frame(info_container)
            btn_create_table.pack(in_=table_btn_frame, side="left", padx=2)
            btn_edit_columns.pack(in_=table_btn_frame, side="left", padx=2)

            def on_format_change(event=None):
                """Wechsle zwischen Text- und Tabellenansicht je nach Auswahl."""
                fmt = info_format_var.get()
                # Lösche vorhandene Widgets aus dem Info-Container
                for child in info_container.winfo_children():
                    child.grid_forget()
                # Verstecke Steuer-Buttons standardmäßig
                table_btn_frame.grid_remove()
                if fmt == tr("Tabelle", "Table"):
                    # Wenn noch keine Tabelle existiert, erstelle eine leere Tabelle.
                    if not table_headers:
                        create_table()
                    # Tabelle anzeigen und Buttons unterhalb einblenden
                    table_frame.grid(row=0, column=0, sticky="nsew")
                    table_btn_frame.grid(row=1, column=0, sticky="w", pady=4)
                    # Der Info-Container soll die Tabelle nach oben wachsen lassen
                    info_container.rowconfigure(0, weight=1)
                else:
                    # Textansicht anzeigen und Buttons ausblenden
                    text_frame.grid(row=0, column=0, sticky="nsew")

            # initiale Ansicht
            on_format_change()
            fmt_combo.bind("<<ComboboxSelected>>", on_format_change)

            # Buttons für Hinzufügen und Abbrechen
            btn_frame = ttk.Frame(frm)
            btn_frame.grid(row=8, column=1, sticky="e", pady=8)
            ttk.Button(btn_frame, text=tr("Hinzufügen", "Add"), command=on_add_click).pack(side="right", padx=4)
            ttk.Button(btn_frame, text=tr("Abbrechen", "Cancel"), command=top.destroy).pack(side="right", padx=4)

        def gui_edit(self):
            self.touch()
            sel = self.tree.selection()
            if not sel:
                messagebox.showinfo(tr("Info", "Info"), tr("Kein Eintrag ausgewählt", "No entry selected")); return
            iid = str(self.tree.item(sel[0])["values"][0])  # ← NEU
            e = self.vault.entries.get(iid)
            if not e: return
            # Arbeiterfunktion zum Speichern des geänderten Eintrags. Sie nimmt alle Daten
            # als Parameter entgegen und führt die Speicherung im Hintergrund aus.
            def do_save_work(new_label: str, new_username: str, new_email: str,
                             new_website: str, new_info: str, new_password: Optional[str]) -> None:
                # Aktualisiere Felder
                e.label = new_label
                e.username = new_username
                e.email = new_email
                e.website = new_website
                e.info = new_info
                if new_password:
                    e.password = new_password
                e.updated_at = time.time()
                self.vault.updated_at = e.updated_at
                save_vault(self.path, self.vault, self.master_pw)
                write_audit("update", f"{e.id}|{new_label}")
            # Callback nach erfolgreichem Speichern
            def on_save_success(_res=None):
                self.refresh_tree()
                top.destroy()
                messagebox.showinfo(tr("Erfolg", "Success"), tr("Eintrag gespeichert.", "Entry saved."))
            # Callback bei Fehlern
            def on_save_error(exc: Exception):
                # Zeige eine Fehlermeldung in der aktuellen Sprache
                messagebox.showerror(tr("Fehler", "Error"), tr("Speichern fehlgeschlagen:", "Saving failed:") + f"\n{exc}")
            # Handler für die Speichern-Schaltfläche: validiert Eingaben und startet die
            # asynchrone Speicherung mit Fortschrittsdialog.
            def on_save_click():
                new_label = ent_label.get().strip() or e.label
                new_username = ent_user.get().strip() or e.username
                new_email = ent_email.get().strip() or e.email
                new_website = ent_web.get().strip() or e.website
                # Info abhängig vom Format (Text/Tabelle) ermitteln
                if info_format_var.get() == tr("Tabelle", "Table"):
                    try:
                        import json as _j
                        table_data = {"headers": table_headers, "rows": []}
                        if isinstance(table_tree, ttk.Treeview):
                            for iid_row2 in table_tree.get_children(""):
                                table_data["rows"].append([table_tree.set(iid_row2, h) for h in table_headers])
                        new_info = _j.dumps({"__table__": table_data}, ensure_ascii=False)
                    except Exception:
                        new_info = e.info
                else:
                    tmp_txt = txt_info.get("1.0", "end").strip()
                    new_info = tmp_txt if tmp_txt else e.info
                new_pw = ent_pw.get().strip() or None
                # Prüfe Passwortstärke, falls ein neues Passwort gesetzt wird
                if new_pw:
                    cat, score = password_strength(new_pw)
                    if score < 40:
                        # Warnung bei schwachem Passwort mit zweisprachiger Meldung
                        if not messagebox.askyesno(
                            tr("Schwaches Passwort", "Weak password"),
                            tr("Passwortstärke", "Password strength") + f" {cat} ({score}). " + tr("Fortfahren?", "Continue?"),
                            parent=top,
                        ):
                            return
                # Starte Speichervorgang im Hintergrund
                self.run_with_progress(
                    tr("Speichern", "Save"), tr("Änderungen werden gespeichert. Bitte warten...", "Changes are being saved. Please wait..."),
                    do_save_work,
                    (new_label, new_username, new_email, new_website, new_info, new_pw),
                    on_success=on_save_success,
                    on_error=on_save_error
                )
            top = tk.Toplevel(self.root)
            top.title(tr("Ändern", "Edit"))
            # Grid-Layout: Spalte 1 expandiert, Zeile 5 (Info) expandiert
            frm = ttk.Frame(top, padding=8)
            frm.grid(row=0, column=0, sticky="nsew")
            top.columnconfigure(0, weight=1)
            top.rowconfigure(0, weight=1)
            frm.columnconfigure(1, weight=1)
            # Der Info-Container befindet sich in Zeile 6; diese dehnt sich aus
            frm.rowconfigure(6, weight=1)
            # Label
            ttk.Label(frm, text=tr("Label:", "Label:")).grid(row=0, column=0, sticky="w", pady=2)
            ent_label = ttk.Entry(frm)
            ent_label.insert(0, e.label)
            ent_label.grid(row=0, column=1, sticky="ew", pady=2)
            # Benutzer
            ttk.Label(frm, text=tr("Benutzer:", "User:")).grid(row=1, column=0, sticky="w", pady=2)
            ent_user = ttk.Entry(frm)
            ent_user.insert(0, e.username)
            ent_user.grid(row=1, column=1, sticky="ew", pady=2)
            # Email
            ttk.Label(frm, text=tr("Email:", "Email:")).grid(row=2, column=0, sticky="w", pady=2)
            ent_email = ttk.Entry(frm)
            ent_email.insert(0, e.email)
            ent_email.grid(row=2, column=1, sticky="ew", pady=2)
            # Webseite/IP
            ttk.Label(frm, text=tr("Webseite/IP:", "Website/IP:")).grid(row=3, column=0, sticky="w", pady=2)
            ent_web = ttk.Entry(frm)
            ent_web.insert(0, e.website)
            ent_web.grid(row=3, column=1, sticky="ew", pady=2)
            # Passwort
            ttk.Label(frm, text=tr("Passwort (leer=unverändert):", "Password (leave empty to keep unchanged):")).grid(row=4, column=0, sticky="w", pady=2)
            ent_pw = ttk.Entry(frm)
            ent_pw.grid(row=4, column=1, sticky="ew", pady=2)
            # Passwort generieren
            def do_gen_pw_edit():
                ent_pw.delete(0, tk.END)
                ent_pw.insert(0, generate_password())
            ttk.Button(frm, text="Generieren", command=do_gen_pw_edit).grid(row=4, column=2, padx=6, pady=2)
            # ----------------------------------------------------------
            # Info‑Format (Text oder Tabelle) und Info‑Container
            # ----------------------------------------------------------
            # Bestimme, ob der aktuelle Eintrag eine Tabelle enthält.
            import json as _json
            is_table_default = False
            table_data_default = None
            try:
                parsed = _json.loads(e.info)
                if isinstance(parsed, dict) and "__table__" in parsed:
                    table_data_default = parsed["__table__"]
                    if isinstance(table_data_default, dict) and "headers" in table_data_default and "rows" in table_data_default:
                        is_table_default = True
            except Exception:
                pass
            # Format‑Auswahl
            info_format_var = tk.StringVar(value=tr("Tabelle", "Table") if is_table_default else tr("Text", "Text"))
            ttk.Label(frm, text=tr("Format:", "Format:")).grid(row=5, column=0, sticky="w", pady=2)
            fmt_combo = ttk.Combobox(frm, textvariable=info_format_var, state="readonly",
                                     values=[tr("Text", "Text"), tr("Tabelle", "Table")])
            fmt_combo.grid(row=5, column=1, sticky="w", pady=2)
            # Container für Info: entweder Text oder Tabelle
            info_container = ttk.Frame(frm)
            info_container.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=2)
            # Erlaube, dass die Info-Zeile mit dem Fenster wächst
            frm.rowconfigure(6, weight=1)
            # Sorgt dafür, dass der Inhalt des Containers (Text oder Tabelle) die volle
            # Breite und Höhe nutzt.
            info_container.rowconfigure(0, weight=1)
            info_container.columnconfigure(0, weight=1)
            # Text‑Frame und zugehörige Widgets
            text_frame = ttk.Frame(info_container)
            txt_info = tk.Text(text_frame, wrap="word")
            try:
                txt_info.configure(background=ENTRY_BG_COLOR)
            except Exception:
                pass
            txt_scroll_y = ttk.Scrollbar(text_frame, orient="vertical", command=txt_info.yview)
            txt_scroll_x = ttk.Scrollbar(text_frame, orient="horizontal", command=txt_info.xview)
            txt_info.configure(yscrollcommand=txt_scroll_y.set, xscrollcommand=txt_scroll_x.set)
            txt_info.grid(row=0, column=0, sticky="nsew")
            txt_scroll_y.grid(row=0, column=1, sticky="ns")
            txt_scroll_x.grid(row=1, column=0, sticky="ew")
            text_frame.rowconfigure(0, weight=1)
            text_frame.columnconfigure(0, weight=1)
            # Tabelle‑Frame; Treeview wird dynamisch erstellt
            table_frame = ttk.Frame(info_container)
            table_tree: Optional[ttk.Treeview] = None  # type: ignore[var-annotated]
            table_headers: List[str] = []
            table_sort_state: Dict[str, bool] = {}
            def sort_table(col: str) -> None:
                nonlocal table_tree, table_sort_state
                if not table_tree:
                    return
                items = [(table_tree.set(iid, col), iid) for iid in table_tree.get_children("")]
                try:
                    items.sort(key=lambda x: float(x[0]), reverse=table_sort_state.get(col, False))
                except Exception:
                    items.sort(key=lambda x: x[0].lower(), reverse=table_sort_state.get(col, False))
                for index, (_, iid2) in enumerate(items):
                    table_tree.move(iid2, "", index)
                table_sort_state[col] = not table_sort_state.get(col, False)
            def edit_cell(event):
                nonlocal table_tree
                if not table_tree:
                    return
                region = table_tree.identify("region", event.x, event.y)
                if region != "cell":
                    return
                row_id2 = table_tree.identify_row(event.y)
                col_id2 = table_tree.identify_column(event.x)
                if not row_id2 or not col_id2:
                    return
                col_idx2 = int(col_id2.strip("#")) - 1
                current_value2 = table_tree.set(row_id2, table_headers[col_idx2])
                edit_win = tk.Toplevel(top)
                edit_win.title(tr("Zelle bearbeiten", "Edit cell"))
                ttk.Label(edit_win, text=tr("Neuer Wert:", "New value:")).pack(padx=6, pady=(6,2))
                entry2 = ttk.Entry(edit_win)
                entry2.pack(padx=6, pady=(0,6), fill="x")
                entry2.insert(0, current_value2)
                entry2.focus_set()
                def commit2():
                    new_val2 = entry2.get()
                    table_tree.set(row_id2, table_headers[col_idx2], new_val2)
                    edit_win.destroy()
                # Enter bestätigt die Eingabe genau wie der OK-Button
                entry2.bind("<Return>", lambda _ev: commit2())
                ttk.Button(edit_win, text=tr("OK", "OK"), command=commit2).pack(pady=(0,6))

            def on_right_click(event):
                nonlocal table_tree
                if not table_tree:
                    return
                row_id2 = table_tree.identify_row(event.y)
                col_id2 = table_tree.identify_column(event.x)
                if not row_id2 or not col_id2:
                    return
                col_idx2 = int(col_id2.strip("#")) - 1
                cell_val = table_tree.set(row_id2, table_headers[col_idx2])
                if cell_val and isinstance(cell_val, str) and (cell_val.startswith("http://") or cell_val.startswith("https://") or cell_val.startswith("www.")):
                    menu = tk.Menu(table_frame, tearoff=0)
                    def open_link():
                        url = cell_val
                        url2 = ("https://" + url) if url.startswith("www.") else url
                        try:
                            webbrowser.open(url2)
                        except Exception:
                            pass
                    menu.add_command(label=tr("Link öffnen", "Open link"), command=open_link)
                    try:
                        menu.tk_popup(event.x_root, event.y_root)
                    finally:
                        menu.grab_release()
            def create_table():
                nonlocal table_tree, table_headers, table_frame
                cols = simpledialog.askinteger(tr("Spaltenzahl", "Number of columns"),
                                               tr("Wie viele Spalten?", "How many columns?"),
                                               parent=top, minvalue=1, maxvalue=20)
                if not cols:
                    return
                rows = simpledialog.askinteger(tr("Zeilenzahl", "Number of rows"),
                                               tr("Wie viele Zeilen?", "How many rows?"),
                                               parent=top, minvalue=1, maxvalue=100)
                if not rows:
                    return
                headers_local: List[str] = []
                for i2 in range(cols):
                    name2 = simpledialog.askstring(tr("Spaltenkopf", "Column header"),
                                                   tr("Name für Spalte", "Name for column") + f" {i2+1}:", parent=top)
                    if not name2:
                        name2 = f"Col{i2+1}"
                    headers_local.append(name2)
                table_headers[:] = headers_local
                # Entferne alte Tabelle
                for child in table_frame.winfo_children():
                    child.destroy()
                tv2 = ttk.Treeview(table_frame, columns=headers_local, show="headings")
                try:
                    style_local = ttk.Style()
                    # Tabelle im Editor verwendet den globalen Tabellenhintergrund
                    style_local.configure("Custom.Edit.Treeview", background=TABLE_BG_COLOR, fieldbackground=TABLE_BG_COLOR)
                    if GUI_FG_COLOR:
                        style_local.configure("Custom.Edit.Treeview", foreground=GUI_FG_COLOR)
                    tv2.configure(style="Custom.Edit.Treeview")
                except Exception:
                    pass
                # Tags für Zeilenhintergründe definieren
                try:
                    tv2.tag_configure("evenrow", background=TABLE_BG_COLOR)
                    tv2.tag_configure("oddrow", background=ENTRY_BG_COLOR)
                except Exception:
                    pass
                for h2 in headers_local:
                    tv2.heading(h2, text=h2, command=lambda col=h2: sort_table(col))
                    tv2.column(h2, width=100, anchor="w")
                # Füge die gewünschten leeren Zeilen mit alternierenden Tags hinzu
                for r2 in range(rows):
                    tag_name2 = "evenrow" if r2 % 2 == 0 else "oddrow"
                    tv2.insert("", "end", values=["" for _ in headers_local], tags=(tag_name2,))
                sb_y2 = ttk.Scrollbar(table_frame, orient="vertical", command=tv2.yview)
                sb_x2 = ttk.Scrollbar(table_frame, orient="horizontal", command=tv2.xview)
                tv2.configure(yscrollcommand=sb_y2.set, xscrollcommand=sb_x2.set)
                tv2.grid(row=0, column=0, sticky="nsew")
                sb_y2.grid(row=0, column=1, sticky="ns")
                sb_x2.grid(row=1, column=0, sticky="ew")
                # Füge Gitterlinien hinzu, um Spalten und Zeilen klar zu trennen
                try:
                    add_grid_to_treeview(tv2)
                except Exception:
                    pass
                table_frame.rowconfigure(0, weight=1)
                table_frame.columnconfigure(0, weight=1)
                tv2.bind("<Double-1>", edit_cell)
                tv2.bind("<Button-3>", on_right_click)
                table_tree = tv2
            def edit_columns():
                nonlocal table_headers, table_tree, table_frame
                if not table_headers:
                    messagebox.showinfo(tr("Info", "Info"), tr("Keine Tabelle vorhanden.", "No table exists."), parent=top)
                    return
                col_win = tk.Toplevel(top)
                col_win.title(tr("Spalten bearbeiten", "Edit columns"))
                col_win.transient(top)
                col_frame = ttk.Frame(col_win, padding=8)
                col_frame.grid(row=0, column=0, sticky="nsew")
                col_win.columnconfigure(0, weight=1)
                col_win.rowconfigure(0, weight=1)
                entries_cols: List[ttk.Entry] = []
                def remove_last():
                    nonlocal entries_cols
                    if not entries_cols:
                        return
                    idx2 = len(entries_cols) - 1
                    ent2 = entries_cols.pop()
                    ent2.destroy()
                    for w in col_frame.grid_slaves(row=idx2, column=0):
                        w.destroy()
                def add_col():
                    idx2 = len(entries_cols)
                    ttk.Label(col_frame, text=tr("Spalte", "Column") + f" {idx2+1}:").grid(row=idx2, column=0, sticky="w", pady=2)
                    ent2 = ttk.Entry(col_frame)
                    ent2.grid(row=idx2, column=1, sticky="ew", pady=2)
                    col_frame.columnconfigure(1, weight=1)
                    entries_cols.append(ent2)
                # Bestehende Spalten vorbelegen
                for i2, h2 in enumerate(table_headers):
                    ttk.Label(col_frame, text=tr("Spalte", "Column") + f" {i2+1}:").grid(row=i2, column=0, sticky="w", pady=2)
                    e2 = ttk.Entry(col_frame)
                    e2.insert(0, h2)
                    e2.grid(row=i2, column=1, sticky="ew", pady=2)
                    col_frame.columnconfigure(1, weight=1)
                    entries_cols.append(e2)
                btn_add = ttk.Button(col_frame, text=tr("Spalte hinzufügen", "Add column"), command=add_col)
                btn_remove = ttk.Button(col_frame, text=tr("Spalte entfernen", "Remove column"), command=remove_last)
                btn_add.grid(row=len(entries_cols)+1, column=0, pady=(6,2), sticky="w")
                btn_remove.grid(row=len(entries_cols)+1, column=1, pady=(6,2), sticky="w")
                def apply_changes():
                    nonlocal table_headers, table_tree
                    new_headers2: List[str] = []
                    for idx2, ent2 in enumerate(entries_cols):
                        txt2 = ent2.get().strip()
                        new_headers2.append(txt2 if txt2 else f"Col{idx2+1}")
                    rows_val2: List[List[str]] = []
                    if table_tree:
                        for iid2 in table_tree.get_children(""):
                            rows_val2.append([table_tree.set(iid2, h3) for h3 in table_headers])
                    table_headers[:] = new_headers2
                    for child in table_frame.winfo_children():
                        child.destroy()
                    tv_new2 = ttk.Treeview(table_frame, columns=new_headers2, show="headings")
                    try:
                        st = ttk.Style()
                        st.configure("Custom.Edit.Rebuild", background=TABLE_BG_COLOR, fieldbackground=TABLE_BG_COLOR)
                        if GUI_FG_COLOR:
                            st.configure("Custom.Edit.Rebuild", foreground=GUI_FG_COLOR)
                        tv_new2.configure(style="Custom.Edit.Rebuild")
                    except Exception:
                        pass
                    # Konfiguriere Zeilentags für alternierende Hintergründe
                    try:
                        tv_new2.tag_configure("evenrow", background=TABLE_BG_COLOR)
                        tv_new2.tag_configure("oddrow", background=ENTRY_BG_COLOR)
                    except Exception:
                        pass
                    for h3 in new_headers2:
                        tv_new2.heading(h3, text=h3, command=lambda col=h3: sort_table(col))
                        tv_new2.column(h3, width=100, anchor="w")
                    # Füge Zeilen mit alternierenden Tags ein
                    for idx_row2, row2 in enumerate(rows_val2):
                        vals2 = row2[:len(new_headers2)] + [""] * (len(new_headers2) - len(row2))
                        tag_name2 = "evenrow" if idx_row2 % 2 == 0 else "oddrow"
                        tv_new2.insert("", "end", values=vals2, tags=(tag_name2,))
                    sb_y3 = ttk.Scrollbar(table_frame, orient="vertical", command=tv_new2.yview)
                    sb_x3 = ttk.Scrollbar(table_frame, orient="horizontal", command=tv_new2.xview)
                    tv_new2.configure(yscrollcommand=sb_y3.set, xscrollcommand=sb_x3.set)
                    tv_new2.grid(row=0, column=0, sticky="nsew")
                    sb_y3.grid(row=0, column=1, sticky="ns")
                    sb_x3.grid(row=1, column=0, sticky="ew")
                    # Gitterlinien hinzufügen, um die Tabelle optisch klar zu strukturieren
                    try:
                        add_grid_to_treeview(tv_new2)
                    except Exception:
                        pass
                    table_frame.rowconfigure(0, weight=1)
                    table_frame.columnconfigure(0, weight=1)
                    tv_new2.bind("<Double-1>", edit_cell)
                    tv_new2.bind("<Button-3>", on_right_click)
                    table_tree = tv_new2
                    col_win.destroy()
                def cancel_changes():
                    col_win.destroy()
                btn_save2 = ttk.Button(col_frame, text=tr("OK", "OK"), command=apply_changes)
                btn_cancel2 = ttk.Button(col_frame, text=tr("Abbrechen", "Cancel"), command=cancel_changes)
                btn_save2.grid(row=len(entries_cols)+2, column=0, pady=(6,4), sticky="w")
                btn_cancel2.grid(row=len(entries_cols)+2, column=1, pady=(6,4), sticky="w")
            # Buttons und Zeilenumbruch-Optionen
            wrap_var = tk.BooleanVar(value=False)
            def toggle_wrap():
                txt_info.configure(wrap="word" if wrap_var.get() else "none")
            # Erzeuge Buttons und gruppiere sie in einem separaten Frame. Dies erleichtert die
            # einheitliche Platzierung. Der Wrap-Checkbutton bleibt separat.
            btn_create_table = ttk.Button(frm, text=tr("Tabelle erstellen", "Create table"), command=create_table)
            btn_edit_columns = ttk.Button(frm, text=tr("Spalten bearbeiten", "Edit columns"), command=edit_columns)
            # Buttons befinden sich in einem Rahmen innerhalb des Info-Containers, damit sie direkt
            # unter der Tabelle angezeigt werden können.
            table_btn_frame = ttk.Frame(info_container)
            btn_create_table.pack(in_=table_btn_frame, side="left", padx=2)
            btn_edit_columns.pack(in_=table_btn_frame, side="left", padx=2)
            wrap_check = ttk.Checkbutton(frm, text=tr("Zeilenumbruch", "Wrap lines"), variable=wrap_var, command=toggle_wrap)
            def on_format_change(event=None):
                fmt = info_format_var.get()
                # Verstecke bisherige Unterwidgets
                for child in info_container.winfo_children():
                    child.grid_forget()
                table_btn_frame.grid_remove()
                wrap_check.grid_remove()
                if fmt == tr("Tabelle", "Table"):
                    # Zeige die Tabelle und die Bearbeiten-Buttons innerhalb des Info-Containers
                    table_frame.grid(row=0, column=0, sticky="nsew")
                    # Wenn noch keine Tabelle vorhanden ist, erstelle eine leere
                    if not table_headers:
                        create_table()
                    table_btn_frame.grid(row=1, column=0, sticky="w", pady=4)
                    # Der Info-Container lässt die Tabelle nach oben wachsen
                    info_container.rowconfigure(0, weight=1)
                else:
                    text_frame.grid(row=0, column=0, sticky="nsew")
                    wrap_check.grid(row=7, column=1, sticky="w", pady=(2,0))
            # Initialisierung je nach bestehendem Info
            if is_table_default and table_data_default:
                try:
                    headers0 = table_data_default.get("headers", [])
                    rows0 = table_data_default.get("rows", [])
                    table_headers[:] = list(headers0)
                    for child in table_frame.winfo_children():
                        child.destroy()
                    tv0 = ttk.Treeview(table_frame, columns=table_headers, show="headings")
                    try:
                        style0 = ttk.Style()
                        style0.configure("Custom.Init.Edit", background=TABLE_BG_COLOR, fieldbackground=TABLE_BG_COLOR)
                        if GUI_FG_COLOR:
                            style0.configure("Custom.Init.Edit", foreground=GUI_FG_COLOR)
                        tv0.configure(style="Custom.Init.Edit")
                    except Exception:
                        pass
                    # Definiere Tags für abwechselnde Zeilenfarben auch für die initiale Tabelle
                    try:
                        tv0.tag_configure("evenrow", background=TABLE_BG_COLOR)
                        tv0.tag_configure("oddrow", background=ENTRY_BG_COLOR)
                    except Exception:
                        pass
                    for h0 in table_headers:
                        tv0.heading(h0, text=h0, command=lambda col=h0: sort_table(col))
                        tv0.column(h0, width=100, anchor="w")
                    # Füge vorhandene Daten mit alternierenden Tags ein
                    for idx0, row0 in enumerate(rows0):
                        vals0 = row0[:len(table_headers)] + [""] * (len(table_headers) - len(row0))
                        tag_name0 = "evenrow" if idx0 % 2 == 0 else "oddrow"
                        tv0.insert("", "end", values=vals0, tags=(tag_name0,))
                    sb_y0 = ttk.Scrollbar(table_frame, orient="vertical", command=tv0.yview)
                    sb_x0 = ttk.Scrollbar(table_frame, orient="horizontal", command=tv0.xview)
                    tv0.configure(yscrollcommand=sb_y0.set, xscrollcommand=sb_x0.set)
                    tv0.grid(row=0, column=0, sticky="nsew")
                    sb_y0.grid(row=0, column=1, sticky="ns")
                    sb_x0.grid(row=1, column=0, sticky="ew")
                    # Füge Gitterlinien hinzu, damit Zeilen und Spalten deutlich abgegrenzt sind
                    try:
                        add_grid_to_treeview(tv0)
                    except Exception:
                        pass
                    table_frame.rowconfigure(0, weight=1)
                    table_frame.columnconfigure(0, weight=1)
                    tv0.bind("<Double-1>", edit_cell)
                    tv0.bind("<Button-3>", on_right_click)
                    table_tree = tv0
                except Exception:
                    txt_info.delete("1.0", "end")
                    txt_info.insert("1.0", e.info)
            else:
                txt_info.delete("1.0", "end")
                txt_info.insert("1.0", e.info if e.info else "")
            on_format_change()
            fmt_combo.bind("<<ComboboxSelected>>", on_format_change)
            # Button-Leiste für Speichern/Abbrechen
            btnf = ttk.Frame(frm)
            btnf.grid(row=8, column=1, sticky="w", pady=8)
            ttk.Button(btnf, text=tr("Speichern", "Save"), command=on_save_click).pack(side="left", padx=4)
            ttk.Button(btnf, text=tr("Abbrechen", "Cancel"), command=top.destroy).pack(side="left", padx=4)

        def gui_delete(self):
            self.touch()
            sel = self.tree.selection()
            if not sel: return
            iid = str(self.tree.item(sel[0])["values"][0])  # ← NEU
            e = self.vault.entries.get(iid)
            if not e: return
            if not messagebox.askyesno(
                tr("Löschen", "Delete"),
                tr("Wirklich löschen ", "Really delete ") + f"'{e.label}'?",
                parent=self.root,
            ):
                return
            lbl = e.label
            # Arbeiterfunktion zum Entfernen und Speichern
            def do_delete_work(entry_id: str, label: str) -> None:
                # Entferne den Eintrag und speichere den Tresor
                del self.vault.entries[entry_id]
                self.vault.updated_at = time.time()
                save_vault(self.path, self.vault, self.master_pw)
                write_audit("delete", f"{entry_id}|{label}")
            # Callback nach erfolgreichem Löschen
            def on_delete_success(_res: None = None):
                self.refresh_tree()
            # Callback bei Fehler
            def on_delete_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Löschen fehlgeschlagen:", "Delete failed:") + f"\n{exc}",
                    parent=self.root,
                )
            # Starte den Fortschrittsdialog
            self.run_with_progress(
                tr("Eintrag löschen", "Delete entry"),
                tr("Eintrag wird gelöscht. Bitte warten...", "Entry is being deleted. Please wait..."),
                do_delete_work,
                args=(iid, lbl),
                on_success=on_delete_success,
                on_error=on_delete_error,
            )

        def gui_export_entry(self):
            self.touch()
            sel = self.tree.selection()
            if not sel: return
            iid = str(self.tree.item(sel[0])["values"][0])  # ← NEU
            e = self.vault.entries.get(iid)
            if not e: return
            f = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[(tr("Text-Dateien", "Text files"), "*.txt")],
            )
            if not f: return
            export_entry_txt(self.vault, iid, Path(f))
            # Audit: export single entry
            write_audit("export_entry", f"{iid}|{e.label}")
            messagebox.showinfo(
                tr("OK", "OK"),
                tr("Exportiert → ", "Exported → ") + f"{f}",
            )

        def gui_export_all(self):
            self.touch()
            f = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[(tr("Text-Dateien", "Text files"), "*.txt")],
            )
            if not f: return
            export_all_txt(self.vault, Path(f))
            # Audit: export all (txt)
            write_audit("export_all", f"{len(self.vault.entries)} entries (txt)")
            messagebox.showinfo(
                tr("OK", "OK"),
                tr("Exportiert → ", "Exported → ") + f"{f}",
            )

        def gui_export_csv(self):
            self.touch()
            f = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[(tr("CSV-Dateien", "CSV files"), "*.csv")],
            )
            if not f: return
            export_all_csv(self.vault, Path(f))
            # Audit: export all (csv)
            write_audit("export_all", f"{len(self.vault.entries)} entries (csv)")
            messagebox.showinfo(
                tr("OK", "OK"),
                tr("Exportiert → ", "Exported → ") + f"{f}",
            )

        def gui_import_csv(self):
            """Importiert Einträge aus einer CSV‑Datei in den aktuellen Tresor.

            Der Benutzer wählt zunächst eine CSV‑Datei aus. Die Einträge werden
            mithilfe der Funktion ``import_entries_from_csv`` geladen und dem
            Tresor hinzugefügt. Jede importierte Zeile erhält eine neue
            eindeutige ID. Nach dem Import wird der Tresor gespeichert und
            die Baumansicht aktualisiert. Fehler werden per Dialog gemeldet.
            """
            self.touch()
            f = filedialog.askopenfilename(
                title=tr("CSV-Datei wählen", "Select CSV file"),
                filetypes=[
                    (tr("CSV-Dateien", "CSV files"), "*.csv"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if not f:
                return
            try:
                count = import_entries_from_csv(self.vault, Path(f))
                if count:
                    save_vault(self.path, self.vault, self.master_pw)
                    # Audit: import csv
                    write_audit("import_csv", f"{count} entries")
                    self.refresh_tree()
                    messagebox.showinfo(
                        tr("Import abgeschlossen", "Import completed"),
                        f"{count} " + tr("Einträge importiert.", "entries imported."),
                    )
                else:
                    messagebox.showinfo(
                        tr("Keine Einträge", "No entries"),
                        tr("Die CSV-Datei enthielt keine importierbaren Einträge.", "The CSV file contained no importable entries."),
                    )
            except Exception as e:
                messagebox.showerror(
                    tr("Import-Fehler", "Import error"),
                    tr("Fehler beim Importieren: ", "Error during import: ") + f"{e}",
                )

        def gui_gen_pw(self):
            self.touch()
            pw = generate_password()
            # Audit: generate password
            write_audit("generate_password", "gui")
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self.root.after(CLIP_CLEAR_MS, lambda: (self.root.clipboard_clear(), None))
            messagebox.showinfo(
                tr("Generiert", "Generated"),
                tr("Passwort generiert und in Zwischenablage kopiert.", "Password generated and copied to clipboard.") + f"\n{pw}",
            )

        def copy_pw_and_clear(self, pw: str):
            self.touch()
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self.root.after(CLIP_CLEAR_MS, lambda: (self.root.clipboard_clear(), None))
            # Note: It is hard to map back to an ID/label in this context; log generic copy
            write_audit("copy_password", "gui")
            messagebox.showinfo(
                tr("Zwischenablage", "Clipboard"),
                tr(
                    "Passwort in Zwischenablage kopiert (wird in 30s geleert).",
                    "Password copied to clipboard (will be cleared in 30s).",
                ),
            )

        def gui_change_master_pw(self):
            self.touch()
            cur = simpledialog.askstring(
                tr("Aktuell", "Current"),
                tr("Aktuelles Master-Passwort:", "Current master password:"),
                show="*",
                parent=self.root,
            )
            if cur != self.master_pw:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Aktuelles Passwort falsch", "Current password is wrong"),
                    parent=self.root,
                )
                return
            np1 = simpledialog.askstring(
                tr("Neu", "New"),
                tr("Neues Master-Passwort:", "New master password:"),
                show="*",
                parent=self.root,
            )
            if not np1:
                return
            np2 = simpledialog.askstring(
                tr("Bestätigen", "Confirm"),
                tr("Bestätigen:", "Confirm:"),
                show="*",
                parent=self.root,
            )
            if np1 != np2:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Nicht identisch", "Not identical"),
                    parent=self.root,
                )
                return
            # Prüfe Passwortpolitik (Mindestlänge, Zeichentypen).
            try:
                ok_policy, reason = _check_master_policy(np1)
            except Exception:
                ok_policy, reason = True, ""
            if not ok_policy:
                # Frage den Benutzer, ob er trotz Verletzung der Policy fortfahren möchte.
                if not messagebox.askyesno(
                    tr("Schwaches Master-Passwort", "Weak master password"),
                    reason + ". " + tr("Fortfahren?", "Continue?"),
                    parent=self.root,
                ):
                    return
                # Kurze Verzögerung, um schnelle Angriffe zu verlangsamen
                try:
                    time.sleep(1.5)
                except Exception:
                    pass
            # Prüfe Stärke des neuen Passworts mit dem bisherigen Heuristik-Score
            cat, score = password_strength(np1)
            if score < 40:
                if not messagebox.askyesno(
                    tr("Schwaches Passwort", "Weak password"),
                    tr("Passwortstärke", "Password strength") + f" {cat} ({score}). " + tr("Fortfahren?", "Continue?"),
                    parent=self.root,
                ):
                    return
            # Arbeiterfunktion zum Speichern mit neuem Passwort
            def do_change_pw_work(new_pw: str) -> None:
                save_vault(self.path, self.vault, new_pw)
                return None
            def on_change_success(_res: None = None):
                self.master_pw = np1
                write_audit("change_master_password", "")
                messagebox.showinfo(
                    tr("OK", "OK"),
                    tr("Master-Passwort geändert", "Master password changed"),
                    parent=self.root,
                )
            def on_change_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Ändern des Master-Passworts fehlgeschlagen:", "Changing master password failed:") + f"\n{exc}",
                    parent=self.root,
                )
            # Starte Fortschrittsdialog
            self.run_with_progress(
                tr("Master-Passwort ändern", "Change master password"),
                tr("Neues Master-Passwort wird gespeichert. Bitte warten...", "Saving new master password. Please wait..."),
                do_change_pw_work,
                args=(np1,),
                on_success=on_change_success,
                on_error=on_change_error,
            )

        def gui_resave(self):
            self.touch()
            # Arbeiterfunktion für die Neuverschlüsselung
            def do_resave_work() -> None:
                save_vault(self.path, self.vault, self.master_pw)
                write_audit("rerandomize", "")
            # Callback bei Erfolg
            def on_resave_success(_res: None = None):
                messagebox.showinfo(
                    tr("OK", "OK"),
                    tr("Tresor neu verschlüsselt und gespeichert.", "Vault re-encrypted and saved."),
                    parent=self.root,
                )
            # Callback bei Fehler
            def on_resave_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Re-Randomizing fehlgeschlagen:", "Re-randomizing failed:") + f"\n{exc}",
                    parent=self.root,
                )
            self.run_with_progress(
                tr("Neu verschlüsseln", "Re-encrypt"),
                tr("Tresor wird neu verschlüsselt. Bitte warten...", "Vault is being re-encrypted. Please wait..."),
                do_resave_work,
                on_success=on_resave_success,
                on_error=on_resave_error,
            )

        def gui_encrypt_any_file(self):
            """Lässt den Benutzer eine Datei auswählen und verschlüsseln.

            Es werden eine Quell-Datei, eine Ausgabedatei und ein Passwort abgefragt.
            Die verschlüsselte Datei wird geschrieben. Fehler werden mit einem Dialog angezeigt.
            """
            self.touch()
            # Wähle die Datei, die verschlüsselt werden soll. Titel und Dateitypen werden übersetzt.
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Datei zum Verschlüsseln wählen", "Select file to encrypt"),
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if not f:
                return
            base = os.path.basename(f)
            out = filedialog.asksaveasfilename(
                parent=self.root,
                title=tr(
                    "Speicherort für verschlüsselte Datei wählen",
                    "Select destination for encrypted file",
                ),
                initialfile=base + ".enc",
                defaultextension=".enc",
                filetypes=[
                    (tr("Verschlüsselte Datei", "Encrypted file"), "*.enc"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if not out:
                return
            # Doppelte Passwortabfrage zur Minimierung von Tippfehlern – Titel und Prompts übersetzt
            pw1 = simpledialog.askstring(
                tr("Passwort", "Password"),
                tr("Passwort für Verschlüsselung:", "Password for encryption:"),
                show="*",
                parent=self.root,
            )
            if not pw1:
                return
            pw2 = simpledialog.askstring(
                tr("Bestätigen", "Confirm"),
                tr("Passwort erneut eingeben:", "Re-enter password:"),
                show="*",
                parent=self.root,
            )
            if pw1 != pw2:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Passwörter stimmen nicht überein.", "Passwords do not match."),
                    parent=self.root,
                )
                return
            # Arbeiterfunktion für Verschlüsselung
            def do_encrypt_work(src: Path, passwd: str, dest: Path) -> None:
                encrypt_file_data(src, passwd, dest)
                write_audit("encrypt_file", f"{src}->{dest}")
                return None
            # Callback bei Erfolg
            def on_enc_success(_res: None = None):
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Datei verschlüsselt:", "File encrypted:") + f"\n{out}",
                    parent=self.root,
                )
            # Callback bei Fehler
            def on_enc_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Verschlüsselung fehlgeschlagen:", "Encryption failed:") + f"\n{exc}",
                    parent=self.root,
                )
            # Starte Fortschrittsdialog
            self.run_with_progress(
                tr("Datei verschlüsseln", "Encrypt file"),
                tr(
                    "Datei wird verschlüsselt. Bitte warten...",
                    "File is being encrypted. Please wait...",
                ),
                do_encrypt_work,
                args=(Path(f), pw1, Path(out)),
                on_success=on_enc_success,
                on_error=on_enc_error,
            )

        def gui_decrypt_any_file(self):
            """Lässt den Benutzer eine verschlüsselte Datei auswählen und entschlüsseln."""
            self.touch()
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Verschlüsselte Datei wählen", "Select encrypted file"),
                filetypes=[
                    (tr("Verschlüsselte Dateien", "Encrypted files"), "*.enc"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if not f:
                return
            base = os.path.basename(f)
            # Standard: Originalname ohne .enc Endung
            base_out = base[:-4] if base.lower().endswith(".enc") else base + ".dec"
            out = filedialog.asksaveasfilename(
                parent=self.root,
                title=tr(
                    "Speicherort für entschlüsselte Datei wählen",
                    "Select destination for decrypted file",
                ),
                initialfile=base_out,
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if not out:
                return
            pw = simpledialog.askstring(
                tr("Passwort", "Password"),
                tr("Passwort für Entschlüsselung:", "Password for decryption:"),
                show="*",
                parent=self.root,
            )
            if not pw:
                return
            # Arbeiterfunktion für Entschlüsselung
            def do_decrypt_work(src: Path, passwd: str, dest: Path) -> None:
                decrypt_file_data(src, passwd, dest)
                write_audit("decrypt_file", f"{src}->{dest}")
                return None
            # Callback bei Erfolg
            def on_dec_success(_res: None = None):
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Datei entschlüsselt:", "File decrypted:") + f"\n{out}",
                    parent=self.root,
                )
            # Callback bei Fehler
            def on_dec_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Entschlüsselung fehlgeschlagen:", "Decryption failed:") + f"\n{exc}",
                    parent=self.root,
                )
            self.run_with_progress(
                tr("Datei entschlüsseln", "Decrypt file"),
                tr(
                    "Datei wird entschlüsselt. Bitte warten...",
                    "File is being decrypted. Please wait...",
                ),
                do_decrypt_work,
                args=(Path(f), pw, Path(out)),
                on_success=on_dec_success,
                on_error=on_dec_error,
            )

        def gui_hide_file(self):
            """Versteckt eine Datei in einer anderen Datei (Cover)."""
            self.touch()
            # Wähle die Datei, die versteckt werden soll
            data_f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Datei zum Verstecken wählen", "Select file to hide"),
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if not data_f:
                return
            # Wähle die Cover-Datei
            cover_f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Cover-Datei wählen", "Select cover file"),
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if not cover_f:
                return
            base = os.path.basename(cover_f)
            # Vorschlag für Ausgabedatei: Cover-Datei + .hid
            out_f = filedialog.asksaveasfilename(
                parent=self.root,
                title=tr(
                    "Speicherort für Datei mit verstecktem Inhalt wählen",
                    "Select destination for file with hidden content",
                ),
                initialfile=base + ".hid",
                defaultextension=".hid",
                filetypes=[
                    (tr("Versteckte Datei", "Hidden file"), "*.hid"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if not out_f:
                return
            # Passwort doppelt abfragen zur Fehlervermeidung
            pw1 = simpledialog.askstring(
                tr("Passwort", "Password"),
                tr("Passwort für Verschlüsselung:", "Password for encryption:"),
                show="*",
                parent=self.root,
            )
            if not pw1:
                return
            pw2 = simpledialog.askstring(
                tr("Bestätigen", "Confirm"),
                tr("Passwort erneut eingeben:", "Re-enter password:"),
                show="*",
                parent=self.root,
            )
            if pw1 != pw2:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Passwörter stimmen nicht überein.", "Passwords do not match."),
                    parent=self.root,
                )
                return
            try:
                hide_file_in_file(Path(cover_f), Path(data_f), pw1, Path(out_f))
                write_audit("hide_file", f"{data_f}@{cover_f}->{out_f}")
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Datei versteckt:", "File hidden:") + f"\n{out_f}",
                )
            except Exception as e:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Verstecken fehlgeschlagen:", "Hiding failed:") + f"\n{e}",
                )

        def gui_extract_hidden_file(self):
            """Extrahiert eine versteckte Datei aus einer Datei."""
            self.touch()
            stego_f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Datei mit verstecktem Inhalt wählen", "Select file with hidden content"),
                filetypes=[
                    (tr("Versteckte Datei", "Hidden file"), "*.hid"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if not stego_f:
                return
            pw = simpledialog.askstring(
                tr("Passwort", "Password"),
                tr("Passwort für Entschlüsselung:", "Password for decryption:"),
                show="*",
                parent=self.root,
            )
            if not pw:
                return
            # Versuche, Nutzlast zu entschlüsseln und den ursprünglichen Dateinamen zu ermitteln
            try:
                orig_name, payload = decrypt_hidden_payload(Path(stego_f), pw)
            except Exception as e:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Extraktion fehlgeschlagen:", "Extraction failed:") + f"\n{e}",
                )
                return
            # Zeige erkannte Datei/Endung an
            messagebox.showinfo(
                tr("Versteckte Datei", "Hidden file"),
                tr("Es wurde folgende Datei erkannt:", "The following file was detected:") + f"\n{orig_name}",
            )
            # Vorschlag für Ausgabedatei: ursprünglicher Name im gleichen Verzeichnis
            suggested = Path(stego_f).with_name(orig_name)
            out_f = filedialog.asksaveasfilename(
                parent=self.root,
                title=tr(
                    "Speicherort für extrahierte Datei wählen",
                    "Select destination for extracted file",
                ),
                initialfile=suggested.name,
                defaultextension=Path(orig_name).suffix or ".extrahiert",
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if not out_f:
                return
            try:
                atomic_write(Path(out_f), payload)
                write_audit("extract_file", f"{stego_f}->{out_f}")
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Datei extrahiert:", "File extracted:") + f"\n{out_f}",
                )
            except Exception as e:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Schreiben fehlgeschlagen:", "Write failed:") + f"\n{e}",
                )

        # Erweiterte Funktionen zur Auswahl von Dateien für das Verstecken/Extrahieren.
        # Diese Methoden aktualisieren jeweils die zugehörigen StringVar-Variablen und
        # zeigen den ausgewählten Pfad in der GUI an.
        def gui_select_hide_data(self):
            """Wählt die Datei aus, die versteckt werden soll."""
            self.touch()
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Datei zum Verstecken wählen", "Select file to hide"),
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if f:
                try:
                    self.hide_data_path.set(f)
                except Exception:
                    self.hide_data_path = f

        def gui_select_hide_cover(self):
            """Wählt die Cover-Datei, in der der Inhalt versteckt wird."""
            self.touch()
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Cover-Datei wählen", "Select cover file"),
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if f:
                try:
                    self.hide_cover_path.set(f)
                except Exception:
                    self.hide_cover_path = f

        def gui_select_hide_output(self):
            """Wählt den Ausgabepfad für die Datei mit verstecktem Inhalt (.hid)."""
            self.touch()
            # Wenn es eine Cover-Datei gibt, schlage den selben Dateinamen plus .hid vor
            try:
                cover = self.hide_cover_path.get()
            except Exception:
                cover = self.hide_cover_path
            base = os.path.basename(cover) if cover else ""
            initial = base + ".hid" if base else ""
            f = filedialog.asksaveasfilename(
                parent=self.root,
                title=tr("Speicherort für versteckte Datei wählen", "Select destination for hidden file"),
                initialfile=initial,
                defaultextension=".hid",
                filetypes=[
                    (tr("Versteckte Datei", "Hidden file"), "*.hid"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if f:
                try:
                    self.hide_output_path.set(f)
                except Exception:
                    self.hide_output_path = f

        def gui_do_hide(self):
            """Führt das Verstecken der ausgewählten Datei in der Cover-Datei durch."""
            self.touch()
            # Pfade auslesen (StringVar oder einfache Strings)
            try:
                data_path = self.hide_data_path.get().strip()
            except Exception:
                data_path = str(self.hide_data_path).strip()
            try:
                cover_path = self.hide_cover_path.get().strip()
            except Exception:
                cover_path = str(self.hide_cover_path).strip()
            try:
                out_path = self.hide_output_path.get().strip()
            except Exception:
                out_path = str(self.hide_output_path).strip()
            # Validierungsprüfungen
            if not data_path:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr(
                        "Bitte wählen Sie eine Datei aus, die versteckt werden soll.",
                        "Please select a file to hide.",
                    ),
                    parent=self.root,
                )
                return
            if not cover_path:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr(
                        "Bitte wählen Sie eine Cover-Datei aus.",
                        "Please select a cover file.",
                    ),
                    parent=self.root,
                )
                return
            if not out_path:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr(
                        "Bitte wählen Sie einen Ausgabepfad für die versteckte Datei.",
                        "Please select a destination path for the hidden file.",
                    ),
                    parent=self.root,
                )
                return
            # Passwort doppelt abfragen zur Fehlervermeidung
            pw1 = simpledialog.askstring(
                tr("Passwort", "Password"),
                tr("Passwort für Verschlüsselung:", "Password for encryption:"),
                show="*",
                parent=self.root,
            )
            if not pw1:
                return
            pw2 = simpledialog.askstring(
                tr("Bestätigen", "Confirm"),
                tr("Passwort erneut eingeben:", "Re-enter password:"),
                show="*",
                parent=self.root,
            )
            if pw1 != pw2:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Passwörter stimmen nicht überein.", "Passwords do not match."),
                    parent=self.root,
                )
                return
            # Arbeiterfunktion für Verstecken
            def do_hide_work(cov: str, data: str, passwd: str, dest: str) -> None:
                hide_file_in_file(Path(cov), Path(data), passwd, Path(dest))
                write_audit("hide_file", f"{data}@{cov}->{dest}")
                return None
            # Callback bei Erfolg
            def on_hide_success(_res: None = None):
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Datei wurde versteckt:", "File hidden:") + f"\n{out_path}",
                    parent=self.root,
                )
                # Felder leeren
                try:
                    self.hide_data_path.set("")
                    self.hide_cover_path.set("")
                    self.hide_output_path.set("")
                except Exception:
                    pass
            # Callback bei Fehler
            def on_hide_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Verstecken fehlgeschlagen:", "Hiding failed:") + f"\n{exc}",
                    parent=self.root,
                )
            # Starte Fortschrittsdialog
            self.run_with_progress(
                tr("Datei verstecken", "Hide file"),
                tr(
                    "Datei wird versteckt. Bitte warten...",
                    "File is being hidden. Please wait...",
                ),
                do_hide_work,
                args=(cover_path, data_path, pw1, out_path),
                on_success=on_hide_success,
                on_error=on_hide_error,
            )

        def gui_select_extract_stego(self):
            """Wählt die .hid-Datei mit verstecktem Inhalt."""
            self.touch()
            f = filedialog.askopenfilename(
                parent=self.root,
                title=tr("Datei mit verstecktem Inhalt wählen", "Select file with hidden content"),
                filetypes=[
                    (tr("Versteckte Datei", "Hidden file"), "*.hid"),
                    (tr("Alle Dateien", "All files"), "*.*"),
                ],
            )
            if f:
                try:
                    self.extract_stego_path.set(f)
                except Exception:
                    self.extract_stego_path = f

        def gui_select_extract_output(self):
            """Wählt den Ausgabepfad für die extrahierte Datei."""
            self.touch()
            # Standardmäßig wird kein spezieller Dateiname vorgeschlagen, da der Dateiname
            # aus der Stego-Datei ermittelt werden kann. Der Benutzer kann aber
            # optional einen eigenen Dateinamen angeben.
            f = filedialog.asksaveasfilename(
                parent=self.root,
                title=tr(
                    "Speicherort für extrahierte Datei wählen",
                    "Select destination for extracted file",
                ),
                defaultextension="",
                filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
            )
            if f:
                try:
                    self.extract_output_path.set(f)
                except Exception:
                    self.extract_output_path = f

        def gui_do_extract(self):
            """Extrahiert den versteckten Inhalt aus der angegebenen .hid-Datei."""
            self.touch()
            try:
                stego_f = self.extract_stego_path.get().strip()
            except Exception:
                stego_f = str(self.extract_stego_path).strip()
            try:
                out_f = self.extract_output_path.get().strip()
            except Exception:
                out_f = str(self.extract_output_path).strip()
            if not stego_f:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Bitte wählen Sie eine .hid-Datei aus.", "Please select a .hid file."),
                    parent=self.root,
                )
                return
            if not out_f:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr(
                        "Bitte wählen Sie einen Ausgabepfad für die extrahierte Datei.",
                        "Please select a destination path for the extracted file.",
                    ),
                    parent=self.root,
                )
                return
            pw = simpledialog.askstring(
                tr("Passwort", "Password"),
                tr("Passwort für Entschlüsselung:", "Password for decryption:"),
                show="*",
                parent=self.root,
            )
            if not pw:
                return
            # Arbeiterfunktion: Extrahieren, entschlüsseln und schreiben
            def do_extract_work(stego: str, passwd: str, dest: str) -> str:
                orig_name, payload = decrypt_hidden_payload(Path(stego), passwd)
                # Schreibe die Nutzdaten an den Zielort
                atomic_write(Path(dest), payload)
                write_audit("extract_file", f"{stego}->{dest}")
                return orig_name
            # Callback bei Erfolg
            def on_extract_success(orig_name: str) -> None:
                messagebox.showinfo(
                    tr("Versteckte Datei", "Hidden file"),
                    tr("Es wurde folgende Datei erkannt:", "The following file was detected:") + f"\n{orig_name}",
                    parent=self.root,
                )
                messagebox.showinfo(
                    tr("Erfolg", "Success"),
                    tr("Datei extrahiert:", "File extracted:") + f"\n{out_f}",
                    parent=self.root,
                )
                # Felder leeren
                try:
                    self.extract_stego_path.set("")
                    self.extract_output_path.set("")
                except Exception:
                    pass
            # Callback bei Fehlern
            def on_extract_error(exc: Exception):
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Extraktion fehlgeschlagen:", "Extraction failed:") + f"\n{exc}",
                    parent=self.root,
                )
            # Starte Fortschrittsdialog
            self.run_with_progress(
                tr("Datei extrahieren", "Extract file"),
                tr(
                    "Datei wird extrahiert. Bitte warten...",
                    "File is being extracted. Please wait...",
                ),
                do_extract_work,
                args=(stego_f, pw, out_f),
                on_success=on_extract_success,
                on_error=on_extract_error,
            )

        def gui_open_file_ops_dialog(self):
            """Öffnet ein separates Fenster mit erweiterten Datei-Operationen.

            In diesem Dialog können Dateien verschlüsselt, entschlüsselt, versteckt und
            extrahiert werden. Der Benutzer kann für jede Operation die benötigten
            Pfade auswählen. Alle Operationen funktionieren unabhängig vom Tresor.
            """
            self.touch()
            try:
                import tkinter as tk
            except Exception:
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Tkinter ist nicht verfügbar.", "Tkinter is not available."),
                )
                return
            # Erstelle das Fenster nur einmal. Wenn es bereits existiert, fokussiere es.
            if hasattr(self, "file_ops_window") and self.file_ops_window is not None and self.file_ops_window.winfo_exists():
                self.file_ops_window.lift()
                return
            win = tk.Toplevel(self.root)
            win.title(tr("Datei-Operationen", "File operations"))
            win.geometry("800x600")
            self.file_ops_window = win
            # Hauptbeschreibung
            ttk.Label(
                win,
                text=tr(
                    "In diesem Fenster können Sie beliebige Dateien verschlüsseln, entschlüsseln, verstecken und extrahieren.\n"
                    "Die Operationen sind unabhängig vom Tresor und nutzen den gleichen Sicherheitsalgorithmus.",
                    "In this window you can encrypt, decrypt, hide and extract arbitrary files.\n"
                    "The operations are independent of the vault and use the same security algorithm.",
                ),
                wraplength=760,
                justify="left",
            ).pack(padx=10, pady=(10, 8), anchor="w")
            # Verschlüsselung/Entschlüsselung Abschnitt
            enc_frame = ttk.LabelFrame(
                win,
                text=tr("Datei verschlüsseln / entschlüsseln", "Encrypt / decrypt file"),
                padding=8,
            )
            enc_frame.pack(fill="x", padx=10, pady=(0, 10))
            # Definiere lokale StringVars für Pfade
            enc_in = tk.StringVar(value="")
            enc_out = tk.StringVar(value="")
            dec_in = tk.StringVar(value="")
            dec_out = tk.StringVar(value="")
            # Hilfsfunktionen zur Auswahl
            def select_enc_input():
                f = filedialog.askopenfilename(
                    parent=win,
                    title=tr("Datei zum Verschlüsseln wählen", "Select file to encrypt"),
                    filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
                )
                if f:
                    enc_in.set(f)
            def select_enc_output():
                # Vorschlag: Originalname + .enc
                base = os.path.basename(enc_in.get()) if enc_in.get() else ""
                initial = base + ".enc" if base else ""
                f = filedialog.asksaveasfilename(
                    parent=win,
                    title=tr("Ziel für verschlüsselte Datei", "Destination for encrypted file"),
                    initialfile=initial,
                    defaultextension=".enc",
                    filetypes=[
                        (tr("Verschlüsselte Datei", "Encrypted file"), "*.enc"),
                        (tr("Alle Dateien", "All files"), "*.*"),
                    ],
                )
                if f:
                    enc_out.set(f)
            def do_encrypt():
                src = enc_in.get().strip()
                dst = enc_out.get().strip()
                if not src:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr(
                            "Bitte wählen Sie eine Eingabedatei zum Verschlüsseln.",
                            "Please select an input file to encrypt.",
                        ),
                        parent=win,
                    )
                    return
                if not dst:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr(
                            "Bitte wählen Sie einen Zielpfad für die verschlüsselte Datei.",
                            "Please select a destination path for the encrypted file.",
                        ),
                        parent=win,
                    )
                    return
                # Doppelte Passwortabfrage, um Tippfehler zu vermeiden
                pw1 = simpledialog.askstring(
                    tr("Passwort", "Password"),
                    tr("Passwort für Verschlüsselung:", "Password for encryption:"),
                    show="*",
                    parent=win,
                )
                if not pw1:
                    return
                pw2 = simpledialog.askstring(
                    tr("Bestätigen", "Confirm"),
                    tr("Passwort erneut eingeben:", "Re-enter password:"),
                    show="*",
                    parent=win,
                )
                if pw1 != pw2:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr("Passwörter stimmen nicht überein.", "Passwords do not match."),
                        parent=win,
                    )
                    return
                try:
                    encrypt_file_data(Path(src), pw1, Path(dst))
                    write_audit("encrypt_file", f"{src}->{dst}")
                    messagebox.showinfo(
                        tr("Erfolg", "Success"),
                        tr("Datei verschlüsselt:", "File encrypted:") + f"\n{dst}",
                        parent=win,
                    )
                    enc_in.set(""); enc_out.set("")
                except Exception as e:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr("Verschlüsselung fehlgeschlagen:", "Encryption failed:") + f"\n{e}",
                        parent=win,
                    )
            # Entschlüsselung Hilfsfunktionen
            def select_dec_input():
                f = filedialog.askopenfilename(
                    parent=win,
                    title=tr("Verschlüsselte Datei wählen", "Select encrypted file"),
                    filetypes=[
                        (tr("Verschlüsselte Datei", "Encrypted file"), "*.enc"),
                        (tr("Alle Dateien", "All files"), "*.*"),
                    ],
                )
                if f:
                    dec_in.set(f)
            def select_dec_output():
                f = filedialog.asksaveasfilename(
                    parent=win,
                    title=tr("Ziel für entschlüsselte Datei", "Destination for decrypted file"),
                    defaultextension="",
                    filetypes=[(tr("Alle Dateien", "All files"), "*.*")],
                )
                if f:
                    dec_out.set(f)
            def do_decrypt():
                src = dec_in.get().strip()
                dst = dec_out.get().strip()
                if not src:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr(
                            "Bitte wählen Sie eine .enc-Datei zum Entschlüsseln.",
                            "Please select a .enc file to decrypt.",
                        ),
                        parent=win,
                    )
                    return
                if not dst:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr(
                            "Bitte wählen Sie einen Zielpfad für die entschlüsselte Datei.",
                            "Please select a destination path for the decrypted file.",
                        ),
                        parent=win,
                    )
                    return
                pw = simpledialog.askstring(
                    tr("Passwort", "Password"),
                    tr("Passwort für Entschlüsselung:", "Password for decryption:"),
                    show="*",
                    parent=win,
                )
                if not pw:
                    return
                try:
                    decrypt_file_data(Path(src), pw, Path(dst))
                    write_audit("decrypt_file", f"{src}->{dst}")
                    messagebox.showinfo(
                        tr("Erfolg", "Success"),
                        tr("Datei entschlüsselt:", "File decrypted:") + f"\n{dst}",
                        parent=win,
                    )
                    dec_in.set(""); dec_out.set("")
                except Exception as e:
                    messagebox.showerror(
                        tr("Fehler", "Error"),
                        tr("Entschlüsselung fehlgeschlagen:", "Decryption failed:") + f"\n{e}",
                        parent=win,
                    )
            # Layout für Verschlüsselung
            ttk.Label(enc_frame, text=tr("Datei zum Verschlüsseln auswählen", "Select file to encrypt")).grid(row=0, column=0, sticky="w")
            ttk.Button(enc_frame, text=tr("Datei auswählen", "Select file"), command=select_enc_input).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=enc_in, wraplength=480).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text=tr("Ziel auswählen", "Select destination"), command=select_enc_output).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=enc_out, wraplength=480).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text=tr("Verschlüsseln", "Encrypt"), command=do_encrypt).grid(row=3, column=0, sticky="w", pady=(4, 6))
            # Layout für Entschlüsselung
            ttk.Label(enc_frame, text=tr(".enc-Datei zum Entschlüsseln auswählen", "Select .enc file to decrypt")).grid(row=4, column=0, sticky="w", pady=(8,0))
            ttk.Button(enc_frame, text=tr(".enc-Datei", ".enc file"), command=select_dec_input).grid(row=5, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=dec_in, wraplength=480).grid(row=5, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text=tr("Ziel auswählen", "Select destination"), command=select_dec_output).grid(row=6, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=dec_out, wraplength=480).grid(row=6, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text=tr("Entschlüsseln", "Decrypt"), command=do_decrypt).grid(row=7, column=0, sticky="w", pady=(4, 6))
            # Steganographie-Abschnitt
            steg_frame = ttk.LabelFrame(win, text="Datei verstecken / extrahieren", padding=8)
            steg_frame.pack(fill="x", padx=10, pady=(0, 10))
            ttk.Label(
                steg_frame,
                text=tr(
                    "Wählen Sie die benötigten Dateien zum Verstecken oder Extrahieren und starten Sie den Vorgang.\n"
                    "Beim Verstecken wird die zu versteckende Datei verschlüsselt und ans Ende der Cover-Datei angehängt.",
                    "Select the required files for hiding or extracting and start the operation.\n"
                    "When hiding, the file to be hidden is encrypted and appended to the end of the cover file.",
                ),
                wraplength=760,
                justify="left",
            ).pack(anchor="w", pady=(0, 6))
            # Wir verwenden die bereits im App-Objekt vorhandenen StringVars, damit die Pfade
            # auch im Hauptfenster angezeigt werden können. Falls Tkinter nicht verfügbar ist,
            # verwenden wir einfache Strings.
            hide_ops = ttk.Frame(steg_frame)
            hide_ops.pack(fill="x", pady=(0, 6))
            ttk.Label(hide_ops, text=tr("Verstecken:", "Hide:")).grid(row=0, column=0, sticky="w")

            # Zusätzliche Hilfsbuttons für Cover-Erzeugung und Bild-Aufblähung
            #
            # Die folgenden optionalen Funktionen befinden sich nicht im App‑Objekt und werden
            # ggf. nur definiert, wenn alle Abhängigkeiten vorhanden sind.  Durch die
            # verschachtelte Klassendefinition in ``launch_gui`` stehen diese globalen
            # Funktionen hier nicht im lokalen Namensraum zur Verfügung, was zu einem
            # ``NameError`` führen kann, wenn direkt auf sie zugegriffen wird.  Um dieses
            # Problem zu vermeiden, ermitteln wir die aufzurufende Funktion über ``globals()``
            # zur Laufzeit.  Ist die Funktion nicht vorhanden (oder kein Callable), wird
            # stattdessen eine kleine Info‑Box angezeigt, dass die jeweilige Funktion nicht
            # verfügbar ist.  Diese Fallbacks berücksichtigen die aktuelle Sprache über
            # ``tr()``.

            # Erzeuge einen Befehl zum Generieren eines Cover‑Bildes.  Ist die Funktion
            # ``gui_create_cover_image_generic`` definiert, verwenden wir sie, andernfalls
            # definieren wir einen Fallback, der eine kurze Info anzeigt.
            create_cover_cmd = globals().get("gui_create_cover_image_generic")
            if not callable(create_cover_cmd):
                def create_cover_cmd():
                    try:
                        from tkinter import messagebox
                    except Exception:
                        return
                    messagebox.showinfo(
                        tr("Nicht verfügbar", "Not available"),
                        tr(
                            "Diese Funktion ist nicht verfügbar.",
                            "This function is not available.",
                        ),
                    )

            # Erzeuge einen Befehl zum Aufblasen eines Bildes.  Analog dazu prüfen wir,
            # ob ``gui_inflate_image_generic`` existiert und erstellen sonst einen Fallback.
            inflate_image_cmd = globals().get("gui_inflate_image_generic")
            if not callable(inflate_image_cmd):
                def inflate_image_cmd():
                    try:
                        from tkinter import messagebox
                    except Exception:
                        return
                    messagebox.showinfo(
                        tr("Nicht verfügbar", "Not available"),
                        tr(
                            "Diese Funktion ist nicht verfügbar.",
                            "This function is not available.",
                        ),
                    )

            ttk.Button(
                hide_ops,
                text=tr("Cover-Bild erzeugen…", "Generate cover image…"),
                command=create_cover_cmd,
            ).grid(row=0, column=2, sticky="w", padx=(12, 0))
            ttk.Button(
                hide_ops,
                text=tr("Bild aufblasen…", "Enlarge image…"),
                command=inflate_image_cmd,
            ).grid(row=0, column=3, sticky="w", padx=(6, 0))
            ttk.Button(
                hide_ops,
                text=tr("Zu versteckende Datei", "File to hide"),
                command=self.gui_select_hide_data,
            ).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_data_path, wraplength=480).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(
                hide_ops,
                text=tr("Cover-Datei", "Cover file"),
                command=self.gui_select_hide_cover,
            ).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_cover_path, wraplength=480).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(
                hide_ops,
                text=tr("Ziel (.hid)", "Destination (.hid)"),
                command=self.gui_select_hide_output,
            ).grid(row=3, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_output_path, wraplength=480).grid(row=3, column=1, sticky="w", padx=6)
            ttk.Button(
                hide_ops,
                text=tr("Verstecken", "Hide"),
                command=self.gui_do_hide,
            ).grid(row=4, column=0, sticky="w", pady=(4, 6))
            # Extraktion
            extract_ops = ttk.Frame(steg_frame)
            extract_ops.pack(fill="x")
            ttk.Label(extract_ops, text=tr("Extrahieren:", "Extract:")).grid(row=0, column=0, sticky="w")
            ttk.Button(
                extract_ops,
                text=tr(".hid-Datei", ".hid file"),
                command=self.gui_select_extract_stego,
            ).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(extract_ops, textvariable=self.extract_stego_path, wraplength=480).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(
                extract_ops,
                text=tr("Ziel-Datei", "Destination file"),
                command=self.gui_select_extract_output,
            ).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(extract_ops, textvariable=self.extract_output_path, wraplength=480).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(
                extract_ops,
                text=tr("Extrahieren", "Extract"),
                command=self.gui_do_extract,
            ).grid(row=3, column=0, sticky="w", pady=(4, 6))

        def lock(self):
            """
            Sperrt den aktuell geöffneten Tresor und kehrt zur Login-Ansicht zurück.

            Vor dem Sperren wird der Tresor immer neu verschlüsselt, um den
            Binärinhalt zu randomisieren. Die Speicherung erfolgt im
            Hintergrund mit einem Fortschrittsdialog, damit der Benutzer einen
            Hinweis auf den laufenden Vorgang erhält. Nach erfolgreichem
            Speichern werden Tresor und Passwort aus dem Speicher entfernt
            und die Login-Ansicht aufgebaut.
            """
            # Wenn kein Tresor geöffnet ist, gehe direkt zur Login-Ansicht zurück
            if not (self.vault and self.master_pw):
                self.vault = None
                self.master_pw = None
                self.build_login_ui()
                return
            # Arbeiterfunktion zum Speichern ohne Backup
            def do_lock_work() -> None:
                save_vault(self.path, self.vault, self.master_pw, make_backup=False)
                # Audit-Eintrag anlegen
                write_audit("auto_resave_on_lock", f"{self.path}")
                return None
            def on_lock_success(_res: None = None):
                # Lösche Tresor aus dem Speicher und kehre zur Login-Ansicht zurück
                self.vault = None
                self.master_pw = None
                self.build_login_ui()
            def on_lock_error(exc: Exception):
                # Zeige Fehlerdialog (übersetzt), entlade dennoch Tresor und kehre zur Login-Ansicht zurück
                messagebox.showerror(
                    tr("Fehler", "Error"),
                    tr("Speichern beim Sperren fehlgeschlagen:", "Saving on lock failed:") + f"\n{exc}",
                    parent=self.root,
                )
                self.vault = None
                self.master_pw = None
                self.build_login_ui()
            # Zeige Fortschrittsdialog und starte Speichern
            self.run_with_progress(
                tr("Tresor schließen", "Close vault"),
                tr(
                    "Tresor wird verschlüsselt und geschlossen. Bitte warten...",
                    "Vault is being encrypted and closed. Please wait...",
                ),
                do_lock_work,
                args=(),
                on_success=on_lock_success,
                on_error=on_lock_error,
            )

        def on_close(self):
            if self.vault and self.master_pw:
                try:
                    save_vault(self.path, self.vault, self.master_pw)
                except Exception:
                    pass
            self.root.destroy()

        def show_help(self):
            """
            Zeige eine Hilfeansicht in einem eigenen Fenster mit ausreichender Breite.

            Diese Methode verwendet ``get_help_text()``, um nur den Hilfetext
            in der gewählten Sprache anzuzeigen. Zusätzlich wird ein kurzer
            GUI‑Hinweis angehängt, der ebenfalls über die Übersetzungsfunktion
            ``tr`` zweisprachig bereitgestellt wird. Statt eines modalen
            MessageBox wird ein separates Top‑Level‑Fenster mit einem Textfeld
            geöffnet, damit lange Zeilen besser lesbar sind und das Fenster
            flexibel skaliert werden kann.
            """
            # Hilfetext aus dem Modul‑Docstring gemäß aktueller Sprache extrahieren
            help_text = get_help_text().strip()
            # GUI‑Spezifische Hinweise, übersetzt je nach Sprache
            gui_hint = tr(
                "GUI-Hilfe: Doppelklick öffnet Eintrag. Exporte sind Klartext — bitte sichern/löschen.",
                "GUI help: Double-click opens an entry. Exports are plaintext — please secure/delete them."
            )
            full_text = help_text + "\n\n" + gui_hint
            # Wenn der Farbschema-Umschalter deaktiviert ist, ergänze die Hilfe um den Versuchs-Hinweis.
            # Die Meldung wird zweisprachig über die Funktion tr bereitgestellt.
            if not SHOW_LIGHT_DARK_TOGGLE:
                extra_hint = tr(
                    "\n\nVersuchsweise:\n***Designumschalter ist deaktiviert - ändere das Farbschema über die Konfiguration. Funktion in Arbeit – ändere SHOW_LIGHT_DARK_TOGGLE zum Testen***",
                    "\n\nExperimental:\n***The light/dark switch is disabled - change the colour scheme via the configuration file. Feature in progress – change SHOW_LIGHT_DARK_TOGGLE for testing***",
                )
                full_text += extra_hint
            top = tk.Toplevel(self.root)
            # Übersetze den Fenstertitel entsprechend der aktuellen Sprache
            top.title(tr("Hilfe", "Help"))
            # Setze ein Startmaß; Fenster ist frei skalierbar
            top.geometry("1000x800")
            # Text-Widget mit automatischem Zeilenumbruch
            txt = tk.Text(top, wrap="word")
            txt.insert("1.0", full_text)
            txt.config(state="disabled")
            txt.pack(fill="both", expand=True, padx=8, pady=8, side="left")
            # Vertikale Scrollbar
            scroll = ttk.Scrollbar(top, orient="vertical", command=txt.yview)
            scroll.pack(side="right", fill="y")
            txt.configure(yscrollcommand=scroll.set)
            # Schließen‑Button unten rechts mit Übersetzung
            btnf = ttk.Frame(top)
            btnf.pack(fill="x", pady=4)
            ttk.Button(btnf, text=tr("Schließen", "Close"), command=top.destroy).pack(side="right", padx=10)

        def _autolock_check(self):
            """Überwacht Inaktivität und aktualisiert den Countdown.

            Diese Methode wird regelmäßig (alle 1 s) aufgerufen. Ist ein Tresor
            geöffnet, wird die verbleibende Zeit bis zur automatischen Sperre
            berechnet und in der Statusleiste angezeigt. Bei Ablauf wird der
            Tresor gesperrt. Ist kein Tresor geöffnet, wird "Tresor
            geschlossen" angezeigt. Die Uhr läuft nur, wenn self.vault
            nicht None ist.
            """
            try:
                now = time.time()
                if self.vault is not None:
                    elapsed = now - getattr(self, "last_activity", now)
                    timeout = AUTOLOCK_MINUTES * 60
                    remaining = int(max(0, timeout - elapsed))
                    # Format in mm:ss
                    mins = remaining // 60
                    secs = remaining % 60
                    if remaining > 0:
                        # Aktualisiere Status
                        status_text = tr(
                            "Geöffnet – Auto-Lock in: ",
                            "Open – auto-lock in: ",
                        ) + f"{mins:02d}:{secs:02d}"
                        try:
                            self.status.config(text=status_text)
                        except Exception:
                            pass
                    else:
                        # Zeit abgelaufen: Tresor sperren
                        # Zuerst Tresor schließen, dann Hinweis anzeigen, damit keine Eintragsliste mehr sichtbar ist
                        try:
                            self.lock()
                            # Zeige Hinweis nach dem Sperren
                            messagebox.showinfo(
                                tr("Auto-Lock", "Auto-lock"),
                                tr(
                                    "Tresor wurde automatisch gesperrt (Inaktiv).",
                                    "Vault has been automatically locked (inactive).",
                                ),
                            )
                        except Exception:
                            # Auch bei Fehlern sicherstellen, dass der Tresor gesperrt ist
                            try:
                                self.lock()
                            except Exception:
                                pass
                        # Anzeige aktualisiert sich im lock() Aufruf
                else:
                    # Kein Tresor geöffnet
                    try:
                        self.status.config(text=tr("Tresor geschlossen", "Vault closed"))
                    except Exception:
                        pass
            except Exception:
                # Im Fehlerfall keine Aktion; Status bleibt unverändert
                pass
            # Wiederaufruf in 1 s
            try:
                self.root.after(1000, self._autolock_check)
            except Exception:
                pass

    root = tk.Tk()
    app = App(root, path)
    root.mainloop()

# ====================================
# SECTION L — Hilfe / CLI-Parsing / Main
# ====================================
HELP_TEXT = textwrap.dedent(f"""
pwmanager.py (Version {PROGRAM_VERSION}) — Gebrauchsanweisung

Start GUI (empfohlen):
    python pwmanager.py

CLI:
    python pwmanager.py --cli
Optionen:
  --file PATH       Tresor-Datei (default: {DEFAULT_VAULT_NAME})
  --cli             Starte im CLI-Modus
  --no-gui          Erzwinge CLI (auch wenn Tk verfügbar)
  --safe-cli        CLI im \"sicheren Modus\" (Exports deaktiviert)
  --config PATH     JSON-Datei mit Konfigurationsparametern
  --help            Diese Hilfe anzeigen

Sicherheit:
- Triple‑Layer Encryption (AES‑GCM → XOR‑Pad → ChaCha20‑Poly1305) **plus optional beliebig viele zusätzliche XOR/HMAC‑Schichten**.
  Die Anzahl der zusätzlichen Schichten wird über ``EXTRA_ENCRYPTION_LAYERS`` konfiguriert (0 = nur Triple‑Layer, 1 = eine Schicht, 2 = zwei Schichten, …).  Mehr Schichten erhöhen die Datei‑
  größe und die Rechenzeit.
- KDF: scrypt (N={KDF_N}, r={KDF_R}, p={KDF_P}) oder optional Argon2 (time={ARGON2_TIME}, memory={ARGON2_MEMORY} KiB, parallelism={ARGON2_PARALLELISM})
- HMAC‑SHA512 Integritätsschutz
    - Audit‑Logging (aktivierbar per Konfiguration)
    - Bei jedem Speichern Re‑Randomizing (neue Salt/Nonces/Pads)

Konfiguration:
    - Beim Start wird automatisch nach einer Datei namens '{DEFAULT_CONFIG_FILENAME}'
      im Verzeichnis der EXE/Skripts gesucht. Wenn diese Datei existiert,
      werden die darin gespeicherten Parameter geladen und angewendet, ohne dass
      ``--config`` angegeben werden muss.
    - Über die CLI-Menüoption [C] und die Schaltflächen "Konfig laden" bzw. "Konfig
      erstellen" in der GUI kann eine Konfigurationsdatei mit den aktuellen
      Standardwerten erstellt werden. So können Parameter angepasst werden,
      ohne den Quellcode zu verändern.
    - Die erzeugte Konfigurationsdatei enthält ausführliche Kommentarzeilen,
      die die Bedeutung jedes Parameters erklären. Diese Zeilen beginnen mit
      ``#`` und werden beim Einlesen automatisch ignoriert. Bearbeite die
      Werte nach dem Doppelpunkt, um Parameter wie Auto-Lock oder KDF zu
      ändern.

Tresor-Datei:
    - Beim Start wird standardmäßig die Tresor-Datei '{DEFAULT_VAULT_NAME}' verwendet, sofern sie vorhanden ist.
    - In der GUI können Sie über den Button "Tresor-Datei wählen" eine andere Datei im
      .pwm‑Format auswählen. Dieser Button eignet sich, wenn Sie mit mehreren Tresor-
      Dateien arbeiten oder einen bestehenden Tresor an einem anderen Ort gespeichert
      haben.
    - Existiert die ausgewählte Tresor-Datei noch nicht, wird beim ersten Speichern
      automatisch ein neuer Tresor mit dieser Datei angelegt. Sie müssen also keinen
      leeren Tresor manuell erstellen.
    - In der CLI können Sie die Tresor-Datei über ``--file`` angeben. Wird die Datei
      nicht gefunden, wird sie automatisch angelegt.

Datei‑Verschlüsselung und Verstecken:
    - Neben der Tresor‑Verwaltung ermöglicht pwmanager auch das Verschlüsseln
      beliebiger Dateien und das Verstecken von Dateien in anderen Dateien.
    - Im CLI stehen dafür die Menüpunkte ``[10]`` bis ``[13]`` zur Verfügung:
        * ``[10]`` Datei verschlüsseln – liest eine Datei ein, verschlüsselt den
          Inhalt mit einem Passwort und schreibt eine ``.enc``‑Datei.
        * ``[11]`` Datei entschlüsseln – rekonstruiert aus einer ``.enc``‑Datei
          wieder die Originaldatei.
        * ``[12]`` Datei verstecken – verschlüsselt eine Datei und hängt sie
          unsichtbar an das Ende einer Cover‑Datei an. Die so erzeugte ``.hid``‑Datei
          kann wie gewohnt genutzt werden, enthält aber zusätzlich den verborgenen
          Inhalt.
        * ``[13]`` Verstecktes extrahieren – sucht die Markierung am Ende einer
          ``.hid``‑Datei, extrahiert und entschlüsselt die Nutzlast und stellt die
          ursprüngliche Datei wieder her. Das ursprüngliche Dateiformat wird aus
          der versteckten Nutzlast wiederhergestellt und als Vorschlag für den
          Dateinamen verwendet.
      Diese vier Optionen (10–13) stehen im CLI sowohl im Außenmenü vor dem Laden
      eines Tresors als auch im Hauptmenü zur Verfügung. Sie können Dateivorgänge
      also unabhängig vom Tresor nutzen. Die CLI fragt erst im Moment des
      Verschlüsselns/Entschlüsselns nach dem Passwort.
    - In der GUI gibt es entsprechende Schaltflächen: „Datei verschlüsseln“,
      „Datei entschlüsseln“, „Datei verstecken“ und „Verstecktes extrahieren“.
    - Alle Dateivorgänge verwenden denselben Triple‑Layer‑Algorithmus wie der
      Tresor (AES‑GCM → HMAC‑Pad → ChaCha20‑Poly1305) und sind somit genauso
      sicher.
""")

def main(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--file", "-f", default=DEFAULT_VAULT_NAME)
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--no-gui", action="store_true")
    ap.add_argument("--safe-cli", action="store_true", help="Deaktiviert Export-Funktionen im CLI")
    ap.add_argument("--help", action="store_true")
    ap.add_argument("--config", default=None, help="Pfad zu einer optionalen Konfigurationsdatei (JSON)")
    args = ap.parse_args(argv)

    if args.help:
        print(HELP_TEXT); return

    # Externe Konfiguration laden und anwenden, sofern angegeben
    if args.config:
        cfg_path = Path(args.config)
        existed = cfg_path.exists()
        cfg = load_config_file(cfg_path)
        apply_config(cfg)
        # Merke den Pfad der aktiv geladenen Konfiguration
        globals()["ACTIVE_CONFIG_PATH"] = cfg_path
        if not existed:
            print(f"Konfigurationsdatei '{cfg_path}' wurde neu erstellt mit Standardwerten.")
            print("Bearbeite diese JSON-Datei, um Parameter wie KDF und Auto-Lock anzupassen.")
    else:
        # Wenn kein expliziter Config-Pfad angegeben ist, versuche automatisch eine
        # Standard-Konfigurationsdatei zu laden. Dies ermöglicht die Nutzung einer
        # persistierten Konfiguration ohne Angabe von --config.
        default_cfg_path = exe_dir() / DEFAULT_CONFIG_FILENAME
        if default_cfg_path.exists():
            cfg = load_config_file(default_cfg_path)
            apply_config(cfg)
            globals()["ACTIVE_CONFIG_PATH"] = default_cfg_path

    # Sprache initialisieren, nachdem die Konfiguration angewendet wurde.
    # Dies ermöglicht es, FORCE_LANG aus der Konfig-Datei zu berücksichtigen.
    try:
        init_language()
    except Exception:
        # Fallback: Default-Sprache wird in detect_system_language bestimmt
        pass

    path = Path(args.file)

    tk_available = import_tk()[0] is not None

    if args.cli or args.no_gui or not tk_available:
        # Starte äußere CLI-Menüschleife, die zunächst ohne Tresor auskommt.
        cli_outer_loop(path, safe_mode=args.safe_cli)
    else:
        launch_gui(path)

if __name__ == "__main__":
    main(sys.argv[1:])



# ===========================
# HARDENING RUNTIME WRAPPERS
# ===========================
# 1) Enforce Safe-Mode in GUI actions by wrapping methods at runtime
try:
    def _wlk_guard_wrapper(fn):
        def _wrapped(self, *args, **kwargs):
            try:
                hm = bool(HARDENED_SAFE_MODE)
            except Exception:
                hm = False
            if hm:
                try:
                    from tkinter import messagebox
                    messagebox.showwarning("Sicherer Modus", "Diese Funktion ist im sicheren Modus deaktiviert.")
                except Exception:
                    pass
                return None
            return fn(self, *args, **kwargs)
        return _wrapped

    # Try to import the app class symbol
    # Fallback: probe common class names used in this script
    _WLK_APP_CLS = None
    for _name in ("PWManagerApp", "App", "PasswordManagerApp"):
        try:
            _WLK_APP_CLS = globals().get(_name)
            if _WLK_APP_CLS:
                break
        except Exception:
            pass
    if _WLK_APP_CLS:
        for _meth in ("gui_export_entry", "gui_export_all", "gui_export_csv",
                      "gui_hide_file", "gui_extract_hidden_file", "gui_open_file_ops_dialog"):
            if hasattr(_WLK_APP_CLS, _meth):
                setattr(_WLK_APP_CLS, _meth, _wlk_guard_wrapper(getattr(_WLK_APP_CLS, _meth)))
except Exception:
    pass

# 2) HTTPS validation for Telegram link opening by wrapping webbrowser.open
try:
    import webbrowser as _wb
    import urllib.parse as _urlp
    _orig_open = _wb.open

    def _wlk_safe_open(url, *args, **kwargs):
        try:
            u = str(url).strip()
            parsed = _urlp.urlparse(u if u else "")
            if not parsed.scheme:
                u = "https://" + u
                parsed = _urlp.urlparse(u)
            # enforce https for Telegram links (t.me / telegram.me)
            host = (parsed.netloc or "").lower()
            if "t.me" in host or "telegram.me" in host or "telegram.org" in host:
                if parsed.scheme != "https":
                    return False
            return _orig_open(u, *args, **kwargs)
        except Exception:
            return False

    _wb.open = _wlk_safe_open
except Exception:
    pass


# ================================
# CONFIG-DRIVEN HARDENING OPTIONS (CONFIGURED BLOCK)
# ================================
import pathlib, json, sys

# Defaults (can be overridden by JSON config placed next to the script/exe)
HARDENED_SAFE_MODE = globals().get("HARDENED_SAFE_MODE", False)
SAFE_BLOCK_EXPORT = globals().get("SAFE_BLOCK_EXPORT", False)        # block TXT/CSV export
SAFE_BLOCK_CSV = globals().get("SAFE_BLOCK_CSV", False)              # block CSV (separately)
SAFE_BLOCK_STEGO = globals().get("SAFE_BLOCK_STEGO", False)          # block hide/extract
SAFE_BLOCK_CLIPBOARD = globals().get("SAFE_BLOCK_CLIPBOARD", False)  # block clipboard ops
NO_PLAINTEXT_IN_GUI = globals().get("NO_PLAINTEXT_IN_GUI", False)    # never show passwords in GUI text
AUTO_MASK_REVEAL_MS = int(globals().get("AUTO_MASK_REVEAL_MS", 3000))  # default 3000 ms (3s)   # 0 = off, else auto-hide delay (ms)
AUTO_LOCK_ON_FOCUS_LOSS = globals().get("AUTO_LOCK_ON_FOCUS_LOSS", False)

# Known config file name if available in this script
DEFAULT_CONFIG_FILENAME = globals().get("DEFAULT_CONFIG_FILENAME", "pwmanager_config.json")

def _wlk_exe_dir():
    try:
        if getattr(sys, "frozen", False):
            return pathlib.Path(sys.executable).resolve().parent
        return pathlib.Path(__file__).resolve().parent
    except Exception:
        return pathlib.Path(".").resolve()

def _wlk_load_hardening_from_json():
    cfg_path = _wlk_exe_dir() / DEFAULT_CONFIG_FILENAME
    if not cfg_path.exists():
        return
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return
    g = globals()
    for key in ("HARDENED_SAFE_MODE","SAFE_BLOCK_EXPORT","SAFE_BLOCK_CSV",
                "SAFE_BLOCK_STEGO","SAFE_BLOCK_CLIPBOARD","NO_PLAINTEXT_IN_GUI",
                "AUTO_MASK_REVEAL_MS","AUTO_LOCK_ON_FOCUS_LOSS"):
        if key in data:
            g[key] = data[key]

_wlk_load_hardening_from_json()

def print_hardening_help():
    import textwrap
    txt = """
HARDENING / SICHERHEITS-OPTIONEN (per JSON-Konfig neben der EXE/Skript):
  - HARDENED_SAFE_MODE: true|false
      Sperrt riskante GUI-Funktionen (Export, CSV, Stego, File-Ops) über Wrapper.
  - SAFE_BLOCK_EXPORT: true|false
      Blockiert Klartext-Export (TXT). CSV siehe unten.
  - SAFE_BLOCK_CSV: true|false
      Blockiert CSV-Export separat.
  - SAFE_BLOCK_STEGO: true|false
      Blockiert 'Datei verstecken' und 'Extrahieren' in GUI und CLI.
  - SAFE_BLOCK_CLIPBOARD: true|false
      Unterbindet das Setzen der Zwischenablage (GUI & CLI soweit möglich).
  - NO_PLAINTEXT_IN_GUI: true|false
      Zeigt Passwörter nie im Klartext in Dialogen/Messageboxen an (nur Clipboard).
  - AUTO_MASK_REVEAL_MS: 0|ms
      Wenn >0: Automatisches Verbergen nach Anzeigen-Events (GUI), soweit anwendbar.
  - AUTO_LOCK_ON_FOCUS_LOSS: true|false
      Automatisches Sperren des Tresors, wenn das Fenster den Fokus verliert.

Zur Laufzeit-Validierung von Telegram-Links (t.me/telegram.*) wird https erzwungen.
"""
    print(textwrap.dedent(txt).strip())

# CLI switch
if "--hardening-help" in sys.argv:
    print_hardening_help()
    try:
        sys.exit(0)
    except SystemExit:
        pass

# APPLY FEATURE WRAPPERS / ENFORCERS (cleaned implementations)

# 0) Clipboard blocking (pyperclip + Tkinter clipboard)
try:
    if SAFE_BLOCK_CLIPBOARD:
        try:
            import pyperclip as _pc
            _pc.copy = lambda *_a, **_k: None
        except Exception:
            pass
        try:
            import tkinter as _tk
            _orig_clip_append = _tk.Misc.clipboard_append
            def _blocked_clip_append(self, *a, **k):
                return None
            _tk.Misc.clipboard_append = _blocked_clip_append
        except Exception:
            pass
except Exception:
    pass

# 1) Export/CSV/Stego GUI method wrappers (runtime)
try:
    def _wlk_guard_wrapper_feature(fn, feature_flag):
        def _wrapped(self, *args, **kwargs):
            if globals().get("HARDENED_SAFE_MODE", False) or globals().get(feature_flag, False):
                try:
                    from tkinter import messagebox
                    messagebox.showwarning("Sicherer Modus", "Diese Funktion ist im sicheren Modus deaktiviert.")
                except Exception:
                    pass
                return None
            return fn(self, *args, **kwargs)
        return _wrapped

    _WLK_APP_CLS = None
    for _name in ("PWManagerApp", "App", "PasswordManagerApp"):
        c = globals().get(_name)
        if c:
            _WLK_APP_CLS = c
            break

    if _WLK_APP_CLS:
        mapping = {
            "gui_export_entry": "SAFE_BLOCK_EXPORT",
            "gui_export_all": "SAFE_BLOCK_EXPORT",
            "gui_export_csv": "SAFE_BLOCK_CSV",
            "gui_hide_file": "SAFE_BLOCK_STEGO",
            "gui_extract_hidden_file": "SAFE_BLOCK_STEGO",
            "gui_open_file_ops_dialog": "SAFE_BLOCK_STEGO",
        }
        for m, fflag in mapping.items():
            if hasattr(_WLK_APP_CLS, m):
                setattr(_WLK_APP_CLS, m, _wlk_guard_wrapper_feature(getattr(_WLK_APP_CLS, m), fflag))
except Exception:
    pass

# 2) Redact plaintext in GUI messageboxes (NO_PLAINTEXT_IN_GUI)
try:
    if NO_PLAINTEXT_IN_GUI:
        from tkinter import messagebox as _mb
        _orig_info = getattr(_mb, "showinfo", None)
        _orig_warn = getattr(_mb, "showwarning", None)
        _orig_err = getattr(_mb, "showerror", None)

        def _redact_text(t):
            try:
                s = str(t)
                lines = s.splitlines()
                out = []
                for ln in lines:
                    if "Passwort" in ln or "password" in ln.lower():
                        out.append("Passwort : ••••")
                    else:
                        out.append(ln)
                return "\n".join(out)
            except Exception:
                return t

        if callable(_orig_info):
            def showinfo(title, message, *a, **k): return _orig_info(title, _redact_text(message), *a, **k)
            _mb.showinfo = showinfo
        if callable(_orig_warn):
            def showwarning(title, message, *a, **k): return _orig_warn(title, _redact_text(message), *a, **k)
            _mb.showwarning = showwarning
        if callable(_orig_err):
            def showerror(title, message, *a, **k): return _orig_err(title, _redact_text(message), *a, **k)
            _mb.showerror = showerror
except Exception:
    pass

# 3) Auto-lock on focus loss (if GUI class exposes a lock method)
try:
    if AUTO_LOCK_ON_FOCUS_LOSS and _WLK_APP_CLS:
        _orig_init = getattr(_WLK_APP_CLS, "__init__", None)
        def _init_with_focus_lock(self, *a, **k):
            if _orig_init:
                _orig_init(self, *a, **k)
            try:
                root = getattr(self, "root", None)
                if root is not None:
                    def _on_blur(_e=None):
                        for cand in ("gui_lock", "lock", "_secure_forget_master_pw"):
                            if hasattr(self, cand):
                                try:
                                    getattr(self, cand)()
                                except Exception:
                                    pass
                    root.bind("<FocusOut>", _on_blur)
            except Exception:
                pass
        _WLK_APP_CLS.__init__ = _init_with_focus_lock
except Exception:
    pass

# 4) Extend help: integrate hardening help into existing GUI help routines (if present)
try:
    def _append_hardening_to_help_text(orig_text):
        try:
            extra = ("\n\n— Sicherheit/Hardening —\n"
                     "• Safe-Mode sperrt riskante Funktionen (Export/CSV/Stego).\n"
                     "• Optional: Clipboard blocken, Passwörter nie im Klartext anzeigen.\n"
                     "• Auto-Lock bei Fokusverlust.\n"
                     "• Telegram-Links werden nur über https geöffnet.\n"
                     "• Siehe --hardening-help oder Konfigdatei für Optionen.\n")
            if not orig_text:
                return extra
            return str(orig_text) + extra
        except Exception:
            return orig_text

    if _WLK_APP_CLS:
        for _hm in ("show_help", "gui_show_help", "open_help", "gui_open_help"):
            if hasattr(_WLK_APP_CLS, _hm):
                _orig_help = getattr(_WLK_APP_CLS, _hm)
                def _wrapped_help(self, *a, **k):
                    try:
                        res = _orig_help(self, *a, **k)
                    except Exception:
                        res = None
                    try:
                        # if original help returned text, we can't intercept; try to open appended help window
                        import tkinter as tk
                        win = tk.Toplevel(self.root)
                        win.title("Sicherheit / Hardening")
                        txt = tk.Text(win, wrap="word", height=18, width=90)
                        txt.pack(fill="both", expand=True)
                        txt.insert("1.0", print_hardening_help.__doc__ or "")
                        txt.insert("1.0", "HARDENING-HILFE (Kurzfassung)\n• Safe-Mode sperrt Export/CSV/Stego.\n• Clipboard blockieren, Passwörter nie im Klartext.\n• Auto-Lock bei Fokusverlust.\n• Telegram-Links über https.\n• Mehr: --hardening-help\n")
                        txt.config(state="disabled")
                    except Exception:
                        pass
                    return res
                setattr(_WLK_APP_CLS, _hm, _wrapped_help)
except Exception:
    pass

# 5) Click-to-Reveal / Auto-Mask for entry display windows
try:
    import tkinter as _tk
    _orig_toplevel_init = getattr(_tk.Toplevel, "__init__", None)
    if _orig_toplevel_init is not None:
        def _toplevel_init_wrapper(self, *a, **k):
            _orig_toplevel_init(self, *a, **k)
            try:
                self.after(120, lambda: _post_process_toplevel(self))
            except Exception:
                pass

        def _post_process_toplevel(win):
            try:
                title = ""
                try:
                    title = win.title()
                except Exception:
                    return
                if not isinstance(title, str) or not title.startswith("Anzeigen:"):
                    return
                def walk(w):
                    for child in list(w.winfo_children()):
                        try:
                            txt = None
                            if hasattr(child, "cget"):
                                try:
                                    txt = child.cget("text")
                                except Exception:
                                    txt = None
                            if isinstance(txt, str) and ("Passwort" in txt or "passwort" in txt.lower()):
                                parts = txt.split(":", 1)
                                pw = parts[1].strip() if len(parts) > 1 else ""
                                import tkinter as tk
                                parent = child.master or w
                                frm = tk.Frame(parent)
                                masked = tk.StringVar(value="•" * max(6, len(pw)))
                                lbl = tk.Label(frm, textvariable=masked)
                                lbl.pack(side="left", padx=(0,8))
                                def reveal():
                                    try:
                                        masked.set(pw)
                                        if AUTO_MASK_REVEAL_MS and int(AUTO_MASK_REVEAL_MS) > 0:
                                            win.after(int(AUTO_MASK_REVEAL_MS), lambda: masked.set("•" * max(6, len(pw))))
                                    except Exception:
                                        pass
                                btn = tk.Button(frm, text="Anzeigen", command=reveal)
                                btn.pack(side="left")
                                try:
                                    child.destroy()
                                except Exception:
                                    pass
                                frm.pack(fill="x", padx=4, pady=2)
                            else:
                                walk(child)
                        except Exception:
                            pass
                walk(win)
            except Exception:
                pass

        _tk.Toplevel.__init__ = _toplevel_init_wrapper
except Exception:
    pass




# ====================================
def ensure_pillow():
    try:
        import PIL  # noqa: F401
        return True
    except Exception:
        return False

def generate_noise_bmp(dest_path: Path, min_size_bytes: int = 1 * 1024 * 1024) -> Path:
    """
    Erzeugt ein unkomprimiertes 24-Bit-BMP mit Zufallspixeln (BGR),
    das mindestens 'min_size_bytes' groß ist.
    """
    import math, secrets
    dest_path = Path(dest_path)
    header_size = 54  # 14 + 40
    min_pixels = max(1, math.ceil((min_size_bytes - header_size) / 3))
    side = max(64, math.ceil(math.sqrt(min_pixels)))

    def compute_sizes(side_len):
        row_raw = side_len * 3
        pad = (4 - (row_raw % 4)) % 4
        row = row_raw + pad
        pixel_bytes = row * side_len
        return row_raw, pad, pixel_bytes, header_size + pixel_bytes

    row_raw, row_pad, pixel_bytes, file_size = compute_sizes(side)
    while file_size < min_size_bytes:
        side += 8
        row_raw, row_pad, pixel_bytes, file_size = compute_sizes(side)

    # Header
    bfType = b'BM'
    bfSize = file_size.to_bytes(4, 'little')
    bfReserved = (0).to_bytes(4, 'little')
    bfOffBits = (54).to_bytes(4, 'little')

    biSize = (40).to_bytes(4, 'little')
    biWidth = side.to_bytes(4, 'little', signed=True)
    biHeight = side.to_bytes(4, 'little', signed=True)  # bottom-up
    biPlanes = (1).to_bytes(2, 'little')
    biBitCount = (24).to_bytes(2, 'little')
    biCompression = (0).to_bytes(4, 'little')
    biSizeImage = pixel_bytes.to_bytes(4, 'little')
    biXPelsPerMeter = (2835).to_bytes(4, 'little')
    biYPelsPerMeter = (2835).to_bytes(4, 'little')
    biClrUsed = (0).to_bytes(4, 'little')
    biClrImportant = (0).to_bytes(4, 'little')

    header = (
        bfType + bfSize + bfReserved + bfOffBits +
        biSize + biWidth + biHeight + biPlanes + biBitCount + biCompression +
        biSizeImage + biXPelsPerMeter + biYPelsPerMeter + biClrUsed + biClrImportant
    )

    rnd = secrets.SystemRandom()
    pad_bytes = b'\x00' * row_pad
    pixels = bytearray()
    for _ in range(side):
        row = bytearray(rnd.getrandbits(8) for _ in range(row_raw))
        pixels.extend(row)
        if row_pad:
            pixels.extend(pad_bytes)

    atomic_write(Path(dest_path), header + bytes(pixels))
    return Path(dest_path)

def _calc_canvas_for_min_size(format_upper: str, min_size_bytes: int, base_w: int, base_h: int):
    """
    Grobe Abschätzung der benötigten Seitenlänge, um mit random noise die Zieldateigröße zu erreichen.
    Für PNG/JPEG nehmen wir an, dass Rauschen quasi unkomprimierbar ist.
    """
    import math
    bytes_per_pixel = 3  # RGB
    # Heuristik: Rohdaten ~ w*h*3; Container-Overhead additiv vernachlässigbar
    target_pixels = max(1, math.ceil(min_size_bytes / bytes_per_pixel))
    side = max(max(base_w, base_h), int(math.ceil(math.sqrt(target_pixels))))
    return side, side

def generate_noise_image(dest_path: Path, min_size_bytes: int = 1 * 1024 * 1024, fmt: Optional[str] = None) -> Path:
    """
    Erzeugt eine Zufallsbild-Datei in BMP/PNG/JPEG, die mindestens min_size_bytes groß ist.
    Der Dateityp wird über 'fmt' oder anhand der Dateiendung bestimmt.
    """
    if not ensure_pillow():
        raise RuntimeError("Pillow (PIL) nicht installiert. Bitte 'pip install Pillow' ausführen.")
    from PIL import Image
    import secrets, os

    dest_path = Path(dest_path)
    fmt_upper = (fmt or dest_path.suffix.lstrip(".")).upper()
    if fmt_upper == "JPG":
        fmt_upper = "JPEG"
    if fmt_upper not in ("BMP", "PNG", "JPEG"):
        raise ValueError(f"Nicht unterstütztes Zielformat: {fmt_upper}")

    # Starte mit 512x512, wachse bis Größe passt
    W = H = 512
    while True:
        raw = secrets.token_bytes(W * H * 3)
        img = Image.frombytes("RGB", (W, H), raw)
        if fmt_upper == "BMP":
            img.save(dest_path, format="BMP")
        elif fmt_upper == "PNG":
            # compress_level=0 -> größer
            img.save(dest_path, format="PNG", compress_level=0)
        else:  # JPEG
            img.save(dest_path, format="JPEG", quality=100, subsampling=0, optimize=False, progressive=False)
        sz = os.path.getsize(dest_path)
        if sz >= min_size_bytes:
            break
        # Vergrößern
        W = int(W * 1.3)
        H = int(H * 1.3)
        # Sicherheitsgrenze
        if W > 20000 or H > 20000:
            break
    return dest_path

def enlarge_image_to_min_size(src_path: Path, dest_path: Path, min_size_bytes: int = 1 * 1024 * 1024,
                              bg_strategy: str = "noise") -> Path:
    """
    Legt ein beliebiges Bild (JPG/JPEG/PNG) zentriert auf eine größere, zufällige Hintergrundfläche
    und speichert in dasselbe Format wie 'dest_path' (Dateiendung maßgeblich).
    Ziel: Dateigröße >= min_size_bytes.
    """
    if not ensure_pillow():
        raise RuntimeError("Pillow (PIL) nicht installiert. Bitte 'pip install Pillow' ausführen.")
    from PIL import Image
    import os, math, secrets

    src_path = Path(src_path)
    dest_path = Path(dest_path)
    if not src_path.exists():
        raise FileNotFoundError(f"Quelle nicht gefunden: {src_path}")

    out_fmt = dest_path.suffix.lstrip(".").upper() or "JPEG"
    if out_fmt == "JPG":
        out_fmt = "JPEG"
    if out_fmt not in ("PNG", "JPEG", "BMP"):
        raise ValueError(f"Nicht unterstütztes Ausgabeformat: {out_fmt}")

    with Image.open(src_path) as im0:
        im = im0.convert("RGB")
        w, h = im.size

    def make_bg(W, H):
        if bg_strategy == "solid":
            color = (secrets.randbelow(256), secrets.randbelow(256), secrets.randbelow(256))
            return Image.new("RGB", (W, H), color)
        else:
            raw = secrets.token_bytes(W * H * 3)
            return Image.frombytes("RGB", (W, H), raw)

    scale = 1.6
    while True:
        W = max(w, int(math.ceil(w * scale)))
        H = max(h, int(math.ceil(h * scale)))
        bg = make_bg(W, H)
        x = (W - w) // 2
        y = (H - h) // 2
        bg.paste(im, (x, y))
        if out_fmt == "PNG":
            bg.save(dest_path, format="PNG", compress_level=0)
        elif out_fmt == "BMP":
            bg.save(dest_path, format="BMP")
        else:
            bg.save(dest_path, format="JPEG", quality=100, subsampling=0, optimize=False, progressive=False)
        if os.path.getsize(dest_path) >= min_size_bytes:
            break
        scale *= 1.35
        if max(W, H) > 20000:
            break
    return dest_path

# ---- GUI-Helfer (optional einsetzbar von bestehenden GUIs) ----
def gui_create_cover_image_generic():
    """
    Zeigt einen Dialog zum Erzeugen eines zufälligen Cover-Bildes (BMP/PNG/JPEG).
    Texte und Dateitypen werden übersetzt über die ``tr``-Funktion.
    """
    try:
        from tkinter import filedialog, simpledialog, messagebox
    except Exception:
        return
    # Zielformat anhand Endung
    path = filedialog.asksaveasfilename(
        title=tr("Cover-Bild erzeugen (BMP/PNG/JPEG)", "Create cover image (BMP/PNG/JPEG)"),
        defaultextension=".bmp",
        filetypes=[
            (tr("Bitmap", "Bitmap"), "*.bmp"),
            (tr("PNG", "PNG"), "*.png"),
            (tr("JPEG", "JPEG"), "*.jpg;*.jpeg"),
            (tr("Alle Dateien", "All files"), "*.*"),
        ],
    )
    if not path:
        return
    size_mib = 1.0
    try:
        size_mib = simpledialog.askfloat(
            tr("Zielgröße", "Target size"),
            tr("Mindestgröße in MiB (Standard: 1.0):", "Minimum size in MiB (default: 1.0):"),
            minvalue=0.1,
            initialvalue=1.0,
        )
        if size_mib is None:
            return
    except Exception:
        pass
    try:
        out = generate_noise_image(Path(path), int(size_mib * 1024 * 1024))
        import os
        messagebox.showinfo(
            tr("Fertig", "Done"),
            tr("Cover-Bild erzeugt:\n{out}\n\nGröße: {size:.2f} MiB", "Cover image created:\n{out}\n\nSize: {size:.2f} MiB").format(
                out=out, size=os.path.getsize(out) / 1024 / 1024
            ),
        )
    except Exception as e:
        messagebox.showerror(tr("Fehler", "Error"), f"{e}")

def gui_inflate_image_generic():
    """
    Zeigt einen Dialog zum Aufblasen eines kleinen Bildes auf eine Mindestgröße.
    Der Benutzer wählt Eingabe- und Ausgabedatei aus; Texte werden übersetzt.
    """
    try:
        from tkinter import filedialog, simpledialog, messagebox
    except Exception:
        return
    src = filedialog.askopenfilename(
        title=tr("Kleines Bild auswählen (JPEG/PNG)", "Select small image (JPEG/PNG)"),
        filetypes=[
            (tr("Bilder", "Images"), "*.jpg;*.jpeg;*.png;*.bmp"),
            (tr("Alle Dateien", "All files"), "*.*"),
        ],
    )
    if not src:
        return
    dst = filedialog.asksaveasfilename(
        title=tr("Ausgabe speichern (Format per Endung)", "Save output (format by extension)"),
        defaultextension=".jpg",
        filetypes=[
            (tr("JPEG", "JPEG"), "*.jpg;*.jpeg"),
            (tr("PNG", "PNG"), "*.png"),
            (tr("BMP", "BMP"), "*.bmp"),
            (tr("Alle Dateien", "All files"), "*.*"),
        ],
    )
    if not dst:
        return
    size_mib = simpledialog.askfloat(
        tr("Zielgröße", "Target size"),
        tr("Mindestgröße in MiB (Standard: 1.0):", "Minimum size in MiB (default: 1.0):"),
        minvalue=0.1,
        initialvalue=1.0,
    )
    if size_mib is None:
        return
    try:
        out = enlarge_image_to_min_size(Path(src), Path(dst), int(size_mib * 1024 * 1024))
        import os
        messagebox.showinfo(
            tr("Fertig", "Done"),
            tr("Bild erzeugt:\n{out}\n\nGröße: {size:.2f} MiB", "Image created:\n{out}\n\nSize: {size:.2f} MiB").format(
                out=out, size=os.path.getsize(out) / 1024 / 1024
            ),
        )
    except Exception as e:
        messagebox.showerror(tr("Fehler", "Error"), f"{e}")

# ---- EARLY-CLI: Vor dem normalen Programmfluss eigene Aktionen abfangen ----
def _early_cli_cover_tools(argv=None):
    """
    Prüft auf frühe CLI-Schalter, damit wir den bestehenden Parser/Flow nicht anfassen müssen.
    Nutze z.B.:
      --make-cover OUT.(bmp|png|jpg) [--size-mib 1.0]
      --inflate-image SRC.(jpg|png) OUT.(jpg|png|bmp) [--size-mib 1.0]
    """
    import sys
    args = argv or sys.argv[1:]
    if not args:
        return False  # nichts getan

    def get_opt(name, default=None):
        if name in args:
            i = args.index(name)
            try:
                return args[i+1]
            except Exception:
                return default
        return default

    if "--make-cover" in args:
        out = get_opt("--make-cover")
        if not out:
            print("Fehler: --make-cover benötigt einen Ausgabepfad.")
            sys.exit(2)
        size_mib = float(get_opt("--size-mib", "1.0"))
        outp = Path(out)
        try:
            generate_noise_image(outp, int(max(0.1, size_mib) * 1024 * 1024))
            print(f"[OK] Cover erzeugt: {outp} ({os.path.getsize(outp)} Bytes)")
        except Exception as e:
            print(f"[Fehler] {e}")
            sys.exit(1)
        sys.exit(0)

    if "--inflate-image" in args:
        src = get_opt("--inflate-image")
        dst = None
        # allow two-arg form: --inflate-image SRC DST
        try:
            i = args.index("--inflate-image")
            dst = args[i+2]
            if dst.startswith("--"):
                dst = None
        except Exception:
            pass
        if not src or not dst:
            print("Fehler: --inflate-image benötigt zwei Argumente: SRC DST")
            sys.exit(2)
        size_mib = float(get_opt("--size-mib", "1.0"))
        try:
            enlarge_image_to_min_size(Path(src), Path(dst), int(max(0.1, size_mib) * 1024 * 1024))
            print(f"[OK] Bild erzeugt: {dst} ({os.path.getsize(dst)} Bytes)")
        except Exception as e:
            print(f"[Fehler] {e}")
            sys.exit(1)
        sys.exit(0)

    return False

# Am Modulimport direkt prüfen (nur wenn als Skript ausgeführt, nicht beim Import als Modul)
try:
    if __name__ == "__main__":
        _early_cli_cover_tools()
except Exception:
    pass
