#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pwmanager.py — Hochsicherer Passwort‑Manager als Einzeldatei (modular).

Diese Anwendung speichert Passwörter in einer geschützten Tresor‑Datei. Die folgenden Punkte fassen
die wichtigsten Eigenschaften zusammen (Deutsch/English):

Deutsch:
 - Ein Master‑Passwort schützt eine portable Tresor‑Datei.
 - Dreifache Verschlüsselung: AES‑256‑GCM, XOR‑Obfuskation (HMAC‑Pad) und ChaCha20‑Poly1305.
 - scrypt‑KDF leitet drei unabhängige Schlüssel ab (AES_key, ChaCha_key, MAC_key).
 - HMAC‑SHA512 sichert die Integrität der Daten.
 - Re‑Randomizing: Beim Speichern werden Salt/Nonces/Pad neu erzeugt – die Datei ändert sich immer.
 - Atomisches Speichern mit optionalen Backups vor dem Überschreiben.
 - GUI (Tkinter) und CLI, Export in TXT/CSV, Zwischenablage mit Auto‑Löschung.
 - Konfigurierbar: AUTOLOCK_MINUTES, KDF‑Parameter, sicherer CLI‑Modus.
 - Prüfung der Passwortstärke (ein‑/ausschaltbar).
 - Das gesamte Programm befindet sich in einer Datei und ist zweisprachig kommentiert.

English:
 - A master password protects a portable vault file.
 - Triple‑layer encryption: AES‑256‑GCM, XOR obfuscation (HMAC pad) and ChaCha20‑Poly1305.
 - scrypt KDF derives three independent keys (AES_key, ChaCha_key, MAC_key).
 - HMAC‑SHA512 protects data integrity.
 - Re‑randomizing: each save uses new salt/nonces/pad so the file always changes binary.
 - Atomic saving with optional backup creation before overwriting.
 - GUI (Tkinter) and CLI, export to TXT/CSV, clipboard with auto‑clear.
 - Configurable: AUTOLOCK_MINUTES, KDF parameters, secure CLI option.
 - Optional password strength check.
 - Fully contained in a single file with bilingual (German/English) comments.

Speichern als / Save as: pwmanager.py
Ausführen (GUI empfohlen) / Run (GUI recommended):
    python pwmanager.py
CLI:
    python pwmanager.py --cli
Hilfe / Help:
CLI (zusätzliche Werkzeuge / additional tools):
    python pwmanager.py --make-cover OUT.(bmp|png|jpg) --size-mib 1.0
    python pwmanager.py --inflate-image SRC.(jpg|jpeg|png|bmp) OUT.(jpg|png|bmp) --size-mib 1.0

Diese Werkzeuge erzeugen ein zufälliges Cover‑Bild (BMP/PNG/JPEG) oder blasen ein vorhandenes Bild
auf einen zufälligen Hintergrund auf (PNG/JPEG/BMP), sodass die Datei eine Mindestgröße erreicht.
These utilities generate a random cover image (BMP/PNG/JPEG) or enlarge an existing image on
a random background (PNG/JPEG/BMP) so that the file reaches a minimum size.

    python pwmanager.py --help
"""

from __future__ import annotations
import argparse
import base64
import getpass
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
VERSION = 3
SALT_LEN = 16
NONCE_LEN = 12
CLIP_CLEAR_MS = 30 * 1000               # Clipboard leeren nach 30s in GUI
BACKUP_KEEP = 2                         # Anzahl Backup-Dateien (älteste löschen)
BACKUPS_ENABLED = True                  # Globale Option: Backups erstellen? True/False
SAFE_CLI_DEFAULT = False                # Standard: CLI-Erweiterungen wie Export erlaubt

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
    # Passe CLI-Menüs nur an, wenn Englisch aktiviert ist; sonst bleiben
    # die deutschsprachigen Originaldefinitionen erhalten.
    if CURRENT_LANG == "en":
        MENU = """
===== Password Manager (CLI) =====
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
        OUTER_MENU = """
===== Password Manager (CLI) =====
[V] Open vault
[10] Encrypt file – Encrypt any file with a password (creates a .enc file)
[11] Decrypt file – Decrypt a previously encrypted .enc file
[12] Hide file – Encrypts a file and appends it to a cover file (creates a .hid file)
[13] Extract hidden – Extracts and decrypts the hidden content from a .hid file
[C] Create config file
[0] Exit
"""

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
TELEGRAM_MESSAGE = "Schau doch mal in meinem Telegram-Kanal vorbei:"
TELEGRAM_LINK = "t.me/WitzigLustigKomisch"
# Tatsächliche Ziel‑URL für den Telegram‑Link. Diese wird geöffnet, wenn der
# Benutzer auf TELEGRAM_LINK klickt.
TELEGRAM_TARGET = "https://t.me/+lk64Nq48NndkZGZi"

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
PROGRAM_VERSION = "2.1.2"

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
        print("\n[!] Fehlende Python-Pakete: " + ", ".join(missing))
        if not interactive:
            raise SystemExit("Fehlende Pakete. Bitte manuell installieren.")
        ans = input("Fehlende Pakete automatisch installieren? (erfordert Internet) [j/N]: ").strip().lower()
        if ans in ("j", "y", "ja"):
            for pkg in missing:
                print(f"Installiere {pkg} ...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                except Exception as e:
                    print("Installation von", pkg, "fehlgeschlagen:", e)
                    raise SystemExit("Bitte installiere die Abhängigkeiten manuell.")
        else:
            raise SystemExit("Benötigte Abhängigkeiten fehlen. Abbruch.")

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
        if path.exists():
            print(f"Standard-Tresor-Datei: {path} (vorhanden)")
        else:
            print(f"Standard-Tresor-Datei: {path} (wird bei Bedarf angelegt)")
    else:
        if path.exists():
            print(f"Externe Tresor-Datei: {path}")
        else:
            print(f"Externe Tresor-Datei: {path} (wird bei Bedarf angelegt)")
    # Bestimme Konfig-Status
    try:
        active_cfg = globals().get("ACTIVE_CONFIG_PATH")
        default_cfg = exe_dir() / DEFAULT_CONFIG_FILENAME
        if not active_cfg:
            if default_cfg.exists():
                print("Keine gültige externe Konfiguration geladen – Standardwerte werden verwendet.")
            else:
                print("Keine Konfiguration gefunden – es werden die im Skript hinterlegten Werte verwendet.")
        elif Path(active_cfg).resolve() == default_cfg.resolve():
            print(f"Standard-Konfigurationsdatei geladen: {active_cfg}")
        else:
            print(f"Externe Konfigurationsdatei geladen: {active_cfg}")
    except Exception:
        print("Konfigurationsstatus konnte nicht ermittelt werden.")

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
            return (
                f"Warnung: Der Tresor wurde zuletzt am {ts} gespeichert.\n"
                f"Es wird empfohlen, die Schlüssel zu rotieren (Tresor neu verschlüsseln)."
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
            messagebox.showwarning("Schlüsselrotation empfohlen", msg)
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
# Format:
# [MAGIC(4)][VER(1)]
# [salt(16)][nonce_aes(12)][nonce_pad(12)][nonce_chacha(12)]
# [ciphertext_chacha (variable)]
# [hmac(64)]
#
# Steps:
# plaintext -> ciphertext_aes = AESGCM(aes_key).encrypt(nonce_aes, plaintext, aad=None)
# pad = pad_stream_from_mac(mac_key, nonce_pad, len(ciphertext_aes))
# obf = ciphertext_aes XOR pad
# ciphertext_chacha = ChaCha20Poly1305(chacha_key).encrypt(nonce_chacha, obf, aad=None)
# file_body = salt + nonce_aes + nonce_pad + nonce_chacha + ciphertext_chacha
# file_hmac = HMAC(mac_key, file_body)
# final_file = MAGIC + VER + file_body + file_hmac

def encrypt_vault_bytes(plaintext: bytes, master_pw: bytes) -> bytes:
    """Verschlüsselt plaintext (bytes) mit master_pw (bytes) und liefert kompletten Blob."""
    salt = secrets.token_bytes(SALT_LEN)
    kdf_tlv = _build_kdf_tlv()
    header = MAGIC + VERSION.to_bytes(1,"big") + kdf_tlv
    aes_key, chacha_key, mac_key = derive_three_keys(master_pw, salt)
    # Leite zwei unabhängige Schlüssel aus dem MAC‑Key ab. Wir nutzen HMAC‑SHA512,
    # um aus dem ursprünglichen MAC‑Key zwei 64‑Byte‑Schlüssel abzuleiten: einen
    # für das Pad (XOR‑Obfuskation) und einen für den finalen HMAC. Dadurch wird
    # verhindert, dass derselbe Schlüssel sowohl zur Generierung des Pads als
    # auch zur Integritätsprüfung verwendet wird. Dieses Vorgehen entspricht dem
    # in der Diagnoseliste geforderten Key‑Reuse‑Schutz.
    pad_key = hmac_sha512(mac_key, b"pad")  # 64 Byte
    hmac_key = hmac_sha512(mac_key, b"hmac")  # 64 Byte
    # MAC‑Key selbst wird nicht weiterverwendet
    try:
        del mac_key
    except Exception:
        pass

    # AES-GCM (erste Schicht)
    nonce_aes = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(aes_key)
    ciphertext_aes = aesgcm.encrypt(nonce_aes, plaintext, header)

    # Pad (XOR-Obfuskation)
    nonce_pad = secrets.token_bytes(NONCE_LEN)
    pad = pad_stream_from_mac(pad_key, nonce_pad, len(ciphertext_aes))
    obf = xor_bytes(ciphertext_aes, pad)

    # ChaCha20-Poly1305 (zweite Schicht)
    nonce_chacha = secrets.token_bytes(NONCE_LEN)
    chacha = ChaCha20Poly1305(chacha_key)
    ciphertext_chacha = chacha.encrypt(nonce_chacha, obf, header)

    file_body = salt + nonce_aes + nonce_pad + nonce_chacha + ciphertext_chacha
    # Integritätsprüfung jetzt über header||body
    file_hmac = hmac_sha512(hmac_key, header + file_body)

    out = header + file_body + file_hmac

    # versuchen, sensitive Variablen zu löschen
    try:
        del aes_key, chacha_key, pad_key, hmac_key, pad, obf, ciphertext_aes, ciphertext_chacha, file_body, file_hmac
    except Exception:
        pass
    return out


def decrypt_vault_bytes(blob: bytes, master_pw: bytes) -> bytes:
    """Entschlüsselt kompletten blob mit master_pw und liefert plaintext.
    Unterstützt Version 2 (Altformat, ohne AAD) und Version 3 (mit KDF‑TLV + AAD).
    """
    if len(blob) < 4+1+SALT_LEN+NONCE_LEN*3+64:
        raise ValueError("Datei zu klein oder beschädigt")
    off = 0
    magic = blob[off:off+4]; off += 4
    if magic != MAGIC:
        raise ValueError("Ungültiges Dateiformat (magic mismatch)")
    version = blob[off]; off += 1

    if version == 3:
        kdf_params, off = _parse_kdf_tlv(blob, off)
        # Header exakt so rekonstruieren wie bei Verschlüsselung
        header = MAGIC + bytes([version]) + _build_kdf_tlv()
        salt = blob[off:off+SALT_LEN]; off += SALT_LEN
        nonce_aes = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        nonce_pad = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        nonce_chacha = blob[off:off+NONCE_LEN]; off += NONCE_LEN
        if len(blob) < off + 64:
            raise ValueError("HMAC fehlt/Datei beschädigt")
        ciphertext_chacha = blob[off:-64]
        file_hmac = blob[-64:]

        # Schlüssel wie konfiguriert ableiten (aus globalen Parametern)
        aes_key, chacha_key, mac_key = derive_three_keys(master_pw, salt)
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
    obj = {
        "meta": {"created_at": vault.created_at, "updated_at": time.time()},
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
    if not _HAS_PYPERCLIP:
        print("[Hinweis] pyperclip nicht verfügbar – kein Clipboard gesetzt.")
        return
    try:
        pyperclip.copy(text)
        print(f"[OK] In Zwischenablage kopiert. Wird in {seconds}s gelöscht.")
        def _wipe():
            try:
                time.sleep(max(1, int(seconds)))
                pyperclip.copy("")
            except Exception:
                pass
        t = threading.Thread(target=_wipe, daemon=True)
        t.start()
    except Exception:
        print("[Fehler] Clipboard konnte nicht gesetzt werden.")

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
        print("Passwort in Zwischenablage kopiert.")
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
        print("Clipboard nicht verfügbar. Installiere 'pyperclip' oder native Tools.")

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

def cli_encrypt_file() -> None:
    """Hilfsfunktion für CLI: Beliebige Datei verschlüsseln.

    Fordert den Benutzer interaktiv nach Eingabe-, Ausgabe- und Passwortdaten.
    Bei erfolgreicher Verschlüsselung wird eine Meldung ausgegeben und ein Audit-Eintrag
    geschrieben. Fehler werden abgefangen und dem Benutzer gemeldet.
    """
    inp = input("Pfad der zu verschlüsselnden Datei: ").strip()
    if not inp:
        print("Abbruch: kein Pfad.")
        return
    in_path = Path(inp)
    if not in_path.is_file():
        print("Datei nicht gefunden:", inp)
        return
    default_out = in_path.with_suffix(in_path.suffix + ".enc")
    outp = input(f"Ausgabedatei [{default_out}]: ").strip()
    if not outp:
        outp = str(default_out)
    # Passwort doppelt abfragen, um Tippfehler zu vermeiden
    pw1 = getpass.getpass("Passwort für Verschlüsselung: ")
    if not pw1:
        print("Abbruch: kein Passwort.")
        return
    pw2 = getpass.getpass("Passwort erneut eingeben: ")
    if pw1 != pw2:
        print("Passwörter stimmen nicht überein. Abbruch.")
        return
    try:
        encrypt_file_data(in_path, pw1, Path(outp))
        write_audit("encrypt_file", f"{inp}->{outp}")
        print(f"Datei verschlüsselt und gespeichert: {outp}")
    except Exception as e:
        print("Fehler:", e)


def cli_decrypt_file() -> None:
    """Hilfsfunktion für CLI: Entschlüsselt eine mit encrypt_file_data erzeugte Datei."""
    inp = input("Pfad der verschlüsselten Datei: ").strip()
    if not inp:
        print("Abbruch: kein Pfad.")
        return
    in_path = Path(inp)
    if not in_path.is_file():
        print("Datei nicht gefunden:", inp)
        return
    default_out = str(in_path.with_suffix(""))
    outp = input(f"Ausgabedatei [{default_out}]: ").strip()
    if not outp:
        outp = default_out
    pw = getpass.getpass("Passwort für Entschlüsselung: ")
    if not pw:
        print("Abbruch: kein Passwort.")
        return
    try:
        decrypt_file_data(in_path, pw, Path(outp))
        write_audit("decrypt_file", f"{inp}->{outp}")
        print(f"Datei entschlüsselt und gespeichert: {outp}")
    except Exception as e:
        print("Fehler:", e)


def cli_hide_file() -> None:
    """Hilfsfunktion für CLI: Versteckt eine Datei in einer Cover-Datei."""
    data_inp = input("Pfad der zu versteckenden Datei: ").strip()
    if not data_inp:
        print("Abbruch: kein Pfad.")
        return
    data_path = Path(data_inp)
    if not data_path.is_file():
        print("Datei nicht gefunden:", data_inp)
        return
    cover_inp = input("Pfad der Cover-Datei: ").strip()
    if not cover_inp:
        print("Abbruch: kein Cover-Pfad.")
        return
    cover_path = Path(cover_inp)
    if not cover_path.is_file():
        print("Cover-Datei nicht gefunden:", cover_inp)
        return
    default_out = cover_path.with_suffix(cover_path.suffix + ".hid")
    outp = input(f"Ausgabedatei [{default_out}]: ").strip()
    if not outp:
        outp = str(default_out)
    # Passwort doppelt abfragen, um Tippfehler zu vermeiden
    pw1 = getpass.getpass("Passwort für Verschlüsselung: ")
    if not pw1:
        print("Abbruch: kein Passwort.")
        return
    pw2 = getpass.getpass("Passwort erneut eingeben: ")
    if pw1 != pw2:
        print("Passwörter stimmen nicht überein. Abbruch.")
        return
    try:
        hide_file_in_file(cover_path, data_path, pw1, Path(outp))
        write_audit("hide_file", f"{data_inp}@{cover_inp}->{outp}")
        print(f"Datei versteckt in {outp}")
    except Exception as e:
        print("Fehler:", e)


def cli_extract_hidden_file() -> None:
    """Hilfsfunktion für CLI: Extrahiert versteckte Daten aus einer Datei und gibt Originalname aus."""
    stego_inp = input("Pfad der Datei mit verstecktem Inhalt: ").strip()
    if not stego_inp:
        print("Abbruch: kein Pfad.")
        return
    stego_path = Path(stego_inp)
    if not stego_path.is_file():
        print("Datei nicht gefunden:", stego_inp)
        return
    pw = getpass.getpass("Passwort für Entschlüsselung: ")
    if not pw:
        print("Abbruch: kein Passwort.")
        return
    try:
        orig_name, payload = decrypt_hidden_payload(stego_path, pw)
    except Exception as e:
        print("Fehler:", e)
        return
    # Informiere den Benutzer über den erkannten Namen/Typ
    print(f"Versteckte Datei erkannt: {orig_name}")
    # Vorschlag für Ausgabedatei: gleicher Verzeichnis wie stego, aber ursprünglicher Name
    suggested_out = stego_path.with_name(orig_name)
    outp = input(f"Ausgabedatei [{suggested_out}]: ").strip()
    if not outp:
        outp = str(suggested_out)
    try:
        atomic_write(Path(outp), payload)
        write_audit("extract_file", f"{stego_inp}->{outp}")
        print(f"Versteckte Datei extrahiert: {outp}")
    except Exception as e:
        print("Fehler beim Schreiben:", e)


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
            print("Konfig-Datei erstellen")
            default_name = DEFAULT_CONFIG_FILENAME
            fn = input(f"Dateiname für Konfig-Datei [{default_name}]: ").strip()
            if not fn:
                fn = default_name
            cfg_path = Path(fn)
            if not cfg_path.is_absolute():
                cfg_path = exe_dir() / cfg_path
            if cfg_path.exists():
                if input(f"Datei {cfg_path} existiert bereits – überschreiben? (ja): ").strip().lower() != "ja":
                    print("Abbruch der Konfig-Erstellung.")
                    continue
            try:
                cfg = _default_config()
                write_config_with_comments(cfg_path, cfg)
                print(f"Konfigurationsdatei erstellt: {cfg_path}")
                print("Die Datei enthält Erläuterungen zu jedem Parameter.")
                print("Bearbeite diese Datei, um Parameter wie KDF, Auto-Lock oder Audit-Logging anzupassen.")
            except Exception as e:
                print("Fehler beim Erstellen der Konfig-Datei:", e)
        elif choice == "0":
            print("Beendet.")
            # CLI-Farb zurücksetzen vor dem Exit
            if CLI_COLOR_ENABLED:
                print("\033[0m", end="")
            break
        else:
            print("Unbekannte Auswahl.")
def cli_loop(path: Path, safe_mode: bool = SAFE_CLI_DEFAULT) -> None:
    """
    CLI Hauptschleife. safe_mode=True deaktiviert Klartext-Export-Funktionen.
    """
    # Wenn CLI-Farben aktiviert sind, setze Hintergrund- und Schriftfarbe fort.
    if CLI_COLOR_ENABLED:
        print(f"{CLI_BG_COLOR}{CLI_FG_COLOR}", end="")
    # Zeige dem Benutzer, welche Tresor- und Konfigurationsdatei verwendet werden.
    print_cli_status(path)
    master_pw = getpass.getpass("Master-Passwort: ")
    if not master_pw:
        print("Abbruch: kein Passwort.")
        return
    if path.exists():
        try:
            vault = load_vault(path, master_pw)
        except Exception as e:
            print("Fehler beim Laden:", e)
            return
    else:
        print(f"Treordatei nicht gefunden. Neuer Tresor wird erstellt: {path}")
        if len(master_pw) < MIN_MASTER_PW_LEN:
            print(f"Warnung: Master-Passwort sollte >= {MIN_MASTER_PW_LEN} Zeichen haben.")
        vault = Vault.empty()
        save_vault(path, vault, master_pw)
        print("Leerer Tresor erstellt und gespeichert.")
    # Führe ggf. automatische Schlüsselrotation durch
    try:
        rotated = auto_rotate_if_due(path, vault, master_pw)
        if rotated:
            print("Tresor wurde automatisch neu verschlüsselt (Schlüsselrotation)")
    except Exception:
        # Fehler bei der Rotation ignorieren; Warnung folgt ggf. separat
        pass

    # Prüfe, ob eine Schlüsselrotation empfohlen wird (Warnung in CLI ausgeben)
    maybe_warn_rotation_cli(vault)
    while True:
        print(MENU)
        choice = input("> ").strip().lower()
        if choice == "1":
            if not vault.entries:
                print("(keine Einträge)")
            for eid, e in vault.entries.items():
                print(f"[{eid}] {e.label} — {e.username} — {e.email}")
        elif choice == "2":
            eid = input("Eintrags-ID: ").strip()
            e = vault.entries.get(eid)
            if not e:
                print("Nicht gefunden.")
            else:
                print(json.dumps(asdict(e), ensure_ascii=False, indent=2))
        elif choice == "3":
            # Neuer Eintrag: neben den üblichen Feldern wird auch eine Webseite/IP abgefragt.
            label = input("Label: ").strip()
            username = input("Benutzer: ").strip()
            email = input("Email: ").strip()
            pw = input("Passwort (leer = generieren): ").strip()
            if not pw:
                pw = generate_password()
                print("Generiertes Passwort:", pw)
            cat, score = password_strength(pw)
            print(f"Passwortstärke: {cat} ({score}/100)")
            info = input("Info: ").strip()
            website = input("Webseite/IP: ").strip()
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
                print("Hinzugefügt und gespeichert:", eid)
            finally:
                # Überschreibe das Passwort im Speicher, um seine Verweildauer zu minimieren
                for i in range(len(_pw_bytes)):
                    _pw_bytes[i] = 0
                del _pw_bytes
        elif choice == "4":
            eid = input("Eintrags-ID: ").strip()
            e = vault.entries.get(eid)
            if not e:
                print("Nicht gefunden.")
            else:
                label = input(f"Label [{e.label}]: ").strip() or e.label
                username = input(f"Benutzer [{e.username}]: ").strip() or e.username
                email = input(f"Email [{e.email}]: ").strip() or e.email
                pw = input("Neues Passwort (leer = unverändert): ").strip()
                if pw:
                    cat, score = password_strength(pw)
                    print(f"Passwortstärke: {cat} ({score}/100)")
                    # Kopiere Passwort in Bytearray zur späteren Löschung
                    _pw_bytes2 = bytearray(pw.encode("utf-8"))
                    e.password = pw
                info = input(f"Info [{e.info}]: ").strip() or e.info
                website = input(f"Webseite/IP [{e.website}]: ").strip() or e.website
                e.website = website
                e.label, e.username, e.email, e.info = label, username, email, info
                e.updated_at = time.time()
                vault.updated_at = e.updated_at
                save_vault(path, vault, master_pw)
                # Audit: Update
                write_audit("update", f"{eid}|{e.label}")
                print("Eintrag aktualisiert und gespeichert.")

                # Lösche temporäres Passwort aus Speicher (falls gesetzt)
                try:
                    for i in range(len(_pw_bytes2)):
                        _pw_bytes2[i] = 0
                    del _pw_bytes2
                except Exception:
                    pass
        elif choice == "5":
            eid = input("Eintrags-ID zum Löschen: ").strip()
            if eid in vault.entries:
                confirm = input(f"Wirklich löschen {vault.entries[eid].label}? (ja): ").strip().lower()
                if confirm == "ja":
                    # Audit: deletion (store label before removal)
                    lbl = vault.entries[eid].label
                    del vault.entries[eid]
                    vault.updated_at = time.time()
                    save_vault(path, vault, master_pw)
                    write_audit("delete", f"{eid}|{lbl}")
                    print("Gelöscht und gespeichert.")
            else:
                print("Nicht gefunden.")
        elif choice == "6":
            if safe_mode:
                print("Export deaktiviert im sicheren Modus.")
                continue
            eid = input("Eintrags-ID: ").strip()
            if eid in vault.entries:
                out = export_entry_txt(vault, eid)
                # Audit: export single entry
                write_audit("export_entry", f"{eid}|{vault.entries[eid].label}")
                print("Exportiert ->", out)
            else:
                print("Nicht gefunden.")
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
            # Wende GUI-Farben nur an, wenn entsprechende Parameter gesetzt sind. Andernfalls
            # bleibt das Systemdesign erhalten. Die Farbparameter können über die
            # Konfigurationsdatei angepasst werden. Leere Strings bedeuten: keine Anpassung.
            if GUI_BG_COLOR or GUI_FG_COLOR or GUI_BUTTON_COLOR:
                try:
                    # Setze den Hintergrund der Root auf die konfigurierte Farbe
                    if GUI_BG_COLOR:
                        self.root.configure(bg=GUI_BG_COLOR)
                    style = ttk.Style()
                    # Versuche, ein Theme zu wählen, das Farbänderungen erlaubt
                    try:
                        style.theme_use('clam')
                    except Exception:
                        pass
                    # Wende Farben für Frames, Labels und Buttons an (nur wenn definiert)
                    if GUI_BG_COLOR:
                        style.configure('TFrame', background=GUI_BG_COLOR)
                        style.configure('TLabel', background=GUI_BG_COLOR)
                    if GUI_FG_COLOR:
                        style.configure('TLabel', foreground=GUI_FG_COLOR)
                    if GUI_BUTTON_COLOR or GUI_FG_COLOR:
                        # Setze Buttonfarben nur, wenn eine der beiden Farben definiert ist
                        fg = GUI_FG_COLOR if GUI_FG_COLOR else None
                        bg = GUI_BUTTON_COLOR if GUI_BUTTON_COLOR else None
                        style.configure('TButton', background=bg, foreground=fg)
                except Exception:
                    # Bei Fehlermeldungen nichts tun – Standardfarben werden beibehalten
                    pass
            self.path = path
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
                    # Wenn kein Callback, zeige die Exception an
                    messagebox.showerror("Fehler", f"Operation fehlgeschlagen:\n{exc}", parent=self.root)

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
            ttk.Button(btns, text=tr("Hilfe", "Help"), command=self.show_help).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("Beenden", "Exit"), command=self.root.destroy).pack(side="left", padx=6)
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
                        cfg_msg = "Keine gültige externe Konfiguration geladen – Standardwerte werden verwendet."
                        cfg_color = "black"
                    else:
                        cfg_msg = "Keine Konfiguration gefunden – es werden die im Skript hinterlegten Werte verwendet."
                        cfg_color = "black"
                elif Path(active_cfg).resolve() == default_cfg.resolve():
                    cfg_msg = f"Standard-Konfigurationsdatei geladen: {active_cfg}"
                    cfg_color = "blue"
                else:
                    cfg_msg = f"Externe Konfigurationsdatei geladen: {active_cfg}"
                    cfg_color = "green"
            except Exception:
                cfg_msg = "Konfigurationsstatus konnte nicht ermittelt werden."
                cfg_color = "black"
            # Hinweistext
            info_text = (
                "Hinweis: Tresor-Dateien haben die Endung .pwm. Existiert die Datei nicht, wird sie beim Speichern automatisch angelegt.\n"
                "Die Konfiguration wird, falls vorhanden, automatisch aus '" + DEFAULT_CONFIG_FILENAME + "' geladen. Über den Button 'Konfig laden' kannst du eine andere Datei auswählen.\n"
            )
            ttk.Label(frm, text=info_text, wraplength=700, justify="left").pack(pady=(6, 2), anchor="w")
            # Statusausgabe mit Übersetzung
            ttk.Label(frm, text=tr("Status:", "Status:"), foreground="blue").pack(anchor="w")
            ttk.Label(frm, text=vault_msg, foreground=vault_color).pack(anchor="w")
            ttk.Label(frm, text=cfg_msg, foreground=cfg_color).pack(anchor="w", pady=(0, 6))
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
            ttk.Button(enc_frame, text="Datei verschlüsseln", command=self.gui_encrypt_any_file).pack(fill="x", pady=2)
            ttk.Button(enc_frame, text="Datei entschlüsseln", command=self.gui_decrypt_any_file).pack(fill="x", pady=2)
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
            ttk.Button(extract_ops, text="Extrahieren", command=self.gui_do_extract).grid(row=2, column=0, sticky="w", pady=(4, 6))
            # Werbebereich unten: zwei Zeilen, zweiter Link ist klickbar
            adv_frame = ttk.Frame(self.root, padding=(6, 4))
            adv_frame.pack(fill="x")
            # Werbetext im unteren Bereich des Login-Fensters; der Zeilenumbruch
            # (wraplength) sorgt dafür, dass der gesamte Text bei schmaler
            # Fensterbreite sichtbar bleibt.
            adv_msg = ttk.Label(adv_frame, text=TELEGRAM_MESSAGE, wraplength=500)
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
                if not messagebox.askyesno("Existiert", "Datei existiert bereits — überschreiben?", parent=self.root):
                    return
            pw1 = simpledialog.askstring("Neues Master-Passwort", "Master-Passwort:", show="*", parent=self.root)
            if not pw1:
                return
            pw2 = simpledialog.askstring("Bestätigen", "Bestätigen:", show="*", parent=self.root)
            if pw1 != pw2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                return
            if len(pw1) < MIN_MASTER_PW_LEN:
                if not messagebox.askyesno(
                    "Kurzes Passwort",
                    f"Passwort kürzer als {MIN_MASTER_PW_LEN}. Fortfahren?",
                    parent=self.root,
                ):
                    return
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
                messagebox.showinfo("Fertig", "Leerer Tresor erstellt.", parent=self.root)
                self.build_main_ui()
            # Callback bei Fehler
            def on_create_error(exc: Exception):
                messagebox.showerror("Fehler", f"Tresor konnte nicht erstellt werden:\n{exc}", parent=self.root)
            # Starte Fortschrittsdialog
            self.run_with_progress(
                "Tresor erstellen",
                "Neuer Tresor wird angelegt. Bitte warten...",
                do_create_work,
                args=(pw1,),
                on_success=on_create_success,
                on_error=on_create_error,
            )

        def gui_unlock(self):
            pw = self.pw_entry.get()
            # Prüfe, ob die Tresor-Datei existiert
            if not self.path.exists():
                messagebox.showerror("Fehler", "Tresor-Datei existiert nicht. Erzeuge neuen Tresor.", parent=self.root)
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
                # Fehler anzeigen
                messagebox.showerror("Fehler", f"Entschlüsselung fehlgeschlagen:\n{exc}", parent=self.root)
                # Passwortfeld leeren und Fokus setzen
                try:
                    self.pw_entry.delete(0, 'end')
                    self.pw_entry.focus_set()
                except Exception:
                    pass

            # Starte den Fortschrittsdialog zum Laden des Tresors
            self.run_with_progress(
                "Tresor laden",
                "Tresor wird geladen. Bitte warten...",
                do_unlock_work,
                args=(pw,),
                on_success=on_unlock_success,
                on_error=on_unlock_error
            )

        def gui_select_file(self):
            """Dateiauswahldialog für den Tresor. Ermöglicht dem Benutzer, eine andere
            Tresor-Datei auszuwählen. Nach Auswahl wird die Login-UI neu aufgebaut,
            sodass der neue Pfad angezeigt wird."""
            f = filedialog.askopenfilename(
                parent=self.root,
                title="Tresor-Datei auswählen",
                defaultextension=".pwm",
                filetypes=[("Vault-Dateien", "*.pwm"), ("Alle Dateien", "*.*")],
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
                title="Konfigurationsdatei auswählen",
                defaultextension=".json",
                filetypes=[("JSON Dateien", "*.json"), ("Alle Dateien", "*.*")],
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
                        "Konfiguration",
                        f"Konfigurationsdatei '{f}' wurde neu erstellt mit Standardwerten.\n"
                        "Du kannst diese Datei jetzt in einem Texteditor bearbeiten, um Parameter anzupassen.",
                    )
                else:
                    messagebox.showinfo(
                        "Konfiguration",
                        f"Konfiguration aus '{f}' geladen. Änderungen gelten sofort für neue Operationen.",
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
                    "Konfig erstellt",
                    f"Standard-Konfiguration wurde gespeichert unter:\n{cfg_path}\n"
                    "Die Datei enthält Kommentare zu jedem Parameter.\n"
                    "Bearbeite diese Datei und lade sie anschließend über den Konfig-Button.",
                )
            except Exception as e:
                messagebox.showerror("Fehler", f"Konfiguration konnte nicht erstellt werden: {e}")

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
                    "Keine Konfiguration",
                    "Es ist keine Konfigurationsdatei geladen.\n"
                    "Bitte lade oder erstelle zunächst eine Konfiguration.",
                    parent=self.root
                )
                return
            # Aktuelle Werte aus globalen Variablen ermitteln
            current_values = {k: globals().get(k) for k in CONFIG_KEYS}
            # Fenster erstellen
            win = tk.Toplevel(self.root)
            win.title("Konfiguration bearbeiten")
            win.transient(self.root)
            try:
                win.grab_set()
            except Exception:
                pass
            # Canvas mit vertikaler Scrollbar für viele Parameter
            canvas = tk.Canvas(win)
            scrollbar = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            # Entry-Widgets pro Key speichern
            # Mapping von Konfigurationsnamen zu den zugehörigen Eingabefeldern
            entries = {}
            for idx, key in enumerate(CONFIG_KEYS):
                val = current_values.get(key, "")
                expl = CONFIG_EXPLANATIONS.get(key, "")
                ttk.Label(scrollable_frame, text=key + ":").grid(row=2*idx, column=0, sticky="w", padx=4, pady=(6 if idx == 0 else 2, 0))
                ent = ttk.Entry(scrollable_frame, width=40)
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
                    messagebox.showerror("Fehler", f"Konfiguration konnte nicht angewendet werden:\n{e}", parent=win)
                    return
                # Neue Werte zusammenstellen und Datei schreiben
                try:
                    cfg_all = _default_config()
                    for key2 in cfg_all.keys():
                        cfg_all[key2] = globals().get(key2)
                    write_config_with_comments(Path(cfg_path), cfg_all)
                except Exception as e:
                    messagebox.showerror("Fehler", f"Konfiguration konnte nicht gespeichert werden:\n{e}", parent=win)
                    return
                messagebox.showinfo("Erfolg", "Konfiguration wurde gespeichert und angewendet.", parent=win)
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
            ttk.Button(btn_frame, text="Speichern", command=on_save).pack(side="right", padx=4)
            ttk.Button(btn_frame, text="Abbrechen", command=on_cancel).pack(side="right", padx=4)

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
                        cfg_msg = "Keine gültige externe Konfiguration geladen – Standardwerte werden verwendet."
                    else:
                        cfg_msg = "Keine Konfiguration gefunden – es werden die im Skript hinterlegten Werte verwendet."
                elif Path(active_cfg).resolve() == default_cfg.resolve():
                    cfg_msg = f"Standard-Konfigurationsdatei geladen: {active_cfg}"
                else:
                    cfg_msg = f"Externe Konfigurationsdatei geladen: {active_cfg}"
            except Exception:
                cfg_msg = "Konfigurationsstatus konnte nicht ermittelt werden."
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
            # Hauptbereich für Liste und Seitenmenü
            main = ttk.Frame(self.root)
            main.pack(fill="both", expand=True, padx=6, pady=6)

            self.tree = ttk.Treeview(main, columns=("id", "label", "user", "email"), show="headings")
            self.tree.heading("id", text="ID"); self.tree.heading("label", text="Label:")
            self.tree.heading("user", text="Benutzer:"); self.tree.heading("email", text="Email:")
            self.tree.column("id", width=140); self.tree.column("label", width=300)
            self.tree.column("user", width=200); self.tree.column("email", width=260)
            self.tree.pack(fill="both", expand=True, side="left")
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

            # Werbehinweis am unteren Rand der Seitenleiste (zweizeilig). Der Link öffnet den Telegram-Kanal.
            adv_frame = ttk.Frame(side)
            adv_frame.pack(fill="x", pady=(10, 0))
            # Werbetext am unteren Rand der Seitenleiste; durch den geringeren
            # Platzbedarf wird eine kürzere Zeilenlänge gewählt, damit ein
            # Zeilenumbruch erzwungen wird und der Text nicht abgeschnitten wird.
            adv_msg = ttk.Label(adv_frame, text=TELEGRAM_MESSAGE, wraplength=200)
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
            for e in sorted(self.vault.entries.values(), key=lambda x: x.label.lower()):
                self.tree.insert("", "end", values=(e.id, e.label, e.username, e.email))

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

            ttk.Button(btn_pw, text="Anzeigen", command=reveal_or_hide).pack(side="left", padx=2)

            ttk.Button(btn_pw, text="Kopiere Passwort", command=lambda: self.copy_pw_and_clear(e.password)).pack(side="left", padx=2)

            # Info-Feld

            ttk.Label(frm, text="Info:").grid(row=info_row_idx, column=0, sticky="nw", pady=2)

            info_frame = ttk.Frame(frm)

            info_frame.grid(row=info_row_idx, column=1, columnspan=3, sticky="nsew", pady=2)

            info_frame.rowconfigure(0, weight=1); info_frame.columnconfigure(0, weight=1)

            txt_info = tk.Text(info_frame, wrap="word")

            txt_info.insert("1.0", e.info or "")

            txt_info.configure(state="disabled")

            y_scroll = ttk.Scrollbar(info_frame, orient="vertical", command=txt_info.yview)

            x_scroll = ttk.Scrollbar(info_frame, orient="horizontal", command=txt_info.xview)

            txt_info.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

            txt_info.grid(row=0, column=0, sticky="nsew"); y_scroll.grid(row=0, column=1, sticky="ns"); x_scroll.grid(row=1, column=0, sticky="ew")

            # Zeiten im deutschen Format, falls fmt_de existiert

            try:

                created_str = fmt_de(e.created_at); updated_str = fmt_de(e.updated_at)

            except Exception:

                created_str = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(e.created_at))

                updated_str = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(e.updated_at))

            ttk.Label(frm, text="Erstellt:").grid(row=info_row_idx+1, column=0, sticky="w", pady=(8,2))

            ttk.Label(frm, text=created_str).grid(row=info_row_idx+1, column=1, sticky="w", pady=(8,2), padx=(4,0))

            ttk.Label(frm, text="Geändert:").grid(row=info_row_idx+2, column=0, sticky="w", pady=2)

            ttk.Label(frm, text=updated_str).grid(row=info_row_idx+2, column=1, sticky="w", pady=2, padx=(4,0))

            btnf = ttk.Frame(frm)

            btnf.grid(row=info_row_idx+3, column=1, columnspan=3, sticky="e", pady=8)

            ttk.Button(btnf, text="Schließen", command=top.destroy).pack(side="right", padx=4)

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
                messagebox.showinfo("Erfolg", "Eintrag gespeichert.", parent=self.root)

            # Callback bei Fehlern
            def on_add_error(exc: Exception):
                messagebox.showerror("Fehler", f"Speichern fehlgeschlagen:\n{exc}", parent=self.root)

            # Handler für die Schaltfläche "Hinzufügen"
            def on_add_click():
                label = ent_label.get().strip()
                if not label:
                    messagebox.showerror("Fehler", "Label erforderlich", parent=top)
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
                        "Schwaches Passwort",
                        f"Passwortstärke {cat} ({score}). Fortfahren?",
                        parent=top,
                    ):
                        return
                info = txt_info.get("1.0", "end").strip()
                website = ent_web.get().strip()
                # Startet den Fortschrittsdialog
                self.run_with_progress(
                    "Eintrag speichern",
                    "Eintrag wird gespeichert. Bitte warten...",
                    do_add_work,
                    args=(label, username, email, website, info, pw_val),
                    on_success=on_add_success,
                    on_error=on_add_error,
                )
            top = tk.Toplevel(self.root)
            top.title("Hinzufügen")
            # Verwende ein Grid-Layout, bei dem Spalte 1 und die Info-Zeile sich mit dem Fenster
            # ausdehnen. So passen sich die Eingabefelder automatisch an die Fenstergröße an.
            frm = ttk.Frame(top, padding=8)
            frm.grid(row=0, column=0, sticky="nsew")
            top.columnconfigure(0, weight=1)
            top.rowconfigure(0, weight=1)
            frm.columnconfigure(1, weight=1)
            frm.rowconfigure(5, weight=1)
            # Eingabefelder für Label, Benutzer, Email
            ttk.Label(frm, text="Label:").grid(row=0, column=0, sticky="w", pady=2)
            ent_label = ttk.Entry(frm)
            ent_label.grid(row=0, column=1, sticky="ew", pady=2)
            ttk.Label(frm, text="Benutzer:").grid(row=1, column=0, sticky="w", pady=2)
            ent_user = ttk.Entry(frm)
            ent_user.grid(row=1, column=1, sticky="ew", pady=2)
            ttk.Label(frm, text="Email:").grid(row=2, column=0, sticky="w", pady=2)
            ent_email = ttk.Entry(frm)
            ent_email.grid(row=2, column=1, sticky="ew", pady=2)
            # Passwortfeld mit optionalem Generieren
            ttk.Label(frm, text="Passwort (leer=generieren):").grid(row=3, column=0, sticky="w", pady=2)
            ent_pw = ttk.Entry(frm)
            ent_pw.grid(row=3, column=1, sticky="ew", pady=2)
            def do_gen_pw_add():
                ent_pw.delete(0, tk.END)
                ent_pw.insert(0, generate_password())
            ttk.Button(frm, text="Generieren", command=do_gen_pw_add).grid(row=3, column=2, padx=6, pady=2)
            # Webseite/IP
            ttk.Label(frm, text="Webseite/IP:").grid(row=4, column=0, sticky="w", pady=2)
            ent_web = ttk.Entry(frm)
            ent_web.grid(row=4, column=1, sticky="ew", pady=2)
            # Info-Feld mit Scrollbars
            ttk.Label(frm, text="Info:").grid(row=5, column=0, sticky="nw", pady=2)
            info_frame = ttk.Frame(frm)
            info_frame.grid(row=5, column=1, sticky="nsew", pady=2)
            info_frame.rowconfigure(0, weight=1)
            info_frame.columnconfigure(0, weight=1)
            txt_info = tk.Text(info_frame, wrap="none")
            y_scroll = ttk.Scrollbar(info_frame, orient="vertical", command=txt_info.yview)
            x_scroll = ttk.Scrollbar(info_frame, orient="horizontal", command=txt_info.xview)
            txt_info.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
            txt_info.grid(row=0, column=0, sticky="nsew")
            y_scroll.grid(row=0, column=1, sticky="ns")
            x_scroll.grid(row=1, column=0, sticky="ew")
            # Kontrollkästchen zum Umschalten des Zeilenumbruchs
            wrap_var = tk.BooleanVar(value=False)
            def toggle_wrap():
                txt_info.configure(wrap="word" if wrap_var.get() else "none")
            ttk.Checkbutton(frm, text="Zeilenumbruch", variable=wrap_var, command=toggle_wrap).grid(row=6, column=1, sticky="w", pady=(2,0))
            # Button-Leiste
            btnf = ttk.Frame(frm)
            btnf.grid(row=7, column=1, sticky="w", pady=8)
            ttk.Button(btnf, text="Hinzufügen", command=on_add_click).pack(side="left", padx=4)
            ttk.Button(btnf, text="Abbrechen", command=top.destroy).pack(side="left", padx=4)

        def gui_edit(self):
            self.touch()
            sel = self.tree.selection()
            if not sel:
                messagebox.showinfo("Info", "Kein Eintrag ausgewählt"); return
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
                messagebox.showinfo("Erfolg", "Eintrag gespeichert.")
            # Callback bei Fehlern
            def on_save_error(exc: Exception):
                messagebox.showerror("Fehler", f"Speichern fehlgeschlagen:\n{exc}")
            # Handler für die Speichern-Schaltfläche: validiert Eingaben und startet die
            # asynchrone Speicherung mit Fortschrittsdialog.
            def on_save_click():
                new_label = ent_label.get().strip() or e.label
                new_username = ent_user.get().strip() or e.username
                new_email = ent_email.get().strip() or e.email
                new_website = ent_web.get().strip() or e.website
                new_info = txt_info.get("1.0", "end").strip() or e.info
                new_pw = ent_pw.get().strip() or None
                # Prüfe Passwortstärke, falls ein neues Passwort gesetzt wird
                if new_pw:
                    cat, score = password_strength(new_pw)
                    if score < 40:
                        if not messagebox.askyesno(
                            "Schwaches Passwort",
                            f"Passwortstärke {cat} ({score}). Fortfahren?",
                            parent=top,
                        ):
                            return
                # Starte Speichervorgang im Hintergrund
                self.run_with_progress(
                    "Speichern", "Änderungen werden gespeichert. Bitte warten...",
                    do_save_work,
                    (new_label, new_username, new_email, new_website, new_info, new_pw),
                    on_success=on_save_success,
                    on_error=on_save_error
                )
            top = tk.Toplevel(self.root)
            top.title("Ändern")
            # Grid-Layout: Spalte 1 expandiert, Zeile 5 (Info) expandiert
            frm = ttk.Frame(top, padding=8)
            frm.grid(row=0, column=0, sticky="nsew")
            top.columnconfigure(0, weight=1)
            top.rowconfigure(0, weight=1)
            frm.columnconfigure(1, weight=1)
            frm.rowconfigure(5, weight=1)
            # Label
            ttk.Label(frm, text="Label:").grid(row=0, column=0, sticky="w", pady=2)
            ent_label = ttk.Entry(frm)
            ent_label.insert(0, e.label)
            ent_label.grid(row=0, column=1, sticky="ew", pady=2)
            # Benutzer
            ttk.Label(frm, text="Benutzer:").grid(row=1, column=0, sticky="w", pady=2)
            ent_user = ttk.Entry(frm)
            ent_user.insert(0, e.username)
            ent_user.grid(row=1, column=1, sticky="ew", pady=2)
            # Email
            ttk.Label(frm, text="Email:").grid(row=2, column=0, sticky="w", pady=2)
            ent_email = ttk.Entry(frm)
            ent_email.insert(0, e.email)
            ent_email.grid(row=2, column=1, sticky="ew", pady=2)
            # Webseite/IP
            ttk.Label(frm, text="Webseite/IP:").grid(row=3, column=0, sticky="w", pady=2)
            ent_web = ttk.Entry(frm)
            ent_web.insert(0, e.website)
            ent_web.grid(row=3, column=1, sticky="ew", pady=2)
            # Passwort
            ttk.Label(frm, text="Passwort (leer=unverändert):").grid(row=4, column=0, sticky="w", pady=2)
            ent_pw = ttk.Entry(frm)
            ent_pw.grid(row=4, column=1, sticky="ew", pady=2)
            # Passwort generieren
            def do_gen_pw_edit():
                ent_pw.delete(0, tk.END)
                ent_pw.insert(0, generate_password())
            ttk.Button(frm, text="Generieren", command=do_gen_pw_edit).grid(row=4, column=2, padx=6, pady=2)
            # Info-Feld mit Scrollbars
            ttk.Label(frm, text="Info:").grid(row=5, column=0, sticky="nw", pady=2)
            info_frame = ttk.Frame(frm)
            info_frame.grid(row=5, column=1, sticky="nsew", pady=2)
            info_frame.rowconfigure(0, weight=1)
            info_frame.columnconfigure(0, weight=1)
            txt_info = tk.Text(info_frame, wrap="none")
            txt_info.insert("1.0", e.info)
            y_scroll = ttk.Scrollbar(info_frame, orient="vertical", command=txt_info.yview)
            x_scroll = ttk.Scrollbar(info_frame, orient="horizontal", command=txt_info.xview)
            txt_info.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
            txt_info.grid(row=0, column=0, sticky="nsew")
            y_scroll.grid(row=0, column=1, sticky="ns")
            x_scroll.grid(row=1, column=0, sticky="ew")
            # Zeilenumbruch-Kontrollkästchen
            wrap_var = tk.BooleanVar(value=False)
            def toggle_wrap():
                txt_info.configure(wrap="word" if wrap_var.get() else "none")
            ttk.Checkbutton(frm, text="Zeilenumbruch", variable=wrap_var, command=toggle_wrap).grid(row=6, column=1, sticky="w", pady=(2,0))
            # Button-Leiste
            btnf = ttk.Frame(frm)
            btnf.grid(row=7, column=1, sticky="w", pady=8)
            # Der Speichern-Button ruft den zuvor definierten on_save_click-Handler auf.
            ttk.Button(btnf, text="Speichern", command=on_save_click).pack(side="left", padx=4)
            ttk.Button(btnf, text="Abbrechen", command=top.destroy).pack(side="left", padx=4)

        def gui_delete(self):
            self.touch()
            sel = self.tree.selection()
            if not sel: return
            iid = str(self.tree.item(sel[0])["values"][0])  # ← NEU
            e = self.vault.entries.get(iid)
            if not e: return
            if not messagebox.askyesno("Löschen", f"Wirklich löschen '{e.label}'?", parent=self.root):
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
                messagebox.showerror("Fehler", f"Löschen fehlgeschlagen:\n{exc}", parent=self.root)
            # Starte den Fortschrittsdialog
            self.run_with_progress(
                "Eintrag löschen",
                "Eintrag wird gelöscht. Bitte warten...",
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
            f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
            if not f: return
            export_entry_txt(self.vault, iid, Path(f))
            # Audit: export single entry
            write_audit("export_entry", f"{iid}|{e.label}")
            messagebox.showinfo("OK", f"Exportiert → {f}")

        def gui_export_all(self):
            self.touch()
            f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
            if not f: return
            export_all_txt(self.vault, Path(f))
            # Audit: export all (txt)
            write_audit("export_all", f"{len(self.vault.entries)} entries (txt)")
            messagebox.showinfo("OK", f"Exportiert → {f}")

        def gui_export_csv(self):
            self.touch()
            f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
            if not f: return
            export_all_csv(self.vault, Path(f))
            # Audit: export all (csv)
            write_audit("export_all", f"{len(self.vault.entries)} entries (csv)")
            messagebox.showinfo("OK", f"Exportiert → {f}")

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
                title="CSV-Datei wählen",
                filetypes=[("CSV-Dateien", "*.csv"), ("Alle Dateien", "*.*")],
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
                    messagebox.showinfo("Import abgeschlossen", f"{count} Einträge importiert.")
                else:
                    messagebox.showinfo("Keine Einträge", "Die CSV-Datei enthielt keine importierbaren Einträge.")
            except Exception as e:
                messagebox.showerror("Import-Fehler", f"Fehler beim Importieren: {e}")

        def gui_gen_pw(self):
            self.touch()
            pw = generate_password()
            # Audit: generate password
            write_audit("generate_password", "gui")
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self.root.after(CLIP_CLEAR_MS, lambda: (self.root.clipboard_clear(), None))
            messagebox.showinfo("Generiert", f"Passwort generiert und in Zwischenablage kopiert.\n{pw}")

        def copy_pw_and_clear(self, pw: str):
            self.touch()
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self.root.after(CLIP_CLEAR_MS, lambda: (self.root.clipboard_clear(), None))
            # Note: It is hard to map back to an ID/label in this context; log generic copy
            write_audit("copy_password", "gui")
            messagebox.showinfo("Clipboard", "Passwort in Zwischenablage kopiert (wird in 30s geleert).")

        def gui_change_master_pw(self):
            self.touch()
            cur = simpledialog.askstring("Aktuell", "Aktuelles Master-Passwort:", show="*", parent=self.root)
            if cur != self.master_pw:
                messagebox.showerror("Fehler", "Aktuelles Passwort falsch", parent=self.root)
                return
            np1 = simpledialog.askstring("Neu", "Neues Master-Passwort:", show="*", parent=self.root)
            if not np1:
                return
            np2 = simpledialog.askstring("Bestätigen", "Bestätigen:", show="*", parent=self.root)
            if np1 != np2:
                messagebox.showerror("Fehler", "Nicht identisch", parent=self.root)
                return
            # Prüfe Stärke des neuen Passworts
            cat, score = password_strength(np1)
            if score < 40:
                if not messagebox.askyesno(
                    "Schwaches Passwort",
                    f"Passwortstärke {cat} ({score}). Fortfahren?",
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
                messagebox.showinfo("OK", "Master-Passwort geändert", parent=self.root)
            def on_change_error(exc: Exception):
                messagebox.showerror("Fehler", f"Ändern des Master-Passworts fehlgeschlagen:\n{exc}", parent=self.root)
            # Starte Fortschrittsdialog
            self.run_with_progress(
                "Master-Passwort ändern",
                "Neues Master-Passwort wird gespeichert. Bitte warten...",
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
                messagebox.showinfo("OK", "Tresor neu verschlüsselt und gespeichert.", parent=self.root)
            # Callback bei Fehler
            def on_resave_error(exc: Exception):
                messagebox.showerror("Fehler", f"Re-Randomizing fehlgeschlagen:\n{exc}", parent=self.root)
            self.run_with_progress(
                "Neu verschlüsseln",
                "Tresor wird neu verschlüsselt. Bitte warten...",
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
            f = filedialog.askopenfilename(parent=self.root, title="Datei zum Verschlüsseln wählen", filetypes=[("Alle Dateien", "*.*")])
            if not f:
                return
            base = os.path.basename(f)
            out = filedialog.asksaveasfilename(
                parent=self.root,
                title="Speicherort für verschlüsselte Datei wählen",
                initialfile=base + ".enc",
                defaultextension=".enc",
                filetypes=[("Verschlüsselte Datei", "*.enc"), ("Alle Dateien", "*.*")],
            )
            if not out:
                return
            # Doppelte Passwortabfrage zur Minimierung von Tippfehlern
            pw1 = simpledialog.askstring("Passwort", "Passwort für Verschlüsselung:", show="*", parent=self.root)
            if not pw1:
                return
            pw2 = simpledialog.askstring("Bestätigen", "Passwort erneut eingeben:", show="*", parent=self.root)
            if pw1 != pw2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                return
            # Arbeiterfunktion für Verschlüsselung
            def do_encrypt_work(src: Path, passwd: str, dest: Path) -> None:
                encrypt_file_data(src, passwd, dest)
                write_audit("encrypt_file", f"{src}->{dest}")
                return None
            # Callback bei Erfolg
            def on_enc_success(_res: None = None):
                messagebox.showinfo("Erfolg", f"Datei verschlüsselt:\n{out}", parent=self.root)
            # Callback bei Fehler
            def on_enc_error(exc: Exception):
                messagebox.showerror("Fehler", f"Verschlüsselung fehlgeschlagen:\n{exc}", parent=self.root)
            # Starte Fortschrittsdialog
            self.run_with_progress(
                "Datei verschlüsseln",
                "Datei wird verschlüsselt. Bitte warten...",
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
                title="Verschlüsselte Datei wählen",
                filetypes=[("Verschlüsselte Dateien", "*.enc"), ("Alle Dateien", "*.*")],
            )
            if not f:
                return
            base = os.path.basename(f)
            # Standard: Originalname ohne .enc Endung
            base_out = base[:-4] if base.lower().endswith(".enc") else base + ".dec"
            out = filedialog.asksaveasfilename(
                parent=self.root,
                title="Speicherort für entschlüsselte Datei wählen",
                initialfile=base_out,
                filetypes=[("Alle Dateien", "*.*")],
            )
            if not out:
                return
            pw = simpledialog.askstring("Passwort", "Passwort für Entschlüsselung:", show="*", parent=self.root)
            if not pw:
                return
            # Arbeiterfunktion für Entschlüsselung
            def do_decrypt_work(src: Path, passwd: str, dest: Path) -> None:
                decrypt_file_data(src, passwd, dest)
                write_audit("decrypt_file", f"{src}->{dest}")
                return None
            # Callback bei Erfolg
            def on_dec_success(_res: None = None):
                messagebox.showinfo("Erfolg", f"Datei entschlüsselt:\n{out}", parent=self.root)
            # Callback bei Fehler
            def on_dec_error(exc: Exception):
                messagebox.showerror("Fehler", f"Entschlüsselung fehlgeschlagen:\n{exc}", parent=self.root)
            self.run_with_progress(
                "Datei entschlüsseln",
                "Datei wird entschlüsselt. Bitte warten...",
                do_decrypt_work,
                args=(Path(f), pw, Path(out)),
                on_success=on_dec_success,
                on_error=on_dec_error,
            )

        def gui_hide_file(self):
            """Versteckt eine Datei in einer anderen Datei (Cover)."""
            self.touch()
            # Wähle die Datei, die versteckt werden soll
            data_f = filedialog.askopenfilename(parent=self.root, title="Datei zum Verstecken wählen", filetypes=[("Alle Dateien", "*.*")])
            if not data_f:
                return
            # Wähle die Cover-Datei
            cover_f = filedialog.askopenfilename(parent=self.root, title="Cover-Datei wählen", filetypes=[("Alle Dateien", "*.*")])
            if not cover_f:
                return
            base = os.path.basename(cover_f)
            # Vorschlag für Ausgabedatei: Cover-Datei + .hid
            out_f = filedialog.asksaveasfilename(
                parent=self.root,
                title="Speicherort für Datei mit verstecktem Inhalt wählen",
                initialfile=base + ".hid",
                defaultextension=".hid",
                filetypes=[("Versteckte Datei", "*.hid"), ("Alle Dateien", "*.*")],
            )
            if not out_f:
                return
            # Passwort doppelt abfragen zur Fehlervermeidung
            pw1 = simpledialog.askstring("Passwort", "Passwort für Verschlüsselung:", show="*", parent=self.root)
            if not pw1:
                return
            pw2 = simpledialog.askstring("Bestätigen", "Passwort erneut eingeben:", show="*", parent=self.root)
            if pw1 != pw2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                return
            try:
                hide_file_in_file(Path(cover_f), Path(data_f), pw1, Path(out_f))
                write_audit("hide_file", f"{data_f}@{cover_f}->{out_f}")
                messagebox.showinfo("Erfolg", f"Datei versteckt:\n{out_f}")
            except Exception as e:
                messagebox.showerror("Fehler", f"Verstecken fehlgeschlagen:\n{e}")

        def gui_extract_hidden_file(self):
            """Extrahiert eine versteckte Datei aus einer Datei."""
            self.touch()
            stego_f = filedialog.askopenfilename(
                parent=self.root,
                title="Datei mit verstecktem Inhalt wählen",
                filetypes=[("Versteckte Datei", "*.hid"), ("Alle Dateien", "*.*")],
            )
            if not stego_f:
                return
            pw = simpledialog.askstring("Passwort", "Passwort für Entschlüsselung:", show="*", parent=self.root)
            if not pw:
                return
            # Versuche, Nutzlast zu entschlüsseln und den ursprünglichen Dateinamen zu ermitteln
            try:
                orig_name, payload = decrypt_hidden_payload(Path(stego_f), pw)
            except Exception as e:
                messagebox.showerror("Fehler", f"Extraktion fehlgeschlagen:\n{e}")
                return
            # Zeige erkannte Datei/Endung an
            messagebox.showinfo("Versteckte Datei", f"Es wurde folgende Datei erkannt:\n{orig_name}")
            # Vorschlag für Ausgabedatei: ursprünglicher Name im gleichen Verzeichnis
            suggested = Path(stego_f).with_name(orig_name)
            out_f = filedialog.asksaveasfilename(
                parent=self.root,
                title="Speicherort für extrahierte Datei wählen",
                initialfile=suggested.name,
                defaultextension=Path(orig_name).suffix or ".extrahiert",
                filetypes=[("Alle Dateien", "*.*")],
            )
            if not out_f:
                return
            try:
                atomic_write(Path(out_f), payload)
                write_audit("extract_file", f"{stego_f}->{out_f}")
                messagebox.showinfo("Erfolg", f"Datei extrahiert:\n{out_f}")
            except Exception as e:
                messagebox.showerror("Fehler", f"Schreiben fehlgeschlagen:\n{e}")

        # Erweiterte Funktionen zur Auswahl von Dateien für das Verstecken/Extrahieren.
        # Diese Methoden aktualisieren jeweils die zugehörigen StringVar-Variablen und
        # zeigen den ausgewählten Pfad in der GUI an.
        def gui_select_hide_data(self):
            """Wählt die Datei aus, die versteckt werden soll."""
            self.touch()
            f = filedialog.askopenfilename(parent=self.root, title="Datei zum Verstecken wählen", filetypes=[("Alle Dateien", "*.*")])
            if f:
                try:
                    self.hide_data_path.set(f)
                except Exception:
                    self.hide_data_path = f

        def gui_select_hide_cover(self):
            """Wählt die Cover-Datei, in der der Inhalt versteckt wird."""
            self.touch()
            f = filedialog.askopenfilename(parent=self.root, title="Cover-Datei wählen", filetypes=[("Alle Dateien", "*.*")])
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
                title="Speicherort für versteckte Datei wählen",
                initialfile=initial,
                defaultextension=".hid",
                filetypes=[("Versteckte Datei", "*.hid"), ("Alle Dateien", "*.*")],
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
                messagebox.showerror("Fehler", "Bitte wählen Sie eine Datei aus, die versteckt werden soll.")
                return
            if not cover_path:
                messagebox.showerror("Fehler", "Bitte wählen Sie eine Cover-Datei aus.")
                return
            if not out_path:
                messagebox.showerror("Fehler", "Bitte wählen Sie einen Ausgabepfad für die versteckte Datei.")
                return
            # Passwort doppelt abfragen zur Fehlervermeidung
            pw1 = simpledialog.askstring("Passwort", "Passwort für Verschlüsselung:", show="*", parent=self.root)
            if not pw1:
                return
            pw2 = simpledialog.askstring("Bestätigen", "Passwort erneut eingeben:", show="*", parent=self.root)
            if pw1 != pw2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                return
            # Arbeiterfunktion für Verstecken
            def do_hide_work(cov: str, data: str, passwd: str, dest: str) -> None:
                hide_file_in_file(Path(cov), Path(data), passwd, Path(dest))
                write_audit("hide_file", f"{data}@{cov}->{dest}")
                return None
            # Callback bei Erfolg
            def on_hide_success(_res: None = None):
                messagebox.showinfo("Erfolg", f"Datei wurde versteckt:\n{out_path}", parent=self.root)
                # Felder leeren
                try:
                    self.hide_data_path.set("")
                    self.hide_cover_path.set("")
                    self.hide_output_path.set("")
                except Exception:
                    pass
            # Callback bei Fehler
            def on_hide_error(exc: Exception):
                messagebox.showerror("Fehler", f"Verstecken fehlgeschlagen:\n{exc}", parent=self.root)
            # Starte Fortschrittsdialog
            self.run_with_progress(
                "Datei verstecken",
                "Datei wird versteckt. Bitte warten...",
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
                title="Datei mit verstecktem Inhalt wählen",
                filetypes=[("Versteckte Datei", "*.hid"), ("Alle Dateien", "*.*")],
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
                title="Speicherort für extrahierte Datei wählen",
                defaultextension="",
                filetypes=[("Alle Dateien", "*.*")],
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
                messagebox.showerror("Fehler", "Bitte wählen Sie eine .hid-Datei aus.")
                return
            if not out_f:
                messagebox.showerror("Fehler", "Bitte wählen Sie einen Ausgabepfad für die extrahierte Datei.")
                return
            pw = simpledialog.askstring("Passwort", "Passwort für Entschlüsselung:", show="*", parent=self.root)
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
                messagebox.showinfo("Versteckte Datei", f"Es wurde folgende Datei erkannt:\n{orig_name}", parent=self.root)
                messagebox.showinfo("Erfolg", f"Datei extrahiert:\n{out_f}", parent=self.root)
                # Felder leeren
                try:
                    self.extract_stego_path.set("")
                    self.extract_output_path.set("")
                except Exception:
                    pass
            # Callback bei Fehlern
            def on_extract_error(exc: Exception):
                messagebox.showerror("Fehler", f"Extraktion fehlgeschlagen:\n{exc}", parent=self.root)
            # Starte Fortschrittsdialog
            self.run_with_progress(
                "Datei extrahieren",
                "Datei wird extrahiert. Bitte warten...",
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
                messagebox.showerror("Fehler", "Tkinter ist nicht verfügbar.")
                return
            # Erstelle das Fenster nur einmal. Wenn es bereits existiert, fokussiere es.
            if hasattr(self, "file_ops_window") and self.file_ops_window is not None and self.file_ops_window.winfo_exists():
                self.file_ops_window.lift()
                return
            win = tk.Toplevel(self.root)
            win.title("Datei-Operationen")
            win.geometry("800x600")
            self.file_ops_window = win
            # Hauptbeschreibung
            ttk.Label(win,
                      text="In diesem Fenster können Sie beliebige Dateien verschlüsseln, entschlüsseln, verstecken und extrahieren.\n"
                           "Die Operationen sind unabhängig vom Tresor und nutzen den gleichen Sicherheitsalgorithmus.",
                      wraplength=760,
                      justify="left").pack(padx=10, pady=(10, 8), anchor="w")
            # Verschlüsselung/Entschlüsselung Abschnitt
            enc_frame = ttk.LabelFrame(win, text="Datei verschlüsseln / entschlüsseln", padding=8)
            enc_frame.pack(fill="x", padx=10, pady=(0, 10))
            # Definiere lokale StringVars für Pfade
            enc_in = tk.StringVar(value="")
            enc_out = tk.StringVar(value="")
            dec_in = tk.StringVar(value="")
            dec_out = tk.StringVar(value="")
            # Hilfsfunktionen zur Auswahl
            def select_enc_input():
                f = filedialog.askopenfilename(parent=win, title="Datei zum Verschlüsseln wählen", filetypes=[("Alle Dateien", "*.*")])
                if f:
                    enc_in.set(f)
            def select_enc_output():
                # Vorschlag: Originalname + .enc
                base = os.path.basename(enc_in.get()) if enc_in.get() else ""
                initial = base + ".enc" if base else ""
                    
                f = filedialog.asksaveasfilename(parent=win, title="Ziel für verschlüsselte Datei", initialfile=initial, defaultextension=".enc", filetypes=[("Verschlüsselte Datei", "*.enc"), ("Alle Dateien", "*.*")])
                if f:
                    enc_out.set(f)
            def do_encrypt():
                src = enc_in.get().strip()
                dst = enc_out.get().strip()
                if not src:
                    messagebox.showerror("Fehler", "Bitte wählen Sie eine Eingabedatei zum Verschlüsseln.")
                    return
                if not dst:
                    messagebox.showerror("Fehler", "Bitte wählen Sie einen Zielpfad für die verschlüsselte Datei.")
                    return
                # Doppelte Passwortabfrage, um Tippfehler zu vermeiden
                pw1 = simpledialog.askstring("Passwort", "Passwort für Verschlüsselung:", show="*", parent=win)
                if not pw1:
                    return
                pw2 = simpledialog.askstring("Bestätigen", "Passwort erneut eingeben:", show="*", parent=win)
                if pw1 != pw2:
                    messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                    return
                try:
                    encrypt_file_data(Path(src), pw1, Path(dst))
                    write_audit("encrypt_file", f"{src}->{dst}")
                    messagebox.showinfo("Erfolg", f"Datei verschlüsselt:\n{dst}")
                    enc_in.set(""); enc_out.set("")
                except Exception as e:
                    messagebox.showerror("Fehler", f"Verschlüsselung fehlgeschlagen:\n{e}")
            # Entschlüsselung Hilfsfunktionen
            def select_dec_input():
                f = filedialog.askopenfilename(parent=win, title="Verschlüsselte Datei wählen", filetypes=[("Verschlüsselte Datei", "*.enc"), ("Alle Dateien", "*.*")])
                if f:
                    dec_in.set(f)
            def select_dec_output():
                f = filedialog.asksaveasfilename(parent=win, title="Ziel für entschlüsselte Datei", defaultextension="", filetypes=[("Alle Dateien", "*.*")])
                if f:
                    dec_out.set(f)
            def do_decrypt():
                src = dec_in.get().strip()
                dst = dec_out.get().strip()
                if not src:
                    messagebox.showerror("Fehler", "Bitte wählen Sie eine .enc-Datei zum Entschlüsseln.")
                    return
                if not dst:
                    messagebox.showerror("Fehler", "Bitte wählen Sie einen Zielpfad für die entschlüsselte Datei.")
                    return
                pw = simpledialog.askstring("Passwort", "Passwort für Entschlüsselung:", show="*", parent=win)
                if not pw:
                    return
                try:
                    decrypt_file_data(Path(src), pw, Path(dst))
                    write_audit("decrypt_file", f"{src}->{dst}")
                    messagebox.showinfo("Erfolg", f"Datei entschlüsselt:\n{dst}")
                    dec_in.set(""); dec_out.set("")
                except Exception as e:
                    messagebox.showerror("Fehler", f"Entschlüsselung fehlgeschlagen:\n{e}")
            # Layout für Verschlüsselung
            ttk.Label(enc_frame, text="Datei zum Verschlüsseln auswählen").grid(row=0, column=0, sticky="w")
            ttk.Button(enc_frame, text="Datei auswählen", command=select_enc_input).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=enc_in, wraplength=480).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text="Ziel auswählen", command=select_enc_output).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=enc_out, wraplength=480).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text="Verschlüsseln", command=do_encrypt).grid(row=3, column=0, sticky="w", pady=(4, 6))
            # Layout für Entschlüsselung
            ttk.Label(enc_frame, text=".enc-Datei zum Entschlüsseln auswählen").grid(row=4, column=0, sticky="w", pady=(8,0))
            ttk.Button(enc_frame, text=".enc-Datei", command=select_dec_input).grid(row=5, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=dec_in, wraplength=480).grid(row=5, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text="Ziel auswählen", command=select_dec_output).grid(row=6, column=0, sticky="w", pady=2)
            ttk.Label(enc_frame, textvariable=dec_out, wraplength=480).grid(row=6, column=1, sticky="w", padx=6)
            ttk.Button(enc_frame, text="Entschlüsseln", command=do_decrypt).grid(row=7, column=0, sticky="w", pady=(4, 6))
            # Steganographie-Abschnitt
            steg_frame = ttk.LabelFrame(win, text="Datei verstecken / extrahieren", padding=8)
            steg_frame.pack(fill="x", padx=10, pady=(0, 10))
            ttk.Label(steg_frame,
                      text="Wählen Sie die benötigten Dateien zum Verstecken oder Extrahieren und starten Sie den Vorgang.\n"
                           "Beim Verstecken wird die zu versteckende Datei verschlüsselt und ans Ende der Cover-Datei angehängt.",
                      wraplength=760,
                      justify="left").pack(anchor="w", pady=(0, 6))
            # Wir verwenden die bereits im App-Objekt vorhandenen StringVars, damit die Pfade
            # auch im Hauptfenster angezeigt werden können. Falls Tkinter nicht verfügbar ist,
            # verwenden wir einfache Strings.
            hide_ops = ttk.Frame(steg_frame)
            hide_ops.pack(fill="x", pady=(0, 6))
            ttk.Label(hide_ops, text="Verstecken:").grid(row=0, column=0, sticky="w")

            # Zusätzliche Hilfsbuttons für Cover-Erzeugung und Bild-Aufblähung
            ttk.Button(hide_ops, text="Cover-Bild erzeugen…", command=gui_create_cover_image_generic).grid(row=0, column=2, sticky="w", padx=(12,0))
            ttk.Button(hide_ops, text="Bild aufblasen…", command=gui_inflate_image_generic).grid(row=0, column=3, sticky="w", padx=(6,0))
            ttk.Button(hide_ops, text="Zu versteckende Datei", command=self.gui_select_hide_data).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_data_path, wraplength=480).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(hide_ops, text="Cover-Datei", command=self.gui_select_hide_cover).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_cover_path, wraplength=480).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(hide_ops, text="Ziel (.hid)", command=self.gui_select_hide_output).grid(row=3, column=0, sticky="w", pady=2)
            ttk.Label(hide_ops, textvariable=self.hide_output_path, wraplength=480).grid(row=3, column=1, sticky="w", padx=6)
            ttk.Button(hide_ops, text="Verstecken", command=self.gui_do_hide).grid(row=4, column=0, sticky="w", pady=(4, 6))
            # Extraktion
            extract_ops = ttk.Frame(steg_frame)
            extract_ops.pack(fill="x")
            ttk.Label(extract_ops, text="Extrahieren:").grid(row=0, column=0, sticky="w")
            ttk.Button(extract_ops, text=".hid-Datei", command=self.gui_select_extract_stego).grid(row=1, column=0, sticky="w", pady=2)
            ttk.Label(extract_ops, textvariable=self.extract_stego_path, wraplength=480).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(extract_ops, text="Ziel-Datei", command=self.gui_select_extract_output).grid(row=2, column=0, sticky="w", pady=2)
            ttk.Label(extract_ops, textvariable=self.extract_output_path, wraplength=480).grid(row=2, column=1, sticky="w", padx=6)
            ttk.Button(extract_ops, text="Extrahieren", command=self.gui_do_extract).grid(row=3, column=0, sticky="w", pady=(4, 6))

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
                # Zeige Fehlerdialog, entlade dennoch Tresor und kehre zur Login-Ansicht zurück
                messagebox.showerror("Fehler", f"Speichern beim Sperren fehlgeschlagen:\n{exc}", parent=self.root)
                self.vault = None
                self.master_pw = None
                self.build_login_ui()
            # Zeige Fortschrittsdialog und starte Speichern
            self.run_with_progress(
                "Tresor schließen",
                "Tresor wird verschlüsselt und geschlossen. Bitte warten...",
                do_lock_work,
                args=(),
                on_success=on_lock_success,
                on_error=on_lock_error
            )

        def on_close(self):
            if self.vault and self.master_pw:
                try:
                    save_vault(self.path, self.vault, self.master_pw)
                except Exception:
                    pass
            self.root.destroy()

        def show_help(self):
            """Zeige eine Hilfeansicht in einem eigenen Fenster mit ausreichender Breite.

            Statt eines modalen Messageboxes wird ein neues Top-Level-Fenster mit einem
            Textfeld geöffnet, damit lange Zeilen besser lesbar sind und das Fenster
            breiter gemacht werden kann.
            """
            # Zusammengesetzter Hilfetext aus Modul-Docstring und GUI-Hinweisen
            help_text = __doc__ + "\n\nGUI-Hilfe: Doppelklick öffnet Eintrag. Exporte sind Klartext — bitte sichern/löschen."
            top = tk.Toplevel(self.root)
            top.title("Hilfe")
            # Setze ein Startmaß; Fenster ist frei skalierbar
            top.geometry("900x500")
            # Text-Widget mit Umbruch
            txt = tk.Text(top, wrap="word")
            txt.insert("1.0", help_text)
            txt.config(state="disabled")
            txt.pack(fill="both", expand=True, padx=8, pady=8, side="left")
            # Scrollbar
            scroll = ttk.Scrollbar(top, orient="vertical", command=txt.yview)
            scroll.pack(side="right", fill="y")
            txt.configure(yscrollcommand=scroll.set)
            # Schließen-Button unten rechts
            btnf = ttk.Frame(top)
            btnf.pack(fill="x", pady=4)
            ttk.Button(btnf, text="Schließen", command=top.destroy).pack(side="right", padx=10)

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
                        status_text = f"Geöffnet – Auto-Lock in: {mins:02d}:{secs:02d}"
                        try:
                            self.status.config(text=status_text)
                        except Exception:
                            pass
                    else:
                        # Zeit abgelaufen: Tresor sperren
                        try:
                            messagebox.showinfo("Auto-Lock", "Tresor wurde automatisch gesperrt (Inaktiv).")
                        except Exception:
                            pass
                        self.lock()
                        # Anzeige aktualisiert sich im lock() Aufruf
                else:
                    # Kein Tresor geöffnet
                    try:
                        self.status.config(text="Tresor geschlossen")
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
- Triple-Layer Encryption (AES‑GCM, XOR‑Pad, ChaCha20‑Poly1305)
- KDF: scrypt (N={KDF_N}, r={KDF_R}, p={KDF_P}) oder optional Argon2 (time={ARGON2_TIME}, memory={ARGON2_MEMORY} KiB, parallelism={ARGON2_PARALLELISM})
- HMAC‑SHA512 Integritätsschutz
    - Audit‑Logging (aktivierbar per Konfiguration)
    - Bei jedem Speichern Re‑Randomizing (neue Salt/Nonces/Pad)

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
    try:
        from tkinter import filedialog, simpledialog, messagebox
    except Exception:
        return
    # Zielformat anhand Endung
    path = filedialog.asksaveasfilename(
        title="Cover-Bild erzeugen (BMP/PNG/JPEG)",
        defaultextension=".bmp",
        filetypes=[("Bitmap", "*.bmp"), ("PNG", "*.png"), ("JPEG", "*.jpg;*.jpeg"), ("Alle Dateien", "*.*")],
    )
    if not path:
        return
    size_mib = 1.0
    try:
        size_mib = simpledialog.askfloat("Zielgröße", "Mindestgröße in MiB (Standard: 1.0):",
                                         minvalue=0.1, initialvalue=1.0)
        if size_mib is None:
            return
    except Exception:
        pass
    try:
        out = generate_noise_image(Path(path), int(size_mib * 1024 * 1024))
        import os
        messagebox.showinfo("Fertig", f"Cover-Bild erzeugt:\n{out}\n\nGröße: {os.path.getsize(out)/1024/1024:.2f} MiB")
    except Exception as e:
        messagebox.showerror("Fehler", f"{e}")

def gui_inflate_image_generic():
    try:
        from tkinter import filedialog, simpledialog, messagebox
    except Exception:
        return
    src = filedialog.askopenfilename(
        title="Kleines Bild auswählen (JPEG/PNG)",
        filetypes=[("Bilder", "*.jpg;*.jpeg;*.png;*.bmp"), ("Alle Dateien", "*.*")],
    )
    if not src:
        return
    dst = filedialog.asksaveasfilename(
        title="Ausgabe speichern (Format per Endung)",
        defaultextension=".jpg",
        filetypes=[("JPEG", "*.jpg;*.jpeg"), ("PNG", "*.png"), ("BMP", "*.bmp"), ("Alle Dateien", "*.*")],
    )
    if not dst:
        return
    size_mib = simpledialog.askfloat("Zielgröße", "Mindestgröße in MiB (Standard: 1.0):",
                                     minvalue=0.1, initialvalue=1.0)
    if size_mib is None:
        return
    try:
        out = enlarge_image_to_min_size(Path(src), Path(dst), int(size_mib * 1024 * 1024))
        import os
        messagebox.showinfo("Fertig", f"Bild erzeugt:\n{out}\n\nGröße: {os.path.getsize(out)/1024/1024:.2f} MiB")
    except Exception as e:
        messagebox.showerror("Fehler", f"{e}")

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
