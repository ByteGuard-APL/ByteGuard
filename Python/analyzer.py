"""
ByteGuard - analyzer.py
Motore di analisi forense. Lanciato da C# come sottoprocesso:
riceve il percorso di un file via sys.argv[1] e stampa UN SOLO JSON su stdout.
Nessuna UI, nessuna dipendenza esterna (solo stdlib).
"""

import sys
import os
import io
import json
import math
import datetime


# Su Windows la console usa cp1252 di default, che non copre tutti i caratteri Unicode.
# Sostituiamo sys.stdout con un wrapper UTF-8 esplicito per evitare UnicodeEncodeError
# su percorsi con caratteri accentati o simboli nei magic bytes.
try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)
except AttributeError:
    pass  # stdout non e' una pipe (es. esecuzione in unit test): nessun problema


# Mappa estensione -> magic bytes attesi all'inizio del file.
# Se il file non inizia con questi byte, l'estensione e' probabilmente falsa.
MAGIC_NUMBERS: dict[str, bytes] = {
    ".pdf":  b"%PDF-",
    ".png":  b"\x89PNG\r\n\x1a\n",
    ".jpg":  b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".zip":  b"PK\x03\x04",
    ".exe":  b"MZ",
    ".elf":  b"\x7fELF",
    ".docx": b"PK\x03\x04",  # docx e' un archivio zip rinominato
    ".gz":   b"\x1f\x8b",
}

# Quanti byte leggere per il riconoscimento del magic number
MAGIC_BYTES_READ_COUNT = 16

# Soglia oltre la quale si usa il campionamento invece della lettura completa.
# Sotto questa dimensione il file viene letto intero: e' veloce e preciso al 100%.
SAMPLING_THRESHOLD_BYTES = 100 * 1024 * 1024  # 100 MB

# Dimensione di ogni chunk campionato. Con 3 chunks da 1 MB si leggono in totale
# 3 MB indipendentemente da quanto e' grande il file (100 MB, 10 GB: uguale).
SAMPLE_CHUNK_BYTES = 1 * 1024 * 1024  # 1 MB per chunk


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calcola l'entropia di Shannon dei byte del file (range 0.0 - 8.0 bit/simbolo).

    Valori guida:
        < 5.5   -> testo o dati strutturati semplici
        5.5-7.0 -> file compresso o denso
        > 7.0   -> alta casualita': possibile cifratura o offuscamento (flag forense)

    Formula: H = -sum( p(x) * log2(p(x)) ) per ogni byte distinto x.
    """
    if not data:
        return 0.0

    byte_counts: dict[int, int] = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1

    total = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def read_sampled_content(f: io.RawIOBase, file_size: int) -> bytes:
    """
    Legge tre chunk dal file (inizio, meta', fine) e li concatena.
    Usato per file grandi al posto della lettura completa.

    Perche' 3 zone e non una sola?
    - I file cifrati o compressi hanno distribuzione uniforme ovunque:
      qualsiasi zona e' rappresentativa. Ma per file strutturati (es. ISO,
      database) le zone hanno caratteristiche diverse: campionare solo
      l'inizio darebbe un risultato distorto.
    - Inizio + meta' + fine bilancia copertura e velocita'.

    Limite noto: un payload cifrato nascosto SOLO nella zona centrale di un
    file altrimenti normale potrebbe sfuggire se i chunk non lo coprono.
    Per analisi forensi ad alta precisione, usare la lettura completa.
    """
    chunks = bytearray()

    positions = [
        0,                              # inizio
        max(0, file_size // 2 - SAMPLE_CHUNK_BYTES // 2),  # meta'
        max(0, file_size - SAMPLE_CHUNK_BYTES),             # fine
    ]

    seen: set[int] = set()
    for pos in positions:
        if pos in seen:
            continue  # evita duplicati su file piccoli (non dovrebbe accadere sopra soglia)
        seen.add(pos)
        f.seek(pos)
        chunks += f.read(SAMPLE_CHUNK_BYTES)

    return bytes(chunks)


def analyze_magic_numbers(header_bytes: bytes, declared_extension: str) -> dict:
    """
    Legge i primi byte del file e verifica che corrispondano all'estensione dichiarata.
    Se non corrispondono, il file potrebbe avere l'estensione cambiata per nascondersi.
    """
    normalized_ext = declared_extension.lower()
    
    # 1. Se l'estensione ha un magic byte fisso noto, DEVE coincidere.
    if normalized_ext in MAGIC_NUMBERS:
        extension_match = header_bytes.startswith(MAGIC_NUMBERS[normalized_ext])
        magic_hex = header_bytes.hex().upper()
        magic_ascii = header_bytes.decode("ascii", errors="replace").replace("\x00", ".").strip()
    else:
        # 2. Per file senza magic bytes (es. testo puro, .csv, .json),
        # controlliamo che NON siano file binari noti mascherati (es. un .exe rinominato in .txt).
        spoofed_as = None
        for known_ext, known_magic in MAGIC_NUMBERS.items():
            if header_bytes.startswith(known_magic):
                spoofed_as = known_ext
                break
                
        if spoofed_as:
            # E' un file binario camuffato!
            extension_match = False
            magic_hex = header_bytes.hex().upper()
            magic_ascii = header_bytes.decode("ascii", errors="replace").replace("\x00", ".").strip()
        else:
            # E' legittimamente un file senza magic bytes.
            extension_match = True
            magic_hex = "Nessun magic byte atteso per questo formato"
            magic_ascii = "N/A"

    return {
        "magic_number_hex": magic_hex,
        "magic_number_ascii": magic_ascii,
        "extension_match": extension_match,
    }


def analyze_file(file_path: str) -> dict:
    """Apre il file in modalita' binaria, calcola entropia e magic numbers, restituisce il payload."""
    abs_path = os.path.abspath(file_path)
    _, extension = os.path.splitext(abs_path)
    file_size = os.path.getsize(abs_path)

    # 'rb' e' obbligatorio: nessuna decodifica testo, legge byte grezzi
    with open(abs_path, "rb") as f:
        # I magic bytes vengono sempre letti dall'inizio del file, indipendentemente
        # dalla dimensione: servono pochi byte e non costano nulla.
        header_bytes = f.read(MAGIC_BYTES_READ_COUNT)

        # Per l'entropia scegliamo la strategia in base alla dimensione:
        # - file piccoli (<= 100 MB): lettura completa, risultato esatto
        # - file grandi (> 100 MB): campionamento 3 zone, risultato approssimato ma affidabile
        if file_size <= SAMPLING_THRESHOLD_BYTES:
            f.seek(0)
            content_for_entropy = f.read()
            entropy_sampled = False
        else:
            content_for_entropy = read_sampled_content(f, file_size)
            entropy_sampled = True

    entropy = calculate_shannon_entropy(content_for_entropy)
    magic_info = analyze_magic_numbers(header_bytes, extension)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "file_path": abs_path,
        "file_size_bytes": file_size,
        "declared_extension": extension if extension else "(none)",
        "shannon_entropy": round(entropy, 6),
        "entropy_sampled": entropy_sampled,  # True = valore approssimato (file > 100 MB)
        **magic_info,
        "analysis_status": "success",
        "error_message": None,
        "timestamp_utc": timestamp,
    }


def build_error_payload(file_path: str, error: Exception) -> dict:
    """
    Costruisce un payload di errore in formato JSON standard.
    Gli errori vanno sempre su stdout come JSON, mai su stderr come testo libero:
    cosi' C# usa sempre lo stesso codice per leggere l'output, successo o meno.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "file_path": os.path.abspath(file_path) if file_path else "unknown",
        "file_size_bytes": 0,
        "declared_extension": None,
        "shannon_entropy": 0.0,
        "entropy_sampled": False,
        "magic_number_hex": None,
        "magic_number_ascii": None,
        "extension_match": False,
        "analysis_status": "error",
        "error_message": f"{type(error).__name__}: {str(error)}",
        "timestamp_utc": timestamp,
    }


if __name__ == "__main__":
    # sys.argv[1] e' il percorso del file passato da C#
    if len(sys.argv) < 2:
        print(json.dumps(build_error_payload("unknown", ValueError("Usage: python analyzer.py <file_path>"))))
        sys.exit(1)

    target_file_path = sys.argv[1]
    result_payload: dict

    try:
        result_payload = analyze_file(target_file_path)
    except FileNotFoundError as e:
        result_payload = build_error_payload(target_file_path, e)
    except PermissionError as e:
        result_payload = build_error_payload(target_file_path, e)
    except IsADirectoryError as e:
        result_payload = build_error_payload(target_file_path, e)
    except OSError as e:
        result_payload = build_error_payload(target_file_path, e)
    except Exception as e:
        # Catch-all: nessuna eccezione deve finire su stderr come testo libero
        result_payload = build_error_payload(target_file_path, e)

    # Una sola riga JSON compatta su stdout: ensure_ascii=False preserva i caratteri Unicode
    print(json.dumps(result_payload, ensure_ascii=False, separators=(",", ":")))
    sys.exit(0 if result_payload["analysis_status"] == "success" else 1)
