"""
ByteGuard - analyzer.py
Motore di analisi forense scritto in Python.
Viene invocato dal backend C# (o dal Watchdog Go) come processo isolato.
Riceve il percorso del file come argomento (sys.argv[1]) e stampa ESCLUSIVAMENTE un JSON su stdout.
Ho scelto di non usare librerie esterne per l'analisi, appoggiandomi solo alla Standard Library di Python.
"""

import sys
import os
import io
import json
import math
import datetime
import logging
import warnings


# Per evitare crash durante la lettura di percorsi con caratteri speciali (soprattutto su Windows che usa cp1252),
# ho forzato lo standard output a usare la codifica UTF-8. Questo garantisce che la comunicazione IPC verso Go o C# non si corrompa.
try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)
except AttributeError:
    pass


# Ho implementato questa configurazione del logger per deviare qualsiasi warning (es. deprecazioni interne di Python)
# verso un file di log separato ("byteguard_warnings.log"). È vitale perché se un warning finisse su stdout,
# distruggerebbe la struttura del JSON inviato tramite IPC, mandando in errore il parser di C#.
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "byteguard_warnings.log")
logging.basicConfig(
    filename=log_path,
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.captureWarnings(True)


# Dizionario dei Magic Bytes per le firme dei file.
# Ho mappato manualmente i byte iniziali che identificano univocamente la reale natura di un file.
# Nota tecnica: i file di testo (.txt, .json, .csv) non hanno un magic byte standard, quindi li gestirò con una logica a esclusione.
MAGIC_NUMBERS: dict[str, bytes] = {
    ".pdf":  b"%PDF-",
    ".png":  b"\x89PNG\r\n\x1a\n",
    ".jpg":  b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".zip":  b"PK\x03\x04",
    ".exe":  b"MZ",
    ".dll":  b"MZ",          
    ".sys":  b"MZ",          
    ".elf":  b"\x7fELF",
    ".docx": b"PK\x03\x04",  # Anche i file Office moderni sono sostanzialmente archivi ZIP
    ".xlsx": b"PK\x03\x04",  
    ".gz":   b"\x1f\x8b",
}

# 16 byte sono più che sufficienti per catturare la quasi totalità degli header noti.
MAGIC_BYTES_READ_COUNT = 16

# Ho inserito questa soglia (100 MB) per il campionamento dell'entropia.
# Se provassi a calcolare l'entropia esatta di un file di svariati Giga caricandolo in RAM, causerei un OutOfMemoryError.
SAMPLING_THRESHOLD_BYTES = 100 * 1024 * 1024


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calcolo dell'Entropia di Shannon (misura del disordine dei dati).
    Ho implementato l'algoritmo classico che itera sui byte e calcola le probabilità.

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


def check_double_extension(file_name: str) -> bool:
    """
    Verifica se il file ha una doppia estensione usata per camuffamento (es. 'documento.pdf.exe').
    Ignora file nascosti e compound legittimi come '.tar.gz'.
    """
    # Ignoriamo il punto iniziale dei file nascosti Linux/Mac
    if file_name.startswith('.'):
        file_name = file_name[1:]
        
    parts = file_name.split('.')
    if len(parts) >= 3:
        inner_ext = f".{parts[-2]}".lower()
        outer_ext = f".{parts[-1]}".lower()
        
        # Eccezioni legittime comuni
        if inner_ext == ".tar" and outer_ext in [".gz", ".xz", ".bz2"]:
            return False
            
        # Elenco di estensioni spesso usate per ingannare l'utente
        spoofed_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".zip", ".csv"}
        if inner_ext in spoofed_exts:
            return True
            
    return False


def get_expected_profile(extension: str) -> str:
    """Restituisce il profilo di entropia atteso per una data estensione."""
    ext = (extension or "").lower()
    if ext in [".pdf", ".zip", ".gz", ".docx", ".xlsx", ".jpg", ".jpeg", ".png"]:
        return "COMPRESSED"
    if ext in [".exe", ".elf", ".dll", ".sys"]:
        return "EXECUTABLE"
    if ext in [".txt", ".json", ".xml", ".csv", ".html"]:
        return "TEXT"
    return "EXECUTABLE"  # default conservativo per tipi non noti

def evaluate_forensic_verdict(entropy: float, extension_match: bool, extension: str, has_double_ext: bool) -> tuple[bool, str, str]:
    """
    Applica le regole euristiche per determinare se il file e' anomalo,
    basandosi sull'entropia e sull'eventuale spoofing dell'estensione.
    Restituisce (is_anomalous, verdict, anomaly_code).
    """
    if has_double_ext:
        return True, "Doppia estensione sospetta (possibile camuffamento)", "DOUBLE_EXTENSION"

    if not extension_match:
        return True, "File camuffato (Magic bytes errati)", "MAGIC_MISMATCH"
        
    profile = get_expected_profile(extension)
    
    if profile == "TEXT":
        if entropy > 6.5:
            return True, "Entropia troppo alta per un testo", "HIGH_ENTROPY"
        if entropy < 1.0:
            return True, "Testo anomalo (ripetizioni o padding nullo)", "LOW_ENTROPY"
            
    elif profile == "EXECUTABLE":
        if entropy > 7.2:
            return True, "Possibile eseguibile packed/offuscato", "HIGH_ENTROPY"
        if entropy < 3.0:
            return True, "Eseguibile anomalo (entropia bassissima)", "LOW_ENTROPY"
            
    elif profile == "COMPRESSED":
        if entropy < 6.0:
            return True, "Falso compresso (entropia bassissima)", "LOW_ENTROPY"
        if entropy > 7.98:
            return True, "File fortemente cifrato (entropia estrema)", "EXTREME_ENTROPY"
            
    return False, "Sano", "NONE"


def read_sampled_content(f: io.BufferedReader, file_size: int) -> bytes:
    """
    Legge tre chunk dal file (inizio, meta', fine) calcolandone dinamicamente
    la dimensione in percentuale rispetto al file totale.
    """
    # Chunk dinamico: 1% della dimensione del file per ogni chunk (totale 3%).
    # Limiti di sicurezza RAM: minimo 1 MB, massimo 50 MB a chunk.
    # Es. File da 10 GB -> 1% = 100 MB -> Capped a 50 MB -> Totale RAM usata: 150 MB.
    base_chunk_size = int(file_size * 0.01)
    min_chunk = 1 * 1024 * 1024   # 1 MB
    max_chunk = 50 * 1024 * 1024  # 50 MB
    chunk_size = max(min_chunk, min(base_chunk_size, max_chunk))
    
    chunks = bytearray()

    positions = [
        0,                                        # inizio
        max(0, file_size // 2 - chunk_size // 2), # meta'
        max(0, file_size - chunk_size),           # fine
    ]

    seen: set[int] = set()
    for pos in positions:
        if pos in seen:
            continue  # evita duplicati su file piccoli
        seen.add(pos)
        f.seek(pos)
        chunks += f.read(chunk_size)

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


SUPPORTED_EXTENSIONS = {
    ".pdf", ".zip", ".gz", ".docx", ".xlsx", ".jpg", ".jpeg", ".png",
    ".exe", ".elf", ".dll", ".sys",
    ".txt", ".json", ".xml", ".csv", ".html"
}

def analyze_file(file_path: str) -> dict:
    """Apre il file in modalita' binaria, calcola entropia e magic numbers, restituisce il payload."""
    abs_path = os.path.abspath(file_path)
    file_name = os.path.basename(abs_path)
    _, extension = os.path.splitext(abs_path)
    file_size = os.path.getsize(abs_path)
    
    ext_lower = extension.lower() if extension else "(none)"
    
    # Ignoriamo i file non supportati, restituendo un payload speciale
    if ext_lower not in SUPPORTED_EXTENSIONS:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "file_path": abs_path,
            "file_size_bytes": file_size,
            "declared_extension": ext_lower,
            "shannon_entropy": 0.0,
            "entropy_sampled": False,
            "has_double_extension": False,
            "magic_number_hex": None,
            "magic_number_ascii": None,
            "extension_match": False,
            "is_anomalous": False,
            "verdict": "Ignorato (estensione non supportata)",
            "anomaly_code": "IGNORED",
            "analysis_status": "ignored",
            "error_message": None,
            "timestamp_utc": timestamp,
        }

    has_double_ext = check_double_extension(file_name)

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
    
    is_anomalous, verdict, anomaly_code = evaluate_forensic_verdict(entropy, magic_info["extension_match"], extension, has_double_ext)
    
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "file_path": abs_path,
        "file_size_bytes": file_size,
        "declared_extension": extension if extension else "(none)",
        "shannon_entropy": round(entropy, 6),
        "entropy_sampled": entropy_sampled,  # True = valore approssimato (file > 100 MB)
        "has_double_extension": has_double_ext,
        **magic_info,
        "is_anomalous": is_anomalous,
        "verdict": verdict,
        "anomaly_code": anomaly_code,
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
        "has_double_extension": False,
        "magic_number_hex": None,
        "magic_number_ascii": None,
        "extension_match": False,
        "is_anomalous": True,
        "verdict": "Errore di analisi",
        "anomaly_code": "ANALYSIS_ERROR",
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
