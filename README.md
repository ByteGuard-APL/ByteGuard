# ByteGuard

ByteGuard è un'applicazione desktop scritta in C# (WPF) per l'analisi forense e la crittografia dei file. Sfrutta moduli esterni scritti in Go e Python per gestire carichi di lavoro intensivi e operazioni specifiche sul file system.

## 📋 Requisiti di Sistema

Per compilare ed eseguire il progetto partendo dal codice sorgente, sono necessari:
- **.NET 10.0 SDK** (per l'interfaccia grafica C# WPF)
- **Go 1.21+** (per il modulo Watchdog)
- **Python 3.10+** (per il motore di analisi dell'entropia)

---

## 🚀 Guida all'Avvio (Per i Docenti)

Segui questi passaggi in ordine per testare l'applicativo per la prima volta:

### 1. Compila il modulo Go (Watchdog)
Il sistema di monitoraggio cartelle richiede la pre-compilazione dell'eseguibile Go.
1. Apri un terminale nella cartella `watchdog-go`
2. Esegui il comando:
   ```cmd
   go build -o watchdog.exe .
   ```
3. Verifica che il file `watchdog.exe` sia stato creato con successo in quella cartella.

### 2. Compila e avvia l'interfaccia C#
1. Apri un terminale nella cartella `CSharp`
2. Esegui il comando:
   ```cmd
   dotnet run
   ```
   *(In alternativa, puoi aprire `CSharp/ByteGuard.csproj` con Visual Studio e premere F5).*

---

## 📁 Struttura e File Importanti

### Dove si trova l'eseguibile finale?
Se il progetto è stato compilato correttamente, l'eseguibile principale dell'interfaccia (il file `.exe` da cui si avvia l'app in produzione) si trova in:
👉 `CSharp/bin/Debug/net10.0-windows/ByteGuard.exe`

*(Nota: il file `analyzer.py` viene copiato automaticamente dal sistema di build di C# nella stessa cartella dell'eseguibile).*

### Dove trovo i file di Test?
Abbiamo predisposto una cartella con file campione (sani e anomali) per testare l'analisi dell'entropia e la verifica dei Magic Bytes.
👉 I file si trovano nella cartella: `TestFiles` (nella root del progetto).
- Puoi trascinarli nella "Drop Zone" dell'app per l'analisi singola.
- Puoi selezionare l'intera cartella `TestFiles` usando la funzione "Monitora Cartella" per testare il Watchdog in Go.

### Dove trovo i Log (Errori e Warning)?
Se il modulo Python rileva delle anomalie interne o lancia dei *Warning*, questi vengono silenziosamente intercettati (per non corrompere la comunicazione IPC JSON con Go) e salvati in un file di testo.
👉 Il file di log si trova in: `Python/byteguard_warnings.log`
*(Viene generato automaticamente al primo warning).*

---

## 🧩 Architettura Moduli

- **UI (C# WPF):** Gestisce l'interazione utente e l'orchestrazione dei processi. Usa il pattern *Event Sourcing* (tramite `System.Text.Json`) per leggere l'output dei processi figli in tempo reale.
- **Motore di Analisi (Python):** Script standalone (`analyzer.py`) che calcola l'entropia di Shannon e confronta i Magic Bytes per smascherare file con estensioni falsificate.
- **Watchdog (Go):** Sottoprocesso (`watchdog.exe`) che sfrutta un *Worker Pool* e le *Goroutines* per monitorare le cartelle e gestire code di file in maniera concorrente, invocando Python e comunicando con C# via JSON over stdout.