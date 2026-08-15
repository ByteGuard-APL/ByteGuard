# ByteGuard - Progetto APL

ByteGuard e' un'applicazione desktop scritta in C# (WPF) per l'analisi forense e la crittografia dei file. Utilizza un modulo in Go per fare da Watchdog sulle cartelle e un modulo in Python per analizzare l'entropia e i magic bytes dei file.

## Requisiti di Sistema
- .NET 10.0 SDK (per C#)
- Go 1.21 o superiore
- Python 3.10 o superiore

## Guida all'avvio

Per testare l'applicativo partendo dal codice sorgente, segui questi due passaggi:

1. Compilare il modulo Go
- Apri un terminale nella cartella `watchdog-go`
- Lancia il comando: `go build -o watchdog.exe .`
- Questo generera' l'eseguibile del Watchdog di cui C# ha bisogno.

2. Avviare l'interfaccia C#
- Apri un terminale nella cartella `CSharp`
- Lancia il comando: `dotnet run`
- In alternativa, apri il file `ByteGuard.csproj` con Visual Studio e premi F5.

## Struttura del progetto e file principali

- Eseguibile compilato:
  Se compili il progetto, l'eseguibile finale da avviare si trovera' in `CSharp/bin/Debug/net10.0-windows/ByteGuard.exe`.
  NOTA: lo script `analyzer.py` viene copiato in automatico in questa cartella durante la build.

- File di log:
  Se il modulo Python lancia dei warning durante l'analisi, questi vengono intercettati e salvati in un file di log per non corrompere la comunicazione con Go. Il file verra' creato in `Python/byteguard_warnings.log`.

- Moduli:
  - `CSharp/`: Contiene la UI e la logica di gestione (gestita tramite navigazione SPA).
  - `Python/`: Contiene `analyzer.py`, lo script standalone che fa i calcoli sull'entropia.
  - `watchdog-go/`: Contiene il codice Go per il monitoraggio concorrente delle cartelle.