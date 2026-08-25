# ByteGuard - Progetto APL

ByteGuard e' un'applicazione desktop scritta in C# (WPF) per l'analisi forense e la crittografia dei file. Utilizza un modulo in Go per fare da Watchdog sulle cartelle e un modulo in Python per analizzare l'entropia e i magic bytes dei file.

## Requisiti di Sistema

Prima di avviare il progetto, assicurarsi di avere installati:
- .NET 10.0 SDK
- Go 1.21 o superiore
- Python 3.10 o superiore

Tutti e tre devono essere accessibili da terminale (cioe' presenti nel PATH di sistema).

## Guida all'avvio

Il progetto si avvia con un solo comando. La compilazione del modulo Go e' automatica.

1. Aprire un terminale nella cartella `CSharp`
2. Lanciare il comando: `dotnet run`

Il sistema di build di C# compilera' automaticamente il modulo Go prima di avviare l'applicazione. Non e' necessario eseguire `go build` manualmente.

In alternativa, aprire il file `ByteGuard.csproj` con Visual Studio e premere F5.

## Struttura del progetto e file principali

- Eseguibile compilato:
  L'eseguibile finale si trovera' in `CSharp/bin/Debug/net10.0-windows/ByteGuard.exe`.
  NOTA: lo script `analyzer.py` viene copiato automaticamente in questa cartella durante la build.

- Modulo Go (Watchdog):
  L'eseguibile `watchdog.exe` viene compilato automaticamente nella cartella `watchdog-go/` ad ogni build.

- File di log:
  Se il modulo Python lancia dei warning durante l'analisi, questi vengono salvati in `Python/byteguard_warnings.log`.

- Moduli:
  - `CSharp/`: Contiene la UI e la logica di gestione.
  - `Python/`: Contiene `analyzer.py`, lo script per il calcolo dell'entropia e l'analisi dei magic bytes.
  - `watchdog-go/`: Contiene il codice Go per il monitoraggio concorrente delle cartelle.