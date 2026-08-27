# ByteGuard - Progetto APL

ByteGuard è un'applicazione desktop scritta in C# (WPF) per l'analisi forense e la crittografia dei file. È un progetto multi-linguaggio che sfrutta i punti di forza di diverse tecnologie:
- **C# (WPF)**: Interfaccia grafica fluida e reattiva, e orchestrazione dei processi.
- **Go**: Watchdog concorrente ad alte prestazioni per il monitoraggio in tempo reale delle cartelle.
- **Python**: Motore flessibile per l'analisi forense (entropia di Shannon e spoofing dei Magic Bytes).
- **C++**: Modulo ad alte prestazioni per la cifratura e decifratura sicura dei file.

## Requisiti di Sistema

Prima di clonare o avviare il progetto, assicurati di avere installati:
- **.NET 10.0 SDK** (per l'interfaccia C#)
- **Go 1.21** o superiore (per il Watchdog)
- **Python 3.10** o superiore (per l'analizzatore)
- **MSYS2 con GCC/g++** (per compilare il modulo C++). Di default, il progetto cercherà il compilatore nel percorso `C:\msys64\ucrt64\bin\g++.exe`. Se installato altrove, assicurati che `g++` sia accessibile nelle variabili d'ambiente (PATH).

Tutti gli strumenti (escluso g++ se nel percorso standard) devono essere accessibili da terminale.

## Guida all'avvio (Import ed Esecuzione)

Il progetto è progettato per essere compilato ed eseguito con **un solo comando**. Il sistema di build (MSBuild) è stato istruito per compilare automaticamente i moduli C++ e Go prima di avviare l'interfaccia.

1. Clona la repository sul tuo PC locale.
2. Apri un terminale e spostati nella cartella `CSharp`:
   ```bash
   cd "ByteGuard/CSharp"
   ```
3. Lancia il comando di avvio:
   ```bash
   dotnet run
   ```

*In alternativa*: Puoi aprire il file `ByteGuard.csproj` con **Visual Studio 2022** e premere `F5` per avviare il debug. 

*(La compilazione copierà automaticamente gli eseguibili `watchdog.exe` e `ByteGuardCrypto.exe`, oltre allo script Python, nella cartella finale `bin/Debug` per rendere l'applicativo portatile).*

## Distribuzione ed Esecuzione (Per l'Utente Finale)

I requisiti elencati sopra servono **solo a chi compila il progetto dai sorgenti**. 
Se desideri semplicemente utilizzare l'applicazione senza compilare nulla, puoi scaricare la versione pre-compilata direttamente dalla sezione **Releases** di GitHub (nella barra laterale a destra).

1. Scarica il file `ByteGuard-v1.0.zip` (o versione successiva) dalla sezione Releases.
2. Estrai l'intero contenuto in una cartella a tua scelta.
3. Fai **doppio clic su `ByteGuard.exe`** per avviare l'app.

- **Non** dovrai installare né Go né i compilatori C++ (i binari sono già inclusi nello ZIP).
- **Dovrai** avere installato sul sistema solo **Python 3.10+** (necessario per lo script `analyzer.py`) e il **.NET Desktop Runtime** (spesso già pre-installato su Windows).

## Come si usa l'App

Una volta avviata, l'interfaccia si divide in due sezioni principali accessibili dal menu laterale:

### 1. Analisi Forense (Analysis)
Questa sezione permette di scovare file sospetti, file offuscati, o malware camuffati da documenti innocui.
- **Analisi Manuale**: Trascina uno o più file all'interno del riquadro tratteggiato, oppure clicca su "Seleziona File". Python calcolerà l'entropia del file e verificherà se l'estensione (es. `.pdf`) coincide davvero con la sua firma binaria interna (Magic Bytes).
- **Watchdog in Tempo Reale**: Clicca su "Monitora Cartella" e seleziona una directory (es. la cartella Download). Il modulo Go si piazzerà in ascolto, intercettando immediatamente qualsiasi file scaricato o modificato. Passerà il file a Python e la tabella si aggiornerà in tempo reale.
- **Allarmi Visivi**: I file anomali (es. un eseguibile rinominato in `.txt`, file con entropia troppo alta/cifrati, o con doppie estensioni come `fattura.pdf.exe`) verranno portati in cima alla lista e segnalati in rosso.

### 2. Cassaforte Crittografica (Crypto)
Questa sezione ti permette di blindare file sensibili usando il motore C++.
- **Cifratura**: Seleziona uno o più file, inserisci una chiave di sicurezza (password) e clicca su "Cifra File". Il modulo C++ produrrà delle versioni protette e non leggibili dei tuoi file, salvandole con estensione `.lock`.
- **Decifratura**: Seleziona i file `.lock`, inserisci la password usata in precedenza e clicca su "Decifra File". Se la password è corretta e il file non è stato manomesso, verrà ripristinato al suo stato originale.

## Struttura delle Cartelle
- `CSharp/`: UI e logica di orchestrazione (Interfaccia).
- `core-cpp/`: Motore crittografico in C++ (`ByteGuardCrypto.exe`).
- `Python/`: Motore forense (`analyzer.py`).
- `watchdog-go/`: Pool concorrente per il monitoraggio cartelle (`watchdog.exe`).