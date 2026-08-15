// =============================================================================
// ByteGuard — Modulo Go: Monitoraggio e Watchdog (Worker Pool Architecture)
// =============================================================================
//
// NOTA ACCADEMICA — Filosofia Concorrente in Go
// ─────────────────────────────────────────────
// "Do not communicate by sharing memory; instead, share memory by communicating."
// (Non comunicare condividendo la memoria; condividi la memoria comunicando).
// Questo è il principio cardine della concorrenza in Go, derivato dal calcolo
// dei processi comunicanti (CSP) di Tony Hoare.
//
// In questo modulo applichiamo questo principio tramite l'architettura
// "Worker Pool". I dati (i percorsi dei file da analizzare) fluiscono dal
// produttore (la routine di monitoraggio) ai consumatori (i worker)
// esclusivamente attraverso un canale (channel) tipizzato e thread-safe,
// eliminando la necessità di lock espliciti per la condivisione dei task.
//
// =============================================================================

package main

import (
	"encoding/json"
	"fmt"
	"os"
    "os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Strutture Dati per IPC (Inter-Process Communication) via JSON
// ─────────────────────────────────────────────────────────────────────────────
// Usiamo strutture fortemente tipizzate per garantire che l'output su Stdout
// rispetti esattamente il contratto richiesto dalla GUI C#.
// Utilizziamo l'Exported Name convention: i campi iniziano con lettera
// maiuscola per essere visibili all'esterno del package (necessario per il marshaling JSON).

type EventWatchStarted struct {
	Event  string `json:"event"` // questi tag sono metadati per il marshaling JSON, specificando il nome del campo nell'output JSON
	Folder string `json:"folder"` // funzionano così: verranno automaticamente convertiti in {"event": "...", "folder": "..."} quando serializzati da json.Marshal
}

type EventFileDetected struct {
	Event string `json:"event"`
	File  string `json:"file"`
}

// Struttura che mappa ESATTAMENTE l'output JSON generato da analyzer.py
type PythonAnalysisResult struct {
	FilePath          string  `json:"file_path"`
	FileSizeBytes     int64   `json:"file_size_bytes"`
	DeclaredExtension string  `json:"declared_extension"`
	ShannonEntropy    float64 `json:"shannon_entropy"`
	EntropySampled    bool    `json:"entropy_sampled"`
	MagicNumberHex    string  `json:"magic_number_hex"`
	MagicNumberAscii  string  `json:"magic_number_ascii"`
	ExtensionMatch    bool    `json:"extension_match"`
	IsAnomalous       bool    `json:"is_anomalous"`
	Verdict           string  `json:"verdict"`
	AnalysisStatus    string  `json:"analysis_status"`
	ErrorMessage      *string `json:"error_message"` // Puntatore per gestire i null
	TimestampUTC      string  `json:"timestamp_utc"`
}

// Estendiamo la nostra struct completata per includere i risultati di Python
type EventAnalysisCompleted struct {
	Event    string               `json:"event"`
	File     string               `json:"file"`
	WorkerID int                  `json:"worker_id"`
	Result   PythonAnalysisResult `json:"result"` // Incastoniamo la risposta di Python
}

type EventGeneric struct {
	Event   string `json:"event"`
	Message string `json:"message,omitempty"` // `omitempty` indica al marshaler di omettere il campo se è vuoto (stringa vuota)
}

// outputMutex garantisce che la scrittura su os.Stdout sia atomica.
// Sebbene le scritture brevi su file descriptor POSIX possano essere atomiche,
// l'uso di json.Encoder o di scritture multiple impone l'uso di un Mutex per
// evitare l'interleaving (accavallamento) dei caratteri generati da diverse
// goroutine (dato che condividono lo stesso address space), che produrrebbe JSON non valido (fatal error per il parser C#).
var outputMutex sync.Mutex

// emitJSON serializza in modo sicuro l'oggetto e lo stampa su stdout con newline.
func emitJSON(v interface{}) {
	// Acquisizione esclusiva del lock prima di interagire con lo stream I/O condiviso.
	outputMutex.Lock()
	// Il costrutto defer accoda l'esecuzione della funzione di Unlock al momento
	// in cui la funzione enclosing (emitJSON) esegue il return. Questo pattern
	// idiomatico assicura il rilascio del lock anche in caso di panic, prevenendo deadlock.
	defer outputMutex.Unlock()

	data, err := json.Marshal(v)
	if err == nil {
		fmt.Println(string(data))
	} else {
        // GESTIONE DELL'ERRORE:
        // Se il marshaling fallisce (improbabile con le nostre struct,
        // ma doveroso a livello accademico), costruiamo una stringa JSON di emergenza "a mano"
        // e la stampiamo per informare C# del disastro.
		fallbackJSON := fmt.Sprintf(`{"event": "error", "message": "Errore interno di serializzazione JSON: %v"}`, err)
		fmt.Println(fallbackJSON)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// worker — La Routine Consumatore
// ─────────────────────────────────────────────────────────────────────────────
// NOTA ACCADEMICA — Ciclo di Vita della Goroutine e Prevenzione Leak
// ─────────────────────────────────────────────────────────────────────────────
// Un "Goroutine Leak" si verifica quando una goroutine rimane bloccata per
// sempre in attesa su un canale che non verrà mai scritto né chiuso, o
// quando esegue un loop infinito senza condizioni di uscita.
//
// In Go, la chiusura di un canale funge da segnale di "broadcast" (End-Of-Stream).
// Il costrutto `for job := range jobs` terminerà in modo naturale, e la
// goroutine uscirà dal loop, non appena il canale `jobs` verrà chiuso e
// svuotato di tutti i task pendenti.
//
// Il parametro `*sync.WaitGroup` serve per orchestrare il Graceful Shutdown.
// Il WaitGroup è passato tramite puntatore (*sync.WaitGroup) poiché in Go il passaggio
// di default è Pass by Value; passando il puntatore modifichiamo i dati sottostanti.
// La goroutine segnala la propria terminazione chiamando `wg.Done()`.
func worker(id int, jobs <-chan string, wg *sync.WaitGroup) {
	// defer wg.Done() viene valutato all'ingresso della funzione ma eseguito
	// rigorosamente all'uscita. È il pattern idiomatico per i WaitGroup.
	defer wg.Done()

	// Costruiamo il percorso relativo per lo script Python.
	// NOTA: filepath.Join garantisce la portabilità cross-platform (gestisce
	// automaticamente gli slash '/' su Linux o backslash '\' su Windows).
	pythonScriptPath := filepath.Join("..", "Python", "analyzer.py")

	// Range and Close: il loop for-range riceve valori dal channel ripetutamente
	// finché questo non viene chiuso dal sender. Questo previene i "Goroutine Leak",
	// permettendo alla goroutine di terminare in modo naturale quando non ci sono più job.
	for file := range jobs {
		// 1. Invocazione del Sottoprocesso Python
		// exec.Command prepara il processo isolato.
		cmd := exec.Command("python", pythonScriptPath, file)

		// Eseguiamo il comando in modo sincrono rispetto a QUESTA goroutine.
		// CombinedOutput esegue il comando, aspetta che finisca, e cattura stdout e stderr.
		// Essendo in un Worker Pool, questa operazione bloccante ferma solo questo
		// specifico worker; gli altri continuano a elaborare file in parallelo!
		outputBytes, err := cmd.CombinedOutput()

		// Inizializziamo la struttura dati che conterrà i risultati di Python
		var pyResult PythonAnalysisResult

		// 2. Deserializzazione (Unmarshaling)
		// Convertiamo la stringa JSON stampata da Python nella nostra struct tipizzata.
		parseErr := json.Unmarshal(outputBytes, &pyResult) // dentro parseErr ci sarà nil se il parsing è andato a buon fine, altrimenti conterrà l'errore di parsing.

		// 3. Gestione Robusta degli Errori (Evitiamo Silent Failures)
		if parseErr != nil {
			// SCENARIO DISASTRO SINTATTICO:
			// parseErr indica se la traduzione del JSON è fallita.
			// Se Python va in crash grave (es. SyntaxError) stamperà il "Traceback"
			// invece del JSON. Il parser fallisce, quindi creiamo noi un JSON di emergenza.
			errMsg := fmt.Sprintf("Errore nel parsing dell'output di Python: %v. Output grezzo: %s", parseErr, string(outputBytes))
			pyResult = PythonAnalysisResult{
				FilePath:       file,
				AnalysisStatus: "error",
				ErrorMessage:   &errMsg,
				IsAnomalous:    true,
				Verdict:        "Python Execution Failed",
			}
		} else if err != nil && pyResult.AnalysisStatus != "error" {
			// SCENARIO PARADOSSO:
			// 'err' indica se il S.O. ha terminato Python con un codice di errore.
			// Entriamo in questo blocco se il S.O. ci segnala un fallimento del processo (err != nil),
			// MA CONTEMPORANEAMENTE il JSON che abbiamo appena parsato non segnalava errori
			// (AnalysisStatus != "error").
			// Risolviamo il paradosso forzando lo stato di errore nella struct.
			errMsg := fmt.Sprintf("Il processo Python è terminato con errore di sistema: %v", err)
			pyResult.AnalysisStatus = "error"
			pyResult.ErrorMessage   = &errMsg
		}

		// 4. Invio dell'evento finale alla GUI (C#)
		// Impacchettiamo il risultato Python (pyResult) all'interno dell'evento di completamento.
		emitJSON(EventAnalysisCompleted{
			Event:    "analysis_completed",
			File:     file,
			WorkerID: id,
			Result:   pyResult, // Incastona tutto l'albero JSON ricevuto da Python
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// watchdog — La Routine Produttore (Polling)
// ─────────────────────────────────────────────────────────────────────────────
// NOTA ACCADEMICA — Polling, Ticker e Prevenzione Memory Leak
// ─────────────────────────────────────────────────────────────────────────────
// Questa funzione implementa un polling temporizzato sulla directory.
//
// Abbiamo scelto di utilizzare `time.NewTicker` accoppiato a `defer ticker.Stop()`.
// Come spiegato nella teoria (Package time), l'uso della funzione `time.Tick`
// non permette di arrestare il timer sottostante, causando un "leak" nel Garbage
// Collector quando la goroutine deve terminare. Il nostro approccio con `NewTicker`
// previene questo leak garantendo lo spegnimento del timer al termine della routine.
//
// Il costrutto `select` permette alla goroutine di dormire senza consumare CPU,
// svegliandosi solo allo scoccare del timer (ticker.C) o in caso di ricezione
// del segnale di cancellazione (done).
func watchdog(folder string, jobs chan<- string, done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	seenFiles := make(map[string]bool) // Mappa utilizzata come Set in O(1) per tracciare i file.

	// Istanziamento del Ticker. Fornisce un channel (C) che invia il tick a intervalli regolari.
	ticker := time.NewTicker(1 * time.Second)
	// Garantisce il recupero delle risorse da parte del Garbage Collector all'uscita.
	defer ticker.Stop()

	/* MODIFICA: Il codice originale censiva i file esistenti per ignorarli,
	   analizzando solo i NUOVI file. Abbiamo commentato questa sezione in modo che 
	   al primo avvio il Watchdog rilevi e processi automaticamente tutti i file pre-esistenti
	   nella cartella.
	// Lettura iniziale per popolare lo stato senza triggerare eventi per i file pre-esistenti.
	entries, err := os.ReadDir(folder)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				seenFiles[entry.Name()] = true
			}
		}
	}
	*/

	for {
		// Il costrutto select blocca finché uno dei case di comunicazione non è pronto.
		select {
		case <-done:
			// Cancellation Signal: se il canale `done` viene chiuso dal main,
			// usciamo dal loop e la goroutine termina (eseguendo i defer).
			return

		case <-ticker.C:
			// Allo scattare del timer (ogni secondo), effettuiamo il controllo della cartella.
			entries, err := os.ReadDir(folder)
			if err != nil {
				emitJSON(EventGeneric{Event: "error", Message: fmt.Sprintf("ReadDir fallita: %v", err)})
				continue
			}

			// Iteriamo sul contenuto della directory
			for _, entry := range entries {
				if entry.IsDir() {
					continue // Ignoriamo le sottocartelle
				}

				name := entry.Name()

				if !seenFiles[name] {
					// Nuovo file rilevato!
					seenFiles[name] = true // Marcalo come visto

					fullPath := filepath.Join(folder, name)
					emitJSON(EventFileDetected{
						Event: "file_detected",
						File:  fullPath,
					})

					// Invia il task al Worker Pool.
					// ATTENZIONE alla Backpressure: se il canale `jobs` è pieno,
					// questa operazione si blocca. La select esterna ci assicura di
					// poter comunque abortire se viene chiuso `done`.
					select {
					case jobs <- fullPath:
						// Inviato con successo al Worker Pool
					case <-done:
						// Shutdown richiesto mentre si attendeva di inviare il job.
						return
					}
				}
			}
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		emitJSON(EventGeneric{Event: "error", Message: "Argomento mancante: folder da monitorare."})
		os.Exit(1)
	}
	targetFolder := os.Args[1]

	// Verifica esistenza cartella
	info, err := os.Stat(targetFolder)
	if err != nil || !info.IsDir() {
		emitJSON(EventGeneric{Event: "error", Message: "Cartella non valida o inesistente."})
		os.Exit(1)
	}

	// ─────────────────────────────────────────────────────────────────────────────
	// Inizializzazione Worker Pool e Canali
	// ─────────────────────────────────────────────────────────────────────────────
	// NOTA ACCADEMICA — Canali Bufferizzati vs Non Bufferizzati
	// ─────────────────────────────────────────────────────────────────────────────
	// Usiamo un canale **bufferizzato** (capacità 100).
	// Un canale non bufferizzato (capacità 0) forza una sincronizzazione stretta
	// In un sistema di monitoraggio file I/O-bound, questo è sub-ottimale.
	// Se l'OS scrive 50 file in rapida successione in un millisecondo, e abbiamo
	// solo 8 worker, il watchdog si bloccherebbe al nono file. Usando un buffer,
	// il watchdog può "scaricare" il burst di task nel canale e continuare
	// il monitoraggio senza interruzioni. Il blocco avviene (Backpressure)
	// solo se il buffer di 100 si riempie totalmente.
    // Buffered Channel: forniamo la lunghezza del buffer come secondo argomento
	// a make. Un send verso un buffered channel si blocca (blocks) solo quando
	// il buffer è pieno. Questo disaccoppia i tempi di latenza I/O tra watchdog e workers.
	jobs := make(chan string, 100)

	// Canale di controllo per lo shutdown del watchdog (non bufferizzato)
	done := make(chan struct{})

	// sync.WaitGroup ci permette di attendere la terminazione pulita di tutte
	// le goroutine prima di permettere alla funzione main di ritornare (e quindi
	// di far morire il processo, stroncando le routine figlie).
	var workersWg sync.WaitGroup
	var watchdogWg sync.WaitGroup

	numWorkers := max(runtime.NumCPU(), 2) // Ottimale per CPU-bound, accettabile per mock I/0, casomai metti / 2 per i core

	// Avvio del Pool di Worker
	for i := 1; i <= numWorkers; i++ {
		workersWg.Add(1)
		go worker(i, jobs, &workersWg)
	}

	// Avvio del Watchdog (Produttore)
	watchdogWg.Add(1)
	go watchdog(targetFolder, jobs, done, &watchdogWg)

	emitJSON(EventWatchStarted{
		Event:  "watch_started",
		Folder: targetFolder,
	})

	// ─────────────────────────────────────────────────────────────────────────────
	// Graceful Shutdown e Gestione dei Segnali
	// ─────────────────────────────────────────────────────────────────────────────
	// Il S.O. invia segnali per richiedere la terminazione (SIGINT = Ctrl+C,
	// SIGTERM = terminazione da un process manager come systemd o C# Process.Kill).
	// Ignorare questi segnali causerebbe un "Hard Kill", corrompendo le analisi
	// in corso. Intercettandoli, implementiamo un "Graceful Shutdown".
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Il main thread si blocca qui, in attesa asincrona del segnale dal S.O.
	<-sigs

	emitJSON(EventGeneric{Event: "shutdown_initiated"})

	// 1. Ferma il Produttore: Chiudiamo il canale `done`.
	// Qualsiasi operazione di `<-done` sbloccherà le goroutine in ascolto.
    // La funzione built-in close(ch) segnala al receiver che non ci sono più dati.
	// Chiudere "done" fa scattare l'uscita dai costrutti select in watchdog
	close(done)

	// 2. Attendiamo che il Watchdog termini la sua esecuzione, per assicurarci
	// che non tenterà più di inviare dati nel canale `jobs`.
	watchdogWg.Wait()

	// 3. Ora che il produttore è terminato, è sicuro chiudere il canale `jobs`.
	// In Go, tentare di scrivere in un canale chiuso causa un Panic fatale.
	// Chiudendolo, segnaliamo ai worker che non arriveranno nuovi task.
    // Come regola di design di Go: "Only the sender should close a channel, never the receiver".
	// Ora che il produttore (watchdog) è chiuso, chiudiamo jobs.
	close(jobs)

	// 4. Attendiamo che i consumatori (Worker) completino l'elaborazione
	// dei task rimanenti nel buffer del canale, e che ritornino dalle funzioni.
	workersWg.Wait()

	emitJSON(EventGeneric{Event: "shutdown_completed"})
}
