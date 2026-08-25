// =============================================================================
// ByteGuard — Modulo Go: Monitoraggio e Watchdog (Worker Pool Architecture)
// Implementa il pattern Produttore-Consumatore tramite canali (channels)
// per la gestione concorrente e thread-safe dell'analisi forense.
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

// Strutture Dati per IPC (Inter-Process Communication).
// I JSON tag mappano esattamente l'output per la deserializzazione in C#.

type EventWatchStarted struct {
	Event  string `json:"event"` // questi tag sono metadati per il marshaling JSON, specificando il nome del campo nell'output JSON
	Folder string `json:"folder"` // funzionano così: verranno automaticamente convertiti in {"event": "...", "folder": "..."} quando serializzati da json.Marshal
}

type EventFileDetected struct {
	Event string `json:"event"`
	File  string `json:"file"`
}

type EventFileDeleted struct {
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

// outputMutex garantisce che la scrittura concorrente su os.Stdout sia atomica,
// evitando interleaving di caratteri che causerebbe JSON malformato letto da C#.

var outputMutex sync.Mutex

// emitJSON serializza in modo sicuro l'oggetto e lo stampa su stdout con newline.

func emitJSON(v interface{}) {
	// Acquisizione esclusiva del lock prima di interagire con lo stream I/O condiviso.
	outputMutex.Lock()
	defer outputMutex.Unlock()

	data, err := json.Marshal(v)
	if err == nil {
		fmt.Println(string(data))
	} else {
		fallbackJSON := fmt.Sprintf(`{"event": "error", "message": "Errore interno di serializzazione JSON: %v"}`, err)
		fmt.Println(fallbackJSON)
	}
}

// Worker (Consumatore): elabora i task presi dal channel.
// Il loop for-range garantisce la terminazione naturale della goroutine
// alla chiusura del canale, prevenendo goroutine leaks.
// Il WaitGroup orchestra il Graceful Shutdown.

func worker(id int, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Costruiamo il percorso relativo per lo script Python.
	// NOTA: filepath.Join garantisce la portabilità cross-platform (gestisce
	// automaticamente gli slash '/' su Linux o backslash '\' su Windows).
	pythonScriptPath := filepath.Join("..", "Python", "analyzer.py")

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

// Watchdog (Produttore): effettua polling temporizzato sulla directory per
// rilevare file nuovi, modificati o cancellati.
// Utilizziamo time.NewTicker al posto di time.Tick per poter richiamare
// esplicitamente ticker.Stop() e prevenire resource leaks all'uscita.
func watchdog(folder string, jobs chan<- string, done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	// Tracciamo non solo la presenza del file, ma la data di ultima modifica (ModTime).
	// Questo ci permette di ri-analizzare i file se vengono alterati/sovrascritti.
	seenFiles := make(map[string]time.Time)

	// Istanziamento del Ticker. Fornisce un channel (C) che invia il tick a intervalli regolari.
	ticker := time.NewTicker(1 * time.Second)
	// Garantisce il recupero delle risorse da parte del Garbage Collector all'uscita.
	defer ticker.Stop()

	for {
		// Il costrutto select blocca senza consumare CPU finché uno dei case di comunicazione non è pronto.
		select {
		case <-done:
			// Cancellation Signal: se il canale `done` viene chiuso dal main,
			// usciamo dal loop e la goroutine termina in modo naturale.
			return

		case <-ticker.C:
			// Allo scattare del timer (ogni secondo), effettuiamo il controllo della cartella.
			entries, err := os.ReadDir(folder)
			if err != nil {
				emitJSON(EventGeneric{Event: "error", Message: fmt.Sprintf("ReadDir fallita: %v", err)})
				continue
			}

			// Mappa per tracciare i file fisicamente presenti in questo esatto ciclo di polling.
			currentFiles := make(map[string]bool)

			// Iteriamo sul contenuto della directory
			for _, entry := range entries {
				if entry.IsDir() {
					continue // Ignoriamo le sottocartelle
				}

				name := entry.Name()
				fullPath := filepath.Join(folder, name)

				// Estraiamo i metadati per ottenere il Timestamp di modifica
				info, err := entry.Info()
				if err != nil {
					// Usiamo l'EventGeneric per segnalare che c'è un file "fantasma" o inaccessibile.
					emitJSON(EventGeneric{
						Event:   "error",
						Message: fmt.Sprintf("Accesso negato o file sparito (%s): impossibile leggere i metadati. Dettaglio: %v", name, err),
					})
					continue // Saltiamo l'elaborazione di questo file per questo giro
				}
				modTime := info.ModTime()

				// Segniamo che il file esiste attualmente
				currentFiles[name] = true

				lastSeenTime, exists := seenFiles[name]

				// Rilevamento: il file è NUOVO (!exists) oppure è stato MODIFICATO (modTime.After)
				if !exists || modTime.After(lastSeenTime) {
					// Aggiorniamo la memoria del watchdog con il nuovo timestamp
					seenFiles[name] = modTime

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

			// ─────────────────────────────────────────────────────────────────
			// Fase di Cleanup: Rilevamento file CANCELLATI
			// ─────────────────────────────────────────────────────────────────
			// Confrontiamo la nostra memoria storica (seenFiles) con il presente (currentFiles).
			for name := range seenFiles {
				if !currentFiles[name] {
					// Il file era nella mappa 'seenFiles' ma non esiste più fisicamente
					deletedPath := filepath.Join(folder, name)

					emitJSON(EventFileDeleted{
						Event: "file_deleted",
						File:  deletedPath,
					})

					// Rimuoviamolo dalla nostra memoria per mantenere sincronizzato lo stato
					delete(seenFiles, name)
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

	// Canale bufferizzato per disaccoppiare la latenza I/O tra watchdog e worker.
	// Introduce una backpressure se i worker non riescono a smaltire i burst di file.
	jobs := make(chan string, 100)

	// Canale di controllo per lo shutdown del watchdog (non bufferizzato)
	done := make(chan struct{})

	// sync.WaitGroup ci permette di attendere la terminazione pulita di tutte
	// le goroutine prima di permettere alla funzione main di ritornare (e quindi
	// di far morire il processo, stroncando le routine figlie).
	var workersWg sync.WaitGroup
	var watchdogWg sync.WaitGroup

	numWorkers := max(runtime.NumCPU() / 2, 1)

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

	// Intercettazione segnali OS (SIGINT/SIGTERM) per Graceful Shutdown.
	// Evita la corruzione bloccando l'hard-kill del processo.

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
	// In Go, solo il sender deve chiudere un canale. Essendo il watchdog terminato,
	// possiamo chiudere il canale jobs in sicurezza.
	close(jobs)

	// 4. Attendiamo che i consumatori (Worker) completino l'elaborazione
	// dei task rimanenti nel buffer del canale, e che ritornino dalle funzioni.
	workersWg.Wait()

	emitJSON(EventGeneric{Event: "shutdown_completed"})
}
