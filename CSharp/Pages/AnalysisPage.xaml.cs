// ByteGuard - AnalysisPage.xaml.cs (Code-Behind)
// In questo modulo gestisco la UI della pagina di analisi forense.
// Ho applicato massicciamente il Task-based Asynchronous Pattern (TAP) per non bloccare mai la UI
// e i principi di programmazione funzionale (come LINQ) per la manipolazione dei dati.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Diagnostics;
using Microsoft.Win32;
using ByteGuard.Services;

namespace ByteGuard.Pages
{
    public partial class AnalysisPage : Page
    {
        private readonly PythonAnalyzerService _analyzerService;
        
        // Riferimento al processo Go Watchdog per consentirne l'arresto forzato
        private Process? _watchdogProcess;

        // Uso ObservableCollection (e non una semplice List) perché implementa nativamente INotifyCollectionChanged.
        // Questo permette alla DataGrid WPF di aggiornarsi automaticamente quando aggiungo o rimuovo un AnalysisResult,
        // senza dover scrivere codice per forzare il refresh visivo (Pattern MVVM-like).
        public ObservableCollection<AnalysisResult> ScannedFiles { get; } = new ObservableCollection<AnalysisResult>();

        // HashSet offre un tempo di ricerca O(1). È la scelta ottimale dal punto di vista algoritmico
        // per controllare se l'estensione di un file rientra tra quelle supportate.
        private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".zip", ".gz", ".docx", ".xlsx", ".jpg", ".jpeg", ".png",
            ".exe", ".elf", ".dll", ".sys",
            ".txt", ".json", ".xml", ".csv", ".html"
        };

        // Palette Colori per la UI
        private static readonly SolidColorBrush BrushOk      = new SolidColorBrush(Color.FromRgb(0x2E, 0xCC, 0x71));
        private static readonly SolidColorBrush BrushWarning = new SolidColorBrush(Color.FromRgb(0xF3, 0x9C, 0x12));
        private static readonly SolidColorBrush BrushDanger  = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
        private static readonly SolidColorBrush BrushPrimary = new SolidColorBrush(Color.FromRgb(0xE8, 0xEA, 0xF0));
        private static readonly SolidColorBrush BrushMuted   = new SolidColorBrush(Color.FromRgb(0x88, 0x92, 0xA4));
        private static readonly SolidColorBrush BrushCyan    = new SolidColorBrush(Color.FromRgb(0x00, 0xD4, 0xFF));

        public AnalysisPage()
        {
            InitializeComponent();
            _analyzerService = new PythonAnalyzerService();
            ScannedFiles = new ObservableCollection<AnalysisResult>();
            FilesDataGrid.ItemsSource = ScannedFiles;
        }

        // ======================================================================
        // DRAG & DROP E PULSANTI
        // ======================================================================

        private void DropZone_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                DropZoneBorder.BorderBrush = BrushCyan;
            }
            else
                e.Effects = DragDropEffects.None;
            e.Handled = true;
        }

        private void DropZone_DragLeave(object sender, DragEventArgs e)
        {
            DropZoneBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(0x0F, 0x34, 0x60));
        }

        private async void DropZone_Drop(object sender, DragEventArgs e)
        {
            DropZone_DragLeave(sender, e);
            
            // Uso il Declaration Pattern (is string[] droppedItems) introdotto in C# 7.
            // È molto più sicuro e pulito di un cast esplicito, previene le eccezioni a runtime
            // e dichiara la variabile contestualmente.
            if (e.Data.GetDataPresent(DataFormats.FileDrop) && 
                e.Data.GetData(DataFormats.FileDrop) is string[] droppedItems)
            {
                var filesToProcess = ResolveFiles(droppedItems).ToList();
                if (filesToProcess.Any())
                    await RunManualAnalysisAsync(filesToProcess);
                else
                    ShowError("Nessun file valido trovato nella selezione.");
            }
        }

        private async void BtnBrowseFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog 
            { 
                Title = "Seleziona file da analizzare", 
                Multiselect = true 
            };
            
            if (dialog.ShowDialog() == true)
                await RunManualAnalysisAsync(dialog.FileNames.ToList());
        }

        private async void BtnBrowseFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Seleziona cartella da monitorare",
                // Blocco la multiselezione perché il Watchdog in Go prende solo una cartella alla volta da argv.
                Multiselect = false
            };

            if (dialog.ShowDialog() == true)
            {
                ScannedFiles.Clear();

                // Impostiamo la UI in stato "occupato": disabilita i bottoni di selezione
                // e prepara la progress bar per la modalita' indeterminata.
                SetUiAnalyzing(0);
                TxtGlobalStatus.Text = $"Watchdog Go in ascolto su: {dialog.FolderName}...";
                GlobalProgressBar.IsIndeterminate = true; // Rotellina: non sappiamo quanti file arriveranno
                BtnStopWatchdog.Visibility = Visibility.Visible;

                // Faccio il discard (_) e non uso await, altrimenti la UI si blocca visto che il Watchdog gira all'infinito.
                // Disabilito il warning CS4014 apposta.
#pragma warning disable CS4014
                _ = StartWatchdogAsync(dialog.FolderName);
#pragma warning restore CS4014
            }
        }

        private void BtnClearList_Click(object sender, RoutedEventArgs e)
        {
            ScannedFiles.Clear();
            TxtAnomalyCount.Text = "Anomalie: 0";
            ShowBlankDetails();
        }

        // Il metodo StartWatchdogAsync è il cuore dell'IPC (Inter-Process Communication) asincrona.
        // Avvia l'eseguibile Go in background e ne intercetta l'output riga per riga (stdout).
        private async Task StartWatchdogAsync(string folder)
        {
            // Grazie all'istruzione Copy nel .csproj, il binario si trova nella cartella base dell'eseguibile.
            string watchdogExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "watchdog.exe");

            // Validazione pre-esecuzione: gestisco l'eventuale assenza dell'eseguibile Go compilato.
            if (!File.Exists(watchdogExe))
            {
                MessageBox.Show(
                    $"watchdog.exe non trovato in:\n{watchdogExe}\n\nEseguire 'go build' nella cartella watchdog-go.",
                    "Errore", MessageBoxButton.OK, MessageBoxImage.Error);
                SetUiReady();
                BtnStopWatchdog.Visibility = Visibility.Collapsed;
                return;
            }

            // Avvio il processo di nascosto e catturo l'output
            var startInfo = new ProcessStartInfo
            {
                FileName               = watchdogExe,
                RedirectStandardOutput = true, 
                UseShellExecute        = false, 
                CreateNoWindow         = true,
                
                // Il modulo Go cerca lo script Python in "..\Python\analyzer.py".
                // Impostando la WorkingDirectory nella sottocartella "Python", il path
                // relativo calcolato da Go (..) punterà correttamente alla BaseDirectory.
                WorkingDirectory       = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Python"),
                
                // Forza la codifica UTF-8 per prevenire eccezioni sui percorsi contenenti caratteri Unicode.
                StandardOutputEncoding = System.Text.Encoding.UTF8,
            };

            // Passo la cartella come argomento
            startInfo.ArgumentList.Add(folder);

            // Mantengo il riferimento al processo per consentire la terminazione forzata (Stop) in seguito.
            _watchdogProcess = new Process { StartInfo = startInfo };

            try
            {
                _watchdogProcess.Start();

                // Ascolto continuo dello stdout riga per riga (streaming JSON da Go).
                // Paradigma I/O Asincrono Concorrente (TAP): ReadLineAsync non blocca il thread UI.
                // Restituisce un Task che viene "awaitato". Il thread della UI è libero di gestire i click
                // finché il sistema operativo non segnala che c'è una nuova riga JSON da leggere nel buffer.
                using var reader = _watchdogProcess.StandardOutput;
                string? line;
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    try
                    {
                        DispatchGoEvent(line);
                    }
                    catch (JsonException)
                    {
                        // Ignora log diagnostici o panics di Go per preservare la stabilità del thread UI C#
                        Debug.WriteLine($"[ByteGuard] Riga non-JSON ignorata da Go: {line}");
                    }
                }

                // Aspetto che si chiuda per bene per pulire le risorse.
                await _watchdogProcess.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                // Se proprio non parte lo scrivo nel log
                Debug.WriteLine($"[ByteGuard] Errore avvio watchdog: {ex.Message}");

                // Dato che sono in background, uso il Dispatcher per toccare la UI
                Dispatcher.InvokeAsync(() =>
                {
                    SetUiReady();
                    BtnStopWatchdog.Visibility = Visibility.Collapsed;
                });
            }
        }

        // Esegue il parsing polimorfico degli eventi Go utilizzando JsonDocument.
        // Successivamente, applico un costrutto switch classico per instradare gli eventi JSON generati da Go.
        // Questo approccio mi permette di mantenere il codice leggibile senza creare gerarchie di DTO ridondanti.
        private void DispatchGoEvent(string jsonLine)
        {
            using JsonDocument doc = JsonDocument.Parse(jsonLine);
            JsonElement root = doc.RootElement;

            if (!root.TryGetProperty("event", out JsonElement eventProp))
                return;

            string? eventType = eventProp.GetString();

            switch (eventType)
            {
                case "watch_started":
                    string? folder = root.GetProperty("folder").GetString();
                    Dispatcher.InvokeAsync(() => TxtGlobalStatus.Text = $"Watchdog attivo su: {folder}");
                    break;

                case "file_detected":
                    // Questo evento copre sia file nuovi che file modificati.
                    // Non facciamo nient'altro qui: ci penserà l'analysis_completed quando Go finisce l'analisi.
                    string? detectedFile = root.GetProperty("file").GetString();
                    Dispatcher.InvokeAsync(() => TxtGlobalStatus.Text = $"Rilevato: {Path.GetFileName(detectedFile)}");
                    break;

                case "file_deleted":
                    // Un file che stavamo monitorando è stato eliminato dalla cartella.
                    // Uso LINQ (FirstOrDefault) per trovare il file nella collezione in modo funzionale e pulito.
                    string? deletedFile = root.GetProperty("file").GetString();
                    if (deletedFile != null)
                    {
                        Dispatcher.InvokeAsync(() =>
                        {
                            var toRemove = ScannedFiles.FirstOrDefault(r => r.FilePath == deletedFile);
                            if (toRemove != null)
                            {
                                ScannedFiles.Remove(toRemove);
                                TxtGlobalStatus.Text = $"Rimosso: {Path.GetFileName(deletedFile)}";
                            }
                        });
                    }
                    break;

                case "analysis_completed":
                    // Converto il risultato direttamente nella mia classe AnalysisResult
                    var resultElement = root.GetProperty("result");
                    
                    // Se Python ha ignorato il file (estensione non supportata), scartiamo l'evento silenziando i falsi positivi
                    if (resultElement.TryGetProperty("analysis_status", out var statusProp) && statusProp.GetString() == "ignored")
                    {
                        break;
                    }
                    
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var result = resultElement.Deserialize<ByteGuard.Services.AnalysisResult>(options);
                    
                    if (result != null)
                        UpdateGridDynamically(result);
                    break;

                case "shutdown_initiated":
                    Dispatcher.InvokeAsync(() => TxtGlobalStatus.Text = "Watchdog: shutdown in corso...");
                    break;

                case "shutdown_completed":
                    Dispatcher.InvokeAsync(() =>
                    {
                        SetUiReady();
                        BtnStopWatchdog.Visibility = Visibility.Collapsed;
                    });
                    break;

                case "error":
                    string? msg = root.GetProperty("message").GetString();
                    Dispatcher.InvokeAsync(() => TxtGlobalStatus.Text = $"Errore Watchdog: {msg}");
                    break;

                default:
                    Debug.WriteLine($"[ByteGuard] Evento Go sconosciuto: {eventType}");
                    break;
            }
        }

        // Termina il processo Go quando l'utente preme Stop
        private void BtnStopWatchdog_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_watchdogProcess != null && !_watchdogProcess.HasExited)
                {
                    _watchdogProcess.Kill(entireProcessTree: true);
                    _watchdogProcess.Dispose();
                    Debug.WriteLine("[ByteGuard] Watchdog Go terminato manualmente dall'utente.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ByteGuard] Errore durante la terminazione del Watchdog: {ex.Message}");
            }
            finally
            {
                _watchdogProcess = null;
                SetUiReady();
                BtnStopWatchdog.Visibility = Visibility.Collapsed;
            }
        }

        // Aggiunge (o aggiorna) un risultato nella griglia in tempo reale.
        // Se il file era già in lista (caso: file modificato e rianalizzato), sostituiamo la vecchia riga.
        public void UpdateGridDynamically(AnalysisResult result)
        {
            Dispatcher.InvokeAsync(() =>
            {
                // Uso LINQ per la ricerca del file esistente
                var existing = ScannedFiles.FirstOrDefault(r => r.FilePath == result.FilePath);
                if (existing != null)
                    ScannedFiles.Remove(existing);

                // Metto le anomalie in cima così saltano subito all'occhio
                if (result.IsAnomalous)
                    ScannedFiles.Insert(0, result);
                else
                    ScannedFiles.Add(result);

                // Uso la Lambda Expression all'interno del metodo LINQ Count per calcolare le anomalie
                int anomalyCount = ScannedFiles.Count(r => r.IsAnomalous);
                TxtAnomalyCount.Text = $"Anomalie: {anomalyCount}";
            });
        }

        // Estraggo i file dalle cartelle scartando le estensioni che non ci interessano.
        // OTTIMIZZAZIONE ALGORITMICA: Ho applicato i principi di Programmazione Funzionale e Lazy Evaluation
        // restituendo un IEnumerable<string> e usando la keyword "yield return" assieme a Directory.EnumerateFiles.
        // Questo differisce nettamente dall'uso di GetFiles() perché non costruisce un array gigante in RAM 
        // qualora l'utente dovesse selezionare una cartella con 100.000 file, ma li serve "on-demand" al consumatore.
        private IEnumerable<string> ResolveFiles(IEnumerable<string> paths)
        {
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    // Restituisce il file solo se l'estensione è supportata
                    if (SupportedExtensions.Contains(Path.GetExtension(path)))
                        yield return path;
                }
                else if (Directory.Exists(path))
                {
                    // Per le directory, usiamo un iteratore manuale per poter intercettare e scartare
                    // eventuali UnauthorizedAccessException sulle singole sottocartelle di sistema
                    IEnumerator<string> enumerator = null;
                    try
                    {
                        enumerator = Directory.EnumerateFiles(path, "*.*", SearchOption.AllDirectories).GetEnumerator();
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Debug.WriteLine($"[ByteGuard] Accesso negato alla cartella principale: {path} - Dettaglio: {ex.Message}");
                        continue;
                    }

                    bool hasNext = true;
                    while (hasNext)
                    {
                        try
                        {
                            hasNext = enumerator.MoveNext();
                        }
                        catch (UnauthorizedAccessException)
                        {
                            // Ignora la singola sottocartella protetta e prova a proseguire (se l'enumeratore lo permette)
                            continue;
                        }
                        catch (Exception)
                        {
                            hasNext = false;
                        }

                        if (hasNext)
                        {
                            string currentFile = enumerator.Current;
                            if (SupportedExtensions.Contains(Path.GetExtension(currentFile)))
                                yield return currentFile;
                        }
                    }
                    enumerator?.Dispose();
                }
            }
        }

        // ======================================================================
        // ANALISI MANUALE (Per file singoli scelti dall'utente)
        // ======================================================================
        // Esegue l'analisi di una lista di file (usato per il drag&drop o seleziona file).
        // Per evitare di bloccare la UI, applico il pattern TAP dividendo i file in "chunk" (gruppi).
        private async Task RunManualAnalysisAsync(List<string> filePaths)
        {
            SetUiAnalyzing(filePaths.Count);
            
            int total = filePaths.Count;
            int completed = 0;
            int anomalies = 0;
            
            int chunkSize = Math.Max(1, Environment.ProcessorCount / 2);

            try
            {
                foreach (var chunk in filePaths.Chunk(chunkSize))
                {
                    // L'utilizzo di Task.WhenAll permette di parallelizzare il carico su più thread, 
                    // inviando più file a Python simultaneamente (Parallelismo Concorrente) e attendendone il completamento
                    // senza causare il freezing dell'applicazione WPF.
                    var tasks = chunk.Select(async filePath =>
                    {
                        AnalysisResult result;
                        try
                        {
                            result = await _analyzerService.AnalyzeFileAsync(filePath);
                        }
                        catch (Exception ex)
                        {
                            result = new AnalysisResult 
                            { 
                                FilePath = filePath, 
                                AnalysisStatus = "error", 
                                ErrorMessage = ex.Message 
                            };
                        }

                        if (result.AnalysisStatus != "success")
                        {
                            result = result with 
                            { 
                                IsAnomalous = true,
                                Verdict = "Errore di analisi",
                                AnomalyCode = "ANALYSIS_ERROR"
                            };
                        }
                        return result;
                    });

                    var results = await Task.WhenAll(tasks);

                    foreach (var result in results)
                    {
                        if (result.AnalysisStatus == "ignored")
                            continue; // File non supportato: lo scartiamo in modo trasparente

                        if (result.IsAnomalous)
                        {
                            ScannedFiles.Insert(0, result);
                            anomalies++;
                            TxtAnomalyCount.Text = $"Anomalie: {anomalies}";
                        }
                        else
                        {
                            ScannedFiles.Add(result);
                        }
                        
                        completed++;
                        GlobalProgressBar.Value = completed;
                        TxtGlobalStatus.Text = $"Analisi in corso: {completed} / {total}";
                    }
                }
            }
            finally
            {
                SetUiReady();
            }
        }


        // ======================================================================
        // GESTIONE UI E DETTAGLI
        // ======================================================================

        private void SetUiAnalyzing(int totalFiles)
        {
            ScannedFiles.Clear();
            
            BtnBrowseFile.IsEnabled = false;
            BtnBrowseFolder.IsEnabled = false;
            DropZoneBorder.IsEnabled = false;
            
            TxtGlobalStatus.Text = $"Analisi in corso: 0 / {totalFiles}";
            TxtDropPrompt.Text = "Analisi batch in corso...";
            
            GlobalProgressBar.Maximum = totalFiles;
            GlobalProgressBar.Value = 0;
            TxtAnomalyCount.Text = "Anomalie: 0";
            
            ShowBlankDetails();
        }

        private void SetUiReady()
        {
            BtnBrowseFile.IsEnabled = true;
            BtnBrowseFolder.IsEnabled = true;
            DropZoneBorder.IsEnabled = true;
            
            // Ferma la rotellina se era attiva (modalità Watchdog)
            GlobalProgressBar.IsIndeterminate = false;
            GlobalProgressBar.Value = 0;
            
            TxtGlobalStatus.Text = "Pronto.";
            TxtDropPrompt.Text = "Trascina file o cartelle qui";
        }

        private void FilesDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (FilesDataGrid.SelectedItem is AnalysisResult selected)
            {
                DisplayResults(selected);
            }
        }

        private void DisplayResults(AnalysisResult result)
        {
            if (result.AnalysisStatus == "success")
            {
                TxtStatus.Text       = "Analisi completata con successo";
                TxtStatus.Foreground = BrushOk;
            }
            else
            {
                TxtStatus.Text       = string.Format("Analisi fallita: {0}", result.ErrorMessage);
                TxtStatus.Foreground = BrushDanger;
                
                // Resetta gli altri campi in caso di errore
                TxtFilePath.Text = result.FilePath;
                TxtFileSize.Text = "—";
                TxtEntropy.Text = "—";
                EntropyBarFill.Width = 0;
                TxtSanityCheck.Text = "—";
                TxtMagicHex.Text = "—";
                TxtMagicAscii.Text = "—";
                TxtTimestamp.Text = "—";
                return;
            }

            TxtFilePath.Text = result.FilePath;
            TxtFileSize.Text = FormatFileSize(result.FileSizeBytes);

            double e = result.ShannonEntropy;
            TxtEntropy.Text = string.Format("{0:F6} bit/simbolo", e);
            if (result.EntropySampled)
                TxtEntropy.Text += "  (campionato)";

            if (result.IsAnomalous && (result.AnomalyCode == "HIGH_ENTROPY" || result.AnomalyCode == "LOW_ENTROPY" || result.AnomalyCode == "EXTREME_ENTROPY"))
            {
                TxtEntropy.Foreground = BrushWarning;
                TxtEntropy.Text      += "  [ANOMALIA RILEVATA]";
            }
            else
            {
                TxtEntropy.Foreground = BrushPrimary;
            }

            EntropyBarContainer.UpdateLayout();
            double containerWidth = EntropyBarContainer.ActualWidth;
            if (containerWidth > 0)
                EntropyBarFill.Width = (e / 8.0) * containerWidth;

            EntropyBarFill.Background = TxtEntropy.Foreground;

            if (result.ExtensionMatch)
            {
                TxtSanityCheck.Text       = string.Format("PASSATO — Contenuto congruente con l'estensione '{0}'", result.DeclaredExtension);
                TxtSanityCheck.Foreground = BrushOk;
            }
            else
            {
                TxtSanityCheck.Text       = string.Format("FALLITO — magic byte incompatibili con '{0}'", result.DeclaredExtension);
                TxtSanityCheck.Foreground = BrushDanger;
            }

            if (result.HasDoubleExtension)
            {
                TxtSanityCheck.Text += "\n⚠️ ATTENZIONE: Doppia estensione rilevata (Possibile camuffamento!)";
                TxtSanityCheck.Foreground = BrushDanger;
            }

            TxtMagicHex.Text   = result.MagicNumberHex   ?? "N/A";
            TxtMagicAscii.Text = result.MagicNumberAscii ?? "N/A";
            TxtTimestamp.Text  = result.TimestampUtc;
        }

        private void ShowBlankDetails()
        {
            string dash = "\u2014";
            TxtStatus.Text = "Seleziona un file dalla lista...";
            TxtStatus.Foreground = BrushMuted;
            TxtFilePath.Text    = dash;
            TxtFileSize.Text    = dash;
            TxtEntropy.Text     = dash;
            TxtSanityCheck.Text = dash;
            TxtMagicHex.Text    = dash;
            TxtMagicAscii.Text  = dash;
            TxtTimestamp.Text   = dash;
            EntropyBarFill.Width = 0;
        }
        
        private void ShowError(string message)
        {
            MessageBox.Show(message, "ByteGuard Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private static string FormatFileSize(long bytes)
        {
            if (bytes < 1024)           return string.Format("{0} B",    bytes);
            if (bytes < 1024 * 1024)    return string.Format("{0:F1} KB", bytes / 1024.0);
            if (bytes < 1024L * 1024 * 1024) return string.Format("{0:F2} MB", bytes / (1024.0 * 1024));
            return string.Format("{0:F2} GB", bytes / (1024.0 * 1024 * 1024));
        }
    }

    //Converters per la UI

    public class FileSizeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is long bytes)
            {
                if (bytes < 1024) return $"{bytes} B";
                if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
                if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F2} MB";
                return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) => throw new NotImplementedException();
    }

    public class FileNameConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string path && !string.IsNullOrWhiteSpace(path))
            {
                return System.IO.Path.GetFileName(path);
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) => throw new NotImplementedException();
    }

    public class StatusConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string status)
            {
                return status == "success" ? "Completato" : "Errore";
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) => throw new NotImplementedException();
    }
}