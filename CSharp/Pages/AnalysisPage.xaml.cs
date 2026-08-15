// ByteGuard - AnalysisPage.xaml.cs (Code-Behind)
// Gestisce la pagina di analisi forense: file singoli via Python, cartelle via Go Watchdog.

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
        
        // Riferimento al processo Go Watchdog, per poterlo terminare manualmente
        private Process? _watchdogProcess;

        // ObservableCollection è essenziale in WPF: notifica automaticamente
        // la DataGrid ogni volta che viene aggiunto un nuovo elemento.
        public ObservableCollection<AnalysisResult> ScannedFiles { get; } = new ObservableCollection<AnalysisResult>();

        // Elenco delle estensioni ufficialmente supportate e gestite dal motore.
        // File con estensioni diverse verranno scartati a monte per evitare falsi positivi.
        private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".zip", ".gz", ".docx", ".xlsx", ".jpg", ".jpeg", ".png",
            ".exe", ".elf", ".dll", ".sys",
            ".txt", ".json", ".xml", ".csv", ".html"
        };

        // Palette Colori
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
            
            if (e.Data.GetData(DataFormats.FileDrop) is string[] droppedItems && droppedItems.Length > 0)
            {
                var filesToProcess = ResolveFiles(droppedItems);
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
                // Il Watchdog Go accetta UNA sola cartella come argomento (os.Args[1]).
                // Multiselect = false riflette questo vincolo architetturale del modulo Go.
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

                // Non usiamo 'await' qui perche' il watchdog gira all'infinito.
                // Se lo facessimo, l'interfaccia si bloccherebbe.
                // Salviamo il processo in _watchdogProcess cosi' possiamo chiuderlo dopo dal bottone Stop.
#pragma warning disable CS4014 // Ignoriamo l'avviso del compilatore perche' e' voluto
                _ = StartWatchdogAsync(dialog.FolderName);
#pragma warning restore CS4014
            }
        }

        /// <summary>
        /// Avvia watchdog.exe come sottoprocesso, redirige il suo stdout e legge
        /// gli eventi JSON riga per riga in modo asincrono.
        /// </summary>
        private async Task StartWatchdogAsync(string folder)
        {
            // Calcoliamo il percorso dell'eseguibile Go.
            // Dato che siamo dentro bin/Debug/net10.0-windows, dobbiamo risalire di 4 cartelle
            // per arrivare alla root del progetto e trovare la cartella watchdog-go.
            string watchdogDir = Path.GetFullPath(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "watchdog-go"));
            string watchdogExe = Path.Combine(watchdogDir, "watchdog.exe");

            // Guardia: se l'eseguibile non e' stato compilato (go build non e' stato eseguito),
            // informiamo l'utente invece di andare in crash silenzioso.
            if (!File.Exists(watchdogExe))
            {
                MessageBox.Show(
                    $"watchdog.exe non trovato in:\n{watchdogExe}\n\nEseguire 'go build' nella cartella watchdog-go.",
                    "Errore", MessageBoxButton.OK, MessageBoxImage.Error);
                SetUiReady();
                BtnStopWatchdog.Visibility = Visibility.Collapsed;
                return;
            }

            // Impostiamo l'avvio del processo senza finestre visibili e redirigendo l'output
            var startInfo = new ProcessStartInfo
            {
                FileName               = watchdogExe,
                RedirectStandardOutput = true, // Cosi' possiamo leggere cosa stampa Go
                UseShellExecute        = false, // Serve per far funzionare il redirect
                CreateNoWindow         = true,
                
                // Impostiamo la working directory su watchdog-go/ perche' il codice Go
                // usa un percorso relativo ("../Python/analyzer.py") che altrimenti si spaccherebbe
                WorkingDirectory       = watchdogDir,
                
                // Usiamo UTF-8 per evitare problemi con cartelle/file che contengono accenti
                StandardOutputEncoding = System.Text.Encoding.UTF8,
            };

            // Passiamo la cartella come primo argomento: diventa os.Args[1] nel main() di Go.
            startInfo.ArgumentList.Add(folder);

            // Salviamo il riferimento al processo nel campo membro: serve a BtnStopWatchdog_Click
            // per poter chiamare _watchdogProcess.Kill() in un secondo momento.
            _watchdogProcess = new Process { StartInfo = startInfo };

            try
            {
                _watchdogProcess.Start();

                // Leggiamo quello che Go stampa (che e' sempre JSON) riga per riga
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
                        // Nel caso in cui Go dovesse stampare un errore strano (es. panic crash),
                        // lo ignoriamo per non far crashare anche l'app C#
                        Debug.WriteLine($"[ByteGuard] Riga non-JSON ignorata da Go: {line}");
                    }
                }

                // Quando Go termina (per SIGTERM o kill), aspettiamo che il processo
                // si chiuda completamente prima di continuare (cleanup delle risorse OS).
                await _watchdogProcess.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                // Gestisce il caso in cui watchdog.exe non riesca proprio ad avviarsi
                // (es. permessi mancanti, file corrotto).
                Debug.WriteLine($"[ByteGuard] Errore avvio watchdog: {ex.Message}");

                // Dispatcher.InvokeAsync e' necessario perche' siamo su un thread di background:
                // le proprieta' dei controlli WPF possono essere toccate SOLO dal thread UI.
                Dispatcher.InvokeAsync(() =>
                {
                    SetUiReady();
                    BtnStopWatchdog.Visibility = Visibility.Collapsed;
                });
            }
        }

        /// <summary>
        /// Legge l'evento JSON da Go e aggiorna l'interfaccia di conseguenza.
        /// Usiamo JsonDocument invece di creare mille classi DTO per semplificare il codice.
        /// Ricorda: tutto cio' che tocca la UI deve usare Dispatcher.InvokeAsync.
        /// </summary>
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
                    string? file = root.GetProperty("file").GetString();
                    Dispatcher.InvokeAsync(() => TxtGlobalStatus.Text = $"Rilevato: {Path.GetFileName(file)}");
                    break;

                case "analysis_completed":
                    // Estraiamo la parte "result" del JSON e la trasformiamo direttamente
                    // nella nostra classe AnalysisResult (la stessa che usiamo per Python)
                    var resultElement = root.GetProperty("result");
                    
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

        /// <summary>
        /// Termina manualmente il processo Watchdog Go, se attivo.
        /// </summary>
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
                // SetUiReady ripristina tutto: bottoni, drop zone e status bar
                SetUiReady();
                BtnStopWatchdog.Visibility = Visibility.Collapsed;
            }
        }

        /// <summary>
        /// Metodo pubblico che verrà chiamato dall'oratore (es. ascoltatore dello stdout di Go)
        /// per inserire i risultati in tempo reale nella DataGrid.
        /// </summary>
        public void UpdateGridDynamically(AnalysisResult result)
        {
            // Assicuriamoci di essere sul thread della UI se veniamo chiamati da un thread in background
            Dispatcher.InvokeAsync(() =>
            {
                if (result.IsAnomalous)
                {
                    ScannedFiles.Insert(0, result);
                }
                else
                {
                    ScannedFiles.Add(result);
                }
            });
        }

        // Metodo ricorsivo per estrarre tutti i file validi da una lista mista di file e cartelle
        private List<string> ResolveFiles(IEnumerable<string> paths)
        {
            var files = new List<string>();
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    // Aggiunge il file solo se l'estensione è supportata
                    if (SupportedExtensions.Contains(Path.GetExtension(path)))
                        files.Add(path);
                }
                else if (Directory.Exists(path))
                {
                    try
                    {
                        // Estrae tutti i file e filtra solo quelli supportati
                        var validFiles = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)
                                                  .Where(f => SupportedExtensions.Contains(Path.GetExtension(f)));
                        files.AddRange(validFiles);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        // Silenziamo l'errore per cartelle di sistema a cui non abbiamo accesso.
                        // Aggiungiamo un log diagnostico per non perdere traccia del problema a livello di debug.
                        Debug.WriteLine($"[ByteGuard] Accesso negato alla cartella: {path} - Dettaglio: {ex.Message}");
                    }
                }
            }
            return files;
        }

        // ======================================================================
        // ANALISI MANUALE (Per file singoli scelti dall'utente)
        // ======================================================================
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