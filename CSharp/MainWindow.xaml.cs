// ByteGuard - MainWindow.xaml.cs (Code-Behind)
// Gestisce l'interfaccia Master-Details e l'esecuzione in batch parallela.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using ByteGuard.Services;

namespace ByteGuard
{
    public partial class MainWindow : Window
    {
        private readonly PythonAnalyzerService _analyzerService;

        // ObservableCollection è essenziale in WPF: notifica automaticamente
        // la DataGrid ogni volta che viene aggiunto un nuovo elemento.
        public ObservableCollection<AnalysisResult> ScannedFiles { get; } = new ObservableCollection<AnalysisResult>();

        // Profili di entropia
        private enum EntropyProfile { Testo, Eseguibile, Compresso }

        // Elenco delle estensioni ufficialmente supportate e gestite dal motore.
        // File con estensioni diverse verranno scartati a monte per evitare falsi positivi.
        private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".zip", ".gz", ".docx", ".xlsx", ".jpg", ".png",
            ".exe", ".elf", ".dll", ".sys",
            ".txt", ".json", ".xml", ".csv", ".html"
        };

        private static EntropyProfile GetExpectedProfile(string? extension)
        {
            string ext = (extension ?? "").ToLowerInvariant();
            return ext switch
            {
                ".pdf" or ".zip" or ".gz" or ".docx" or ".xlsx" or ".jpg" or ".png" => EntropyProfile.Compresso,
                ".exe" or ".elf" or ".dll" or ".sys" => EntropyProfile.Eseguibile,
                ".txt" or ".json" or ".xml" or ".csv" or ".html" => EntropyProfile.Testo,
                _ => EntropyProfile.Eseguibile
            };
        }

        // Palette Colori
        private static readonly SolidColorBrush BrushOk      = new SolidColorBrush(Color.FromRgb(0x2E, 0xCC, 0x71));
        private static readonly SolidColorBrush BrushWarning = new SolidColorBrush(Color.FromRgb(0xF3, 0x9C, 0x12));
        private static readonly SolidColorBrush BrushDanger  = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));
        private static readonly SolidColorBrush BrushPrimary = new SolidColorBrush(Color.FromRgb(0xE8, 0xEA, 0xF0));
        private static readonly SolidColorBrush BrushMuted   = new SolidColorBrush(Color.FromRgb(0x88, 0x92, 0xA4));
        private static readonly SolidColorBrush BrushCyan    = new SolidColorBrush(Color.FromRgb(0x00, 0xD4, 0xFF));

        public MainWindow()
        {
            InitializeComponent();
            _analyzerService = new PythonAnalyzerService();
            
            // Collega la griglia alla collezione
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
                    await RunBatchAnalysisAsync(filesToProcess);
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
                await RunBatchAnalysisAsync(dialog.FileNames.ToList());
        }

        private async void BtnBrowseFolder_Click(object sender, RoutedEventArgs e)
        {
            // OpenFolderDialog è nativo in .NET 8 WPF
            var dialog = new OpenFolderDialog 
            { 
                Title = "Seleziona cartelle da analizzare", 
                Multiselect = true 
            };
            
            if (dialog.ShowDialog() == true)
            {
                var filesToProcess = ResolveFiles(dialog.FolderNames);
                if (filesToProcess.Any())
                    await RunBatchAnalysisAsync(filesToProcess);
                else
                    ShowError("Nessun file trovato nelle cartelle selezionate.");
            }
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
                    catch (UnauthorizedAccessException) 
                    { 
                        // Ignora le cartelle di sistema inaccessibili
                    }
                }
            }
            return files;
        }

        // ======================================================================
        // ANALISI BATCH PARALLELA
        // ======================================================================

        private async Task RunBatchAnalysisAsync(List<string> filePaths)
        {
            SetUiAnalyzing(filePaths.Count);
            
            int total = filePaths.Count;
            int completed = 0;
            int anomalies = 0;
            
            // Limitiamo la concorrenza per evitare di sovraccaricare la RAM e il disco (I/O)
            // avviando troppi interpreti Python contemporaneamente. 
            // Usiamo la metà dei core disponibili, con un tetto massimo di 4 processi simultanei,
            // garantendo fluidità e stabilità anche su macchine più lente o con hard disk meccanici.
            int safeConcurrency = Math.Max(1, Math.Min(4, Environment.ProcessorCount / 2));
            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = safeConcurrency };

            try
            {
                // Esecuzione asincrona massiva sul ThreadPool (Background)
                await Parallel.ForEachAsync(filePaths, parallelOptions, async (filePath, ct) =>
                {
                    AnalysisResult result;
                    try
                    {
                        result = await _analyzerService.AnalyzeFileAsync(filePath);
                    }
                    catch (Exception ex)
                    {
                        // Fallback manuale: se un file crasha (es. lock, corruzione)
                        // costruiamo un result fittizio per mostrarlo rosso nella griglia
                        result = new AnalysisResult 
                        { 
                            FilePath = filePath, 
                            AnalysisStatus = "error", 
                            ErrorMessage = ex.Message 
                        };
                    }

                    // Determina se il file presenta un'anomalia forense
                    bool isAnomalous = false;
                    string verdict = "Sano";
                    
                    if (result.IsSuccess)
                    {
                        var profile = GetExpectedProfile(result.DeclaredExtension);
                        double e = result.ShannonEntropy;
                        
                        if (profile == EntropyProfile.Testo && e > 6.5) 
                        {
                            isAnomalous = true;
                            verdict = "Entropia troppo alta per un testo";
                        }
                        else if (profile == EntropyProfile.Eseguibile && e > 7.2) 
                        {
                            isAnomalous = true;
                            verdict = "Possibile eseguibile packed/offuscato";
                        }
                        else if (profile == EntropyProfile.Eseguibile && e < 3.0) 
                        {
                            isAnomalous = true;
                            verdict = "Eseguibile anomalo (entropia bassissima)";
                        }
                        else if (profile == EntropyProfile.Compresso && e < 6.0) 
                        {
                            isAnomalous = true;
                            verdict = "Falso compresso (entropia bassissima)";
                        }
                        
                        // Il sanity check ha la precedenza assoluta
                        if (!result.ExtensionMatch) 
                        {
                            isAnomalous = true;
                            verdict = "File camuffato (Magic bytes errati)";
                        }
                    }
                    else
                    {
                        isAnomalous = true; // Un errore conta come anomalia da indagare
                        verdict = "Errore di analisi";
                    }
                    
                    result.IsAnomalous = isAnomalous;
                    result.Verdict = verdict;

                    // AGGIORNAMENTO UI SINCRO:
                    // Poiché siamo in un thread worker del ThreadPool, non possiamo
                    // toccare `ScannedFiles` direttamente (causerebbe un crash WPF).
                    // Dobbiamo re-indirizzare l'aggiunta al thread principale (Dispatcher).
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        if (isAnomalous)
                        {
                            // Inserisce le anomalie in cima alla lista (indice 0)
                            ScannedFiles.Insert(0, result);
                        }
                        else
                        {
                            // Accoda i file normali in fondo
                            ScannedFiles.Add(result);
                        }
                        
                        completed++;
                        GlobalProgressBar.Value = completed;
                        TxtGlobalStatus.Text = $"Analisi in corso: {completed} / {total}";
                        
                        if (isAnomalous)
                        {
                            anomalies++;
                            TxtAnomalyCount.Text = $"Anomalie: {anomalies}";
                        }
                    });
                });
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
            
            TxtGlobalStatus.Text = $"Analisi completata. {ScannedFiles.Count} file analizzati.";
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
            if (result.IsSuccess)
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

            // Valutazione contestuale dell'entropia
            var profile = GetExpectedProfile(result.DeclaredExtension);
            double e = result.ShannonEntropy;

            TxtEntropy.Text = string.Format("{0:F6} bit/simbolo", e);
            if (result.EntropySampled)
                TxtEntropy.Text += "  (campionato)";
                
            bool anomaliaAlta = false;
            bool anomaliaBassa = false;

            switch (profile)
            {
                case EntropyProfile.Testo:
                    anomaliaAlta = e > 6.5;
                    break;
                case EntropyProfile.Eseguibile:
                    anomaliaAlta = e > 7.2;
                    anomaliaBassa = e < 3.0;
                    break;
                case EntropyProfile.Compresso:
                    anomaliaBassa = e < 6.0;
                    break;
            }

            if (anomaliaAlta)
            {
                TxtEntropy.Foreground = BrushDanger;
                TxtEntropy.Text      += "  [ANOMALIA: TROPPO ALTA]";
            }
            else if (anomaliaBassa)
            {
                TxtEntropy.Foreground = BrushWarning;
                TxtEntropy.Text      += "  [ANOMALIA: TROPPO BASSA]";
            }
            else
            {
                TxtEntropy.Foreground = BrushOk;
                TxtEntropy.Text      += "  [NELLA NORMA]";
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
}