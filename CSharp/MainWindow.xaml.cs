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
using System.Windows.Data;
using System.Windows.Media;
using System.Diagnostics;
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
        // ANALISI BATCH PARALLELA
        // ======================================================================
        private async Task RunBatchAnalysisAsync(List<string> filePaths)
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
                            // Fallback manuale: se un file crasha (es. lock, corruzione)
                            result = new AnalysisResult 
                            { 
                                FilePath = filePath, 
                                AnalysisStatus = "error", 
                                ErrorMessage = ex.Message 
                            };
                        }

                        if (result.AnalysisStatus != "success")
                        {
                            // Se l'errore è stato generato in C#, lo marchiamo manualmente come anomalo
                            result = result with 
                            { 
                                IsAnomalous = true,
                                Verdict = "Errore di analisi",
                                AnomalyCode = "ANALYSIS_ERROR"
                            };
                        }
                        return result;
                    });

                    // Attendiamo il completamento parallelo dell'intero pacchetto.
                    // Al termine, riprendiamo automaticamente l'esecuzione sul thread della UI.
                    var results = await Task.WhenAll(tasks);

                    // Aggiornamento UI a Blocchi (niente Dispatcher necessario)
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