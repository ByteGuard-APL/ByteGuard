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
using ByteGuard.Dialogs;
using ByteGuard.Services;

namespace ByteGuard.Pages
{
    public class CryptoFileItem
    {
        public string FilePath { get; set; } = string.Empty;
        public string Name => Path.GetFileName(FilePath);
        public string Status { get; set; } = "In attesa";
    }

    public partial class CryptoPage : Page
    {
        public ObservableCollection<CryptoFileItem> CryptoQueue { get; set; }

        // Servizio che incapsula la comunicazione inter-processo (IPC) con ByteGuardCrypto.exe (C++)
        private readonly CppCryptoService _cryptoService;

        public CryptoPage()
        {
            InitializeComponent();
            CryptoQueue = new ObservableCollection<CryptoFileItem>();
            // Sfrutto un event handler "anonimo" (Lambda Expression) per aggiornare il contatore della coda.
            CryptoQueue.CollectionChanged += (_, _) => TxtQueueCount.Text = CryptoQueue.Count.ToString();
            FilesDataGrid.ItemsSource = CryptoQueue;
            _cryptoService = new CppCryptoService();
        }

        // ======================================================================
        // DROP ZONE E SELEZIONE FILE
        // ======================================================================
        private void DropZone_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                DropZoneBorder.Background = new SolidColorBrush(Color.FromRgb(0x0F, 0x34, 0x60));
                TxtDropPrompt.Text = "Rilascia per aggiungere alla coda";
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void DropZone_DragLeave(object sender, DragEventArgs e)
        {
            DropZoneBorder.Background = new SolidColorBrush(Color.FromRgb(0x0D, 0x1B, 0x2A));
            TxtDropPrompt.Text = "Trascina i file qui per aggiungerli alla coda";
        }

        private void DropZone_Drop(object sender, DragEventArgs e)
        {
            DropZone_DragLeave(sender, e);
            // Come in AnalysisPage, applico il Declaration Pattern per la type safety in fase di unboxing dell'evento.
            if (e.Data.GetData(DataFormats.FileDrop) is string[] droppedItems)
                AddFilesToQueue(droppedItems);
        }

        private void BtnBrowseFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Seleziona file per crittografia",
                Multiselect = true
            };
            if (dialog.ShowDialog() == true)
                AddFilesToQueue(dialog.FileNames);
        }

        private void AddFilesToQueue(string[] paths)
        {
            // Consumo l'iteratore generato da GetFilesDaPercorso.
            // Uso LINQ (Any) per evitare l'inserimento di duplicati.
            foreach (var file in GetFilesDaPercorso(paths))
            {
                if (!CryptoQueue.Any(x => x.FilePath == file))
                    CryptoQueue.Add(new CryptoFileItem { FilePath = file });
            }
        }

        // OTTIMIZZAZIONE ALGORITMICA: Uso yield return (Lazy Evaluation) per iterare i file.
        // Restituendo un IEnumerable invece di costruire una List<string>, evito del tutto 
        // l'allocazione massiva di memoria nel caso in cui l'utente scelga cartelle enormi.
        private IEnumerable<string> GetFilesDaPercorso(string[] paths)
        {
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    yield return path;
                }
                else if (Directory.Exists(path))
                {
                    // La chiamata ad EnumerateFiles è essa stessa lazy.
                    foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                    {
                        yield return file;
                    }
                }
            }
        }

        // ======================================================================
        // GESTIONE CODA
        // ======================================================================

        private void BtnRemoveFile_Click(object sender, RoutedEventArgs e)
        {
            // Il Tag del bottone punta direttamente all'item (impostato via XAML con Tag="{Binding}")
            if (sender is Button btn && btn.Tag is CryptoFileItem item)
                CryptoQueue.Remove(item);
        }

        private void BtnClearQueue_Click(object sender, RoutedEventArgs e)
        {
            if (CryptoQueue.Count == 0) return;

            var res = MessageBox.Show(
                $"Sei sicuro di voler rimuovere tutti i {CryptoQueue.Count} file dalla coda?",
                "Svuota Coda", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (res == MessageBoxResult.Yes)
                CryptoQueue.Clear();
        }

        // ======================================================================
        // OPERAZIONI CRITTOGRAFICHE
        // Ogni file viene elaborato in modo indipendente, inoltrando il lavoro a ByteGuardCrypto.exe (C++).
        // ======================================================================

        // Ho marcato il metodo come "async" per poter usare l'operatore "await".
        // Senza TAP (Task-based Asynchronous Pattern), il thread UI si congelerebbe (frezeerebbe)
        // in attesa che il processo C++ finisca di crittografare gigabyte di file.
        private async void BtnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (CryptoQueue.Count == 0)
            {
                MessageBox.Show("Aggiungi dei file alla coda prima di procedere.", "Attenzione", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new PasswordDialog { Owner = Window.GetWindow(this) };
            if (dialog.ShowDialog() == true)
            {
                string key = dialog.Password;

                // Itero file per file: ogni file è una chiamata indipendente.
                foreach (var item in CryptoQueue.ToList())
                {
                    item.Status = "Cifratura in corso...";
                    FilesDataGrid.Items.Refresh();

                    // Sposto il lavoro pesante di I/O (la chiamata al C++) su un thread in background gestito dal ThreadPool (Task.Run).
                    // In questo modo, il thread della UI è istantaneamente libero di disegnare la progress bar o l'hover sui bottoni.
                    await Task.Run(async () =>
                    {
                        // Incapsulo il singolo task in un blocco try/catch: se il C++ va in crash su un file specifico,
                        // non voglio che l'intero ciclo di elaborazione degli altri file si interrompa bruscamente.
                        try
                        {
                            var result = await _cryptoService.EncryptAsync(item.FilePath, key);

                            // Visto che siamo dentro Task.Run (su un thread di background), non posso toccare direttamente i controlli WPF (la DataGrid).
                            // Uso Dispatcher.Invoke per "rimbalzare" la chiamata sul thread principale (il thread UI) in modo thread-safe.
                            Dispatcher.Invoke(() =>
                            {
                                if (result.Success)
                                {
                                    // Mostro il nome del file .lock (Append .lock all'estensione originale).
                                    string lockName = Path.GetFileName(result.OutputFile);
                                    item.Status = $"Cifrato → {lockName}";
                                }
                                else
                                {
                                    item.Status = $"Errore: {result.Message}";
                                }
                                FilesDataGrid.Items.Refresh();
                            });
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                item.Status = $"Errore: {ex.Message}";
                                FilesDataGrid.Items.Refresh();
                            });
                        }
                    });
                }
            }
        }

        // Il processo di decifratura segue la stessa identica architettura asincrona (TAP) usata in BtnEncrypt_Click.
        private async void BtnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (CryptoQueue.Count == 0)
            {
                MessageBox.Show("Aggiungi dei file alla coda prima di procedere.", "Attenzione", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new PasswordDialog { Owner = Window.GetWindow(this) };
            if (dialog.ShowDialog() == true)
            {
                string key = dialog.Password;

                foreach (var item in CryptoQueue.ToList())
                {
                    item.Status = "Decifratura in corso...";
                    FilesDataGrid.Items.Refresh();

                    await Task.Run(async () =>
                    {
                        try
                        {
                            var result = await _cryptoService.DecryptAsync(item.FilePath, key);

                            Dispatcher.Invoke(() =>
                            {
                                if (result.Success)
                                {
                                    // Il C++ calcola e verifica rigorosamente l'hash FNV-1a.
                                    // Se la password è sbagliata o il file binario è stato alterato, 
                                    // l'eseguibile C++ lo segnala e result.Success è false.
                                    string restoredName = Path.GetFileName(result.OutputFile);
                                    item.Status = $"Decifrato → {restoredName}";
                                }
                                else
                                {
                                    item.Status = $"Errore: {result.Message}";
                                }
                                FilesDataGrid.Items.Refresh();
                            });
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                item.Status = $"Errore: {ex.Message}";
                                FilesDataGrid.Items.Refresh();
                            });
                        }
                    });
                }
            }
        }
    }
}
