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
    // Uso una classe semplice. Per aggiornare la UI chiamo manualmente FilesDataGrid.Items.Refresh()
    // invece di usare robe più complesse come INotifyPropertyChanged che non mi servono qui.
    public class CryptoFileItem
    {
        public string FilePath { get; set; } = string.Empty;
        public string Name => Path.GetFileName(FilePath);
        public string Status { get; set; } = "In attesa";
    }

    public partial class CryptoPage : Page
    {
        public ObservableCollection<CryptoFileItem> CryptoQueue { get; set; }

        // Il servizio che parla con ByteGuardCrypto.exe
        private readonly CppCryptoService _cryptoService;

        public CryptoPage()
        {
            InitializeComponent();
            CryptoQueue = new ObservableCollection<CryptoFileItem>();
            // Aggiorno il contatore ogni volta che la coda cambia
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
            // Uso un iteratore per consumare i file man mano che li trovo,
            // esplorando anche le sottocartelle in modo ricorsivo.
            foreach (var file in GetFilesDaPercorso(paths))
            {
                if (!CryptoQueue.Any(x => x.FilePath == file))
                    CryptoQueue.Add(new CryptoFileItem { FilePath = file });
            }
        }

        // Uso yield return per scorrere i file uno ad uno senza allocare array giganti in RAM.
        // È molto utile se l'utente seleziona una cartella con migliaia di file.
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
        // Ogni file viene passato uno alla volta a ByteGuardCrypto.exe.
        // La password inserita nel popup viene usata per tutta la selezione corrente.
        // ======================================================================

        // Metodo async così l'interfaccia non si blocca mentre il C++ lavora.
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

                // Itero file per file: ogni file è una chiamata indipendente al C++
                foreach (var item in CryptoQueue.ToList())
                {
                    item.Status = "Cifratura in corso...";
                    FilesDataGrid.Items.Refresh();

                    // Sposto il lavoro pesante su un thread in background per lasciare libera la UI.
                    await Task.Run(async () =>
                    {
                        // Isolo l'eccezione del singolo file così se uno fallisce,
                        // il ciclo continua con il prossimo senza bloccarsi.
                        try
                        {
                            var result = await _cryptoService.EncryptAsync(item.FilePath, key);

                            // Siccome siamo in background, uso Dispatcher per toccare la UI
                            Dispatcher.Invoke(() =>
                            {
                                if (result.Success)
                                {
                                    // Mostro il nome del file .lock prodotto dal C++
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
                            // Se esplode qualcosa (es. exe non trovato), segnamo l'errore e andiamo avanti
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

        // Come sopra, metodo async per non bloccare l'interfaccia.
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
                        // Isolo l'eccezione del singolo file
                        try
                        {
                            var result = await _cryptoService.DecryptAsync(item.FilePath, key);

                            Dispatcher.Invoke(() =>
                            {
                                if (result.Success)
                                {
                                    // Il C++ verifica il checksum FNV-1a: se la chiave è sbagliata
                                    // o il file è stato manomesso, result.Success sarà false.
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
