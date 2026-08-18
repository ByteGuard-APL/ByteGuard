using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using ByteGuard.Dialogs;

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

        public CryptoPage()
        {
            InitializeComponent();
            CryptoQueue = new ObservableCollection<CryptoFileItem>();
            // Aggiorniamo il contatore ogni volta che la coda cambia
            CryptoQueue.CollectionChanged += (_, _) => TxtQueueCount.Text = CryptoQueue.Count.ToString();
            FilesDataGrid.ItemsSource = CryptoQueue;
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
        // E' molto utile se l'utente seleziona una cartella con migliaia di file.
        private IEnumerable<string> GetFilesDaPercorso(string[] paths)
        {
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    yield return path; // Restituisce un singolo file
                }
                else if (Directory.Exists(path))
                {
                    // Esplora la directory ricorsivamente e restituisce i file man mano che li trova.
                    // EnumerateFiles è già pigro (a differenza di GetFiles), e noi lo combiniamo col nostro yield.
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
            // Il Tag del bottone punta direttamente all'item del modello (impostato via XAML con Tag="{Binding}")
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
        // ======================================================================
        
        // Metodo async così l'interfaccia non si blocca ("Non risponde") mentre aspettiamo il C++.
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

                // Disabilitiamo temporaneamente i bottoni o l'interazione se necessario (omesso per brevità)
                // Iteriamo file per file (approccio sequenziale asincrono)
                foreach (var item in CryptoQueue)
                {
                    item.Status = "Cifratura in corso..."; 
                    FilesDataGrid.Items.Refresh();

                    // Sposto il lavoro pesante su un thread in background per lasciare libera la UI.
                    await Task.Run(() => 
                    {
                        // Metto il try-catch qua dentro così se un file dà errore (es. C++ crasha)
                        // non mi fa saltare tutto il ciclo e passa tranquillamente al file successivo.
                        try
                        {
                            // TODO: Chiamare il servizio C++ per questo singolo file:
                            // CppService.Encrypt(item.FilePath, key);
                            // Simuliamo il lavoro del modulo C++:
                            System.Threading.Thread.Sleep(500); 

                            // Siccome siamo in background, uso Dispatcher per toccare la UI.
                            Dispatcher.Invoke(() => 
                            {
                                item.Status = "Cifrato (.lock)";
                                FilesDataGrid.Items.Refresh();
                            });
                        }
                        catch (Exception ex)
                        {
                            // Se esplode qualcosa, segnamo l'errore e andiamo avanti col prossimo file
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

                foreach (var item in CryptoQueue)
                {
                    item.Status = "Decifratura in corso...";
                    FilesDataGrid.Items.Refresh(); // Aggiornamento manuale

                    await Task.Run(() => 
                    {
                        // Isolo l'eccezione del singolo file
                        try
                        {
                            // TODO: Chiamare il servizio C++ per questo singolo file:
                            // CppService.Decrypt(item.FilePath, key);
                            // Il C++ verificherà il checksum FNV-1a prima di decifrare e lancerà un'eccezione
                            // se la chiave è errata o il file è stato alterato.
                            System.Threading.Thread.Sleep(500); // Simulazione
                            
                            Dispatcher.Invoke(() => 
                            {
                                item.Status = "Decifrato";
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
