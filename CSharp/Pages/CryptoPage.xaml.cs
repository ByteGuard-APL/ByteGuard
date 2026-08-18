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
    // Approccio didattico: classe semplice. L'aggiornamento della griglia 
    // viene forzato manualmente da codice tramite FilesDataGrid.Items.Refresh()
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
            // Iteratori Personalizzati (Yield Return): 
            // Consuma l'iteratore in modo "pigro" (lazy), aggiungendo file man mano che 
            // vengono scoperti anche all'interno di sottocartelle espanse ricorsivamente.
            foreach (var file in GetFilesDaPercorso(paths))
            {
                if (!CryptoQueue.Any(x => x.FilePath == file))
                    CryptoQueue.Add(new CryptoFileItem { FilePath = file });
            }
        }

        // Iteratori Personalizzati (Yield Return)
        // Questo metodo genera una sequenza di stringhe. Invece di allocare in memoria
        // una lista gigantesca con tutti i percorsi dei file (es. 10.000 file), 'yield return'
        // restituisce un file alla volta e sospende l'esecuzione, ottimizzando la memoria (O(1)).
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
        
        // Programmazione Asincrona (Task & Await)
        // Usiamo async void poiché si tratta di un gestore di eventi UI top-level.
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

                    // Spostiamo il carico computazionale (crittografia C++) su un thread in background.
                    // In questo modo, l'interfaccia (Main Thread) resta responsiva e non si congela.
                    await Task.Run(() => 
                    {
                        // Gestione Eccezioni (Try-Catch Isolato)
                        // Isoliamo l'operazione. Se un file fallisce, l'eccezione viene catturata qui,
                        // evitando il blocco totale del ciclo foreach sugli altri file.
                        try
                        {
                            // TODO: Chiamare il servizio C++ per questo singolo file:
                            // CppService.Encrypt(item.FilePath, key);
                            // Simuliamo il lavoro del modulo C++:
                            System.Threading.Thread.Sleep(500); 

                            // Aggiorniamo la UI usando il Dispatcher poiché Task.Run è su un thread di background.
                            Dispatcher.Invoke(() => 
                            {
                                item.Status = "Cifrato (.lock)";
                                FilesDataGrid.Items.Refresh();
                            });
                        }
                        catch (Exception ex)
                        {
                            // Segnaliamo l'errore sul singolo file e permettiamo al ciclo di continuare.
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

        // Programmazione Asincrona (Task & Await)
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
                        // Gestione Eccezioni (Try-Catch Isolato)
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
