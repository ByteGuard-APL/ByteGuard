using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
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
            foreach (var path in paths)
            {
                // Aggiunge solo file (non cartelle) e filtra i duplicati
                if (File.Exists(path) && !CryptoQueue.Any(x => x.FilePath == path))
                    CryptoQueue.Add(new CryptoFileItem { FilePath = path });
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
        // I file vengono elaborati UNO ALLA VOLTA tramite il modulo C++.
        // Ogni file e' un'operazione XOR indipendente: in caso di errore su uno
        // specifico file, gli altri non vengono bloccati.
        // Il file cifrato viene creato come NUOVO file con estensione .lock,
        // lasciando l'originale intatto.
        // ======================================================================
        private void BtnEncrypt_Click(object sender, RoutedEventArgs e)
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

                // Iteriamo file per file (approccio one-by-one)
                foreach (var item in CryptoQueue)
                {
                    // TODO: Chiamare il servizio C++ per questo singolo file:
                    // CppService.Encrypt(item.FilePath, key);
                    // Il C++ creera' item.FilePath + ".lock" lasciando l'originale intatto.
                    item.Status = "Cifrato (.lock)";
                }
                FilesDataGrid.Items.Refresh();
            }
        }

        private void BtnDecrypt_Click(object sender, RoutedEventArgs e)
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
                    // TODO: Chiamare il servizio C++ per questo singolo file:
                    // Il C++ verifichera' il checksum FNV-1a prima di decifrare.
                    // Se la chiave e' errata o il file e' stato manomesso, lancera' un'eccezione.
                    // CppService.Decrypt(item.FilePath, key);
                    item.Status = "Decifrato";
                }
                FilesDataGrid.Items.Refresh();
            }
        }
    }
}
