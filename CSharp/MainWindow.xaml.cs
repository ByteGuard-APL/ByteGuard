// ByteGuard - MainWindow.xaml.cs (Code-Behind Shell)
// Gestisce esclusivamente la navigazione SPA (Single Page Application) tra i vari moduli.

using System;
using System.Windows;
using ByteGuard.Pages;

namespace ByteGuard
{
    public partial class MainWindow : Window
    {
        private AnalysisPage _analysisPage;
        private CryptoPage _cryptoPage;

        public MainWindow()
        {
            InitializeComponent();
            
            // Inizializza le pagine (mantenendole in memoria per non perdere lo stato)
            _analysisPage = new AnalysisPage();
            _cryptoPage = new CryptoPage();
            
            // Imposta la pagina di default (Analisi)
            MainFrame.Navigate(_analysisPage);
        }

        private void NavAnalysis_Click(object sender, RoutedEventArgs e)
        {
            // Ripristina la pagina di analisi preesistente
            if (MainFrame != null && _analysisPage != null)
                MainFrame.Navigate(_analysisPage);
        }

        private void NavCrypto_Click(object sender, RoutedEventArgs e)
        {
            if (MainFrame != null && _cryptoPage != null)
                MainFrame.Navigate(_cryptoPage);
        }

        private bool _isSidebarExpanded = true;
        
        private void BtnToggleSidebar_Click(object sender, RoutedEventArgs e)
        {
            _isSidebarExpanded = !_isSidebarExpanded;
            
            if (_isSidebarExpanded)
            {
                SidebarColumn.Width = new GridLength(260);
                LogoPanel.Visibility = Visibility.Visible;
                TxtModuli.Visibility = Visibility.Visible;
                TxtNavAnalysis.Visibility = Visibility.Visible;
                TxtNavCrypto.Visibility = Visibility.Visible;
                // Ripristina il padding normale
                NavAnalysis.Padding = new Thickness(15, 12, 15, 12);
                NavCrypto.Padding = new Thickness(15, 12, 15, 12);
            }
            else
            {
                SidebarColumn.Width = new GridLength(70);
                LogoPanel.Visibility = Visibility.Collapsed;
                TxtModuli.Visibility = Visibility.Collapsed;
                TxtNavAnalysis.Visibility = Visibility.Collapsed;
                TxtNavCrypto.Visibility = Visibility.Collapsed;
                // Padding ridotto: solo verticale, l'emoji si centra da sola
                NavAnalysis.Padding = new Thickness(5, 12, 5, 12);
                NavCrypto.Padding = new Thickness(5, 12, 5, 12);
            }
        }
    }
}