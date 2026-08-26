// ByteGuard - CppCryptoService.cs
// Chiama l'eseguibile C++ (ByteGuardCrypto.exe) come sottoprocesso per cifrare e decifrare i file.
// Funziona esattamente come PythonAnalyzerService: avvio il processo, leggo il JSON dallo stdout e lo deserializzo.

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ByteGuard.Services
{
    // Il risultato che ByteGuardCrypto.exe stampa su stdout in formato JSON.
    // Uso un record perché i dati arrivano dall'esterno e non li modifico mai.
    public record CryptoOperationResult
    {
        // "success" o "error"
        [JsonPropertyName("status")]
        public string Status { get; init; } = "error";

        // Messaggio leggibile che spiega cosa è successo (o cosa è andato storto)
        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;

        // Percorso del file originale passato al C++
        [JsonPropertyName("original_file")]
        public string OriginalFile { get; init; } = string.Empty;

        // Percorso del file prodotto (es. documento.txt.lock); vuoto in caso di errore
        [JsonPropertyName("output_file")]
        public string OutputFile { get; init; } = string.Empty;

        // Proprietà di comodo per non dover confrontare stringhe in giro per il codice
        public bool Success => Status == "success";
    }

    public class CppCryptoService
    {
        private readonly string _executablePath;
        private readonly JsonSerializerOptions _jsonOptions;

        public CppCryptoService(string? executablePath = null)
        {
            // Grazie alla copia nel .csproj, l'eseguibile C++ si trova ora direttamente
            // nella cartella di build di ByteGuard.exe (bin/Debug).
            _executablePath = executablePath
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ByteGuardCrypto.exe");

            // Creo le opzioni una volta sola per non ricrearle ad ogni chiamata
            _jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        }

        // Cifra un file: il C++ crea <nomefile>.lock e lascia l'originale intatto
        public async Task<CryptoOperationResult> EncryptAsync(string filePath, string key)
            => await RunAsync("--encrypt", filePath, key);

        // Decifra un file .lock: il C++ verifica il checksum FNV-1a prima di procedere.
        // Se la chiave è sbagliata o il file è stato manomesso, restituisce success=false.
        public async Task<CryptoOperationResult> DecryptAsync(string filePath, string key)
            => await RunAsync("--decrypt", filePath, key);

        private async Task<CryptoOperationResult> RunAsync(string operation, string filePath, string key)
        {
            // Controllo preventivo: se l'exe non esiste, avviso subito invece di andare in crash
            if (!File.Exists(_executablePath))
                throw new FileNotFoundException(
                    $"ByteGuardCrypto.exe non trovato in:\n{_executablePath}\n\nAssicurarsi che CMake abbia completato la build.");

            var startInfo = new ProcessStartInfo
            {
                FileName               = _executablePath,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                StandardOutputEncoding = Encoding.UTF8,
            };

            // Il C++ vuole: --encrypt (o --decrypt) --key "..." --file "..."
            startInfo.ArgumentList.Add(operation);
            startInfo.ArgumentList.Add("--key");
            startInfo.ArgumentList.Add(key);
            startInfo.ArgumentList.Add("--file");
            startInfo.ArgumentList.Add(filePath);

            // Uso using così se il processo crasha libero subito le risorse
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            // Leggo stdout e stderr in parallelo per evitare che la pipe si intasi
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask);
            await process.WaitForExitAsync();

            string json = stdoutTask.Result.Trim();

            // Il C++ dovrebbe sempre stampare qualcosa su stdout (anche in caso di errore).
            // Se non stampa nulla è crashato malissimo (es. access violation).
            if (string.IsNullOrWhiteSpace(json))
            {
                string stderr = stderrTask.Result.Trim();
                string detail = string.IsNullOrWhiteSpace(stderr)
                    ? "Nessun output ricevuto."
                    : $"Stderr: {stderr}";
                throw new InvalidOperationException($"ByteGuardCrypto non ha prodotto output JSON. {detail}");
            }

            return JsonSerializer.Deserialize<CryptoOperationResult>(json, _jsonOptions)
                ?? throw new JsonException("La deserializzazione del risultato C++ ha restituito null.");
        }
    }
}
