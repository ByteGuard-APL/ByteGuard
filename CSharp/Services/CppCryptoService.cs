// ByteGuard - CppCryptoService.cs
// Interfaccia IPC (Inter-Process Communication) per invocare l'eseguibile C++ (ByteGuardCrypto.exe).
// Come studiato, ho incapsulato la logica di invocazione in una classe servizio dedicata,
// disaccoppiando la UI dal sottosistema crittografico.

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ByteGuard.Services
{
    // Ho scelto di usare il costrutto 'record' invece di una 'class' convenzionale.
    // I record promuovono la Programmazione Funzionale offrendo Immutabilità di default (grazie a 'init').
    // Poiché questi dati provengono dall'esterno tramite JSON e non devono mai essere alterati a runtime,
    // il record è la struttura dati perfetta e thread-safe.
    public record CryptoOperationResult
    {
        [JsonPropertyName("status")]
        public string Status { get; init; } = "error";

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;

        [JsonPropertyName("original_file")]
        public string OriginalFile { get; init; } = string.Empty;

        [JsonPropertyName("output_file")]
        public string OutputFile { get; init; } = string.Empty;

        // Expression-bodied member per calcolare lo stato senza allocare un field
        public bool Success => Status == "success";
    }

    public class CppCryptoService
    {
        private readonly string _executablePath;
        private readonly JsonSerializerOptions _jsonOptions;

        public CppCryptoService(string? executablePath = null)
        {
            // Ottengo dinamicamente la BaseDirectory (la cartella bin/Debug in dev)
            // in cui CMake ha copiato l'eseguibile C++.
            _executablePath = executablePath
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ByteGuardCrypto.exe");

            // Cache delle opzioni JSON per ottimizzare le allocazioni di memoria
            _jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        }

        public async Task<CryptoOperationResult> EncryptAsync(string filePath, string key)
            => await RunAsync("--encrypt", filePath, key);

        public async Task<CryptoOperationResult> DecryptAsync(string filePath, string key)
            => await RunAsync("--decrypt", filePath, key);

        private async Task<CryptoOperationResult> RunAsync(string operation, string filePath, string key)
        {
            // Sanity check precoce per evitare crash in fase di avvio del processo
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

            // Invece di concatenare stringhe per 'Arguments' (che è prono a bug se i path hanno spazi o apici),
            // sfrutto la nuova 'ArgumentList' che gestisce automaticamente l'escaping degli argomenti.
            startInfo.ArgumentList.Add(operation);
            startInfo.ArgumentList.Add("--key");
            startInfo.ArgumentList.Add(key);
            startInfo.ArgumentList.Add("--file");
            startInfo.ArgumentList.Add(filePath);

            // Il blocco 'using' assicura che il puntatore nativo al processo venga rilasciato 
            // determinando la chiamata a Dispose() anche in caso di eccezioni.
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            // OTTIMIZZAZIONE DEADLOCK: Leggo stdout e stderr in parallelo usando Task.WhenAll.
            // Se leggessi prima tutto lo stdout usando un costrutto sincrono o sequenziale,
            // un buffer stderr pieno da parte del C++ potrebbe bloccare permanentemente il processo figlio (pipe intasata).
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask);
            await process.WaitForExitAsync();

            string json = stdoutTask.Result.Trim();

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
