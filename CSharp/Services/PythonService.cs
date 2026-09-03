// ByteGuard - PythonService.cs
// Interfaccia IPC asincrona per invocare il motore di analisi forense Python.

using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ByteGuard.Services
{
    // Come per CppCryptoService, utilizzo un 'record' con init-only properties per garantire
    // l'Immutabilità del dato, conformemente ai dettami della Programmazione Funzionale.
    // L'attributo [JsonPropertyName] agisce da mapper formale tra la convenzione snake_case di Python
    // e la convenzione PascalCase standard di C#.
    public record AnalysisResult
    {
        [JsonPropertyName("file_path")]
        public string FilePath { get; init; } = string.Empty;

        [JsonPropertyName("file_size_bytes")]
        public long FileSizeBytes { get; init; }

        [JsonPropertyName("declared_extension")]
        public string? DeclaredExtension { get; init; }

        [JsonPropertyName("shannon_entropy")]
        public double ShannonEntropy { get; init; }

        [JsonPropertyName("entropy_sampled")]
        public bool EntropySampled { get; init; }

        [JsonPropertyName("magic_number_hex")]
        public string? MagicNumberHex { get; init; }

        [JsonPropertyName("magic_number_ascii")]
        public string? MagicNumberAscii { get; init; }

        [JsonPropertyName("extension_match")]
        public bool ExtensionMatch { get; init; }

        [JsonPropertyName("analysis_status")]
        public string AnalysisStatus { get; init; } = "error";

        [JsonPropertyName("error_message")]
        public string? ErrorMessage { get; init; }

        [JsonPropertyName("timestamp_utc")]
        public string TimestampUtc { get; init; } = string.Empty;

        [JsonPropertyName("is_anomalous")]
        public bool IsAnomalous { get; init; }

        [JsonPropertyName("has_double_extension")]
        public bool HasDoubleExtension { get; init; }

        [JsonPropertyName("verdict")]
        public string Verdict { get; init; } = "Sano";

        [JsonPropertyName("anomaly_code")]
        public string AnomalyCode { get; init; } = "NONE";
    }

    public class PythonAnalyzerService
    {
        private readonly string _pythonExecutable;
        private readonly string _analyzerScriptPath;
        private readonly JsonSerializerOptions _jsonOptions;

        public PythonAnalyzerService(string pythonExecutable = "python", string? analyzerScriptPath = null)
        {
            _pythonExecutable = pythonExecutable;

            // Assicuro la corretta risoluzione del percorso dello script Python a prescindere dal working directory d'avvio (es. da Visual Studio)
            _analyzerScriptPath = analyzerScriptPath
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Python", "analyzer.py");

            // Cache delle options per la deserializzazione JSON ad alte prestazioni
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            };
        }

        // Metodo asincrono basato su TAP per l'esecuzione del processo Python.
        public async Task<AnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _pythonExecutable,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false, 
                CreateNoWindow         = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding  = System.Text.Encoding.UTF8,
            };

            // ArgumentList garantisce la sanitizzazione automatica dei percorsi con spazi
            startInfo.ArgumentList.Add(_analyzerScriptPath);
            startInfo.ArgumentList.Add(filePath);

            // Pattern 'using' per smaltire il puntatore nativo dell'OS al processo al termine dello scope
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            // Come visto a lezione per la concorrenza, prevengo attivamente scenari di Deadlock dell'I/O
            // svuotando concorrentemente entrambi i buffer (stdout e stderr) usando Task.WhenAll.
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask);

            // Attendo la chiusura effettiva (graceful exit)
            await process.WaitForExitAsync();

            string jsonOutput   = stdoutTask.Result.Trim();
            string stderrOutput = stderrTask.Result.Trim();

            // Validazione dello standard output
            if (string.IsNullOrWhiteSpace(jsonOutput))
            {
                string msg = string.IsNullOrWhiteSpace(stderrOutput)
                    ? "Il processo Python ha terminato senza output su stdout."
                    : $"Errore Python (stderr): {stderrOutput}";
                throw new InvalidOperationException(msg);
            }

            // Deserializzazione del JSON raw direttamente nell'oggetto record immutabile
            AnalysisResult result = JsonSerializer.Deserialize<AnalysisResult>(jsonOutput, _jsonOptions)
                ?? throw new JsonException("La deserializzazione ha restituito null inatteso.");

            return result;
        }
    }
}
