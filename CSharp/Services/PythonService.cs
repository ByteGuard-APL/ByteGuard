// ByteGuard - PythonService.cs
// Classe per gestire l'avvio di Python e leggere i suoi risultati in JSON.
// Riceve l'output, lo parsa e lo butta dentro il record AnalysisResult.

using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ByteGuard.Services
{
    // Uso un record invece di una classe perché serve solo a contenere dati che ricevo da Python
    // e non li devo modificare in giro per il codice. Inoltre mappa lo snake_case di Python nel nostro PascalCase.
    public record AnalysisResult
    {
        [JsonPropertyName("file_path")]
        public string FilePath { get; init; } = string.Empty;

        [JsonPropertyName("file_size_bytes")]
        public long FileSizeBytes { get; init; }

        [JsonPropertyName("declared_extension")]
        public string? DeclaredExtension { get; init; }

        // Entropia da 0 a 8. Se è troppo alta (tipo > 7) puzza di file criptato o compresso male.
        [JsonPropertyName("shannon_entropy")]
        public double ShannonEntropy { get; init; }

        // Vero se il file era troppo grosso e l'ho campionato per non metterci una vita.
        [JsonPropertyName("entropy_sampled")]
        public bool EntropySampled { get; init; }

        [JsonPropertyName("magic_number_hex")]
        public string? MagicNumberHex { get; init; }

        [JsonPropertyName("magic_number_ascii")]
        public string? MagicNumberAscii { get; init; }

        // Falso se l'estensione è fake (es. un .exe mascherato da .pdf).
        [JsonPropertyName("extension_match")]
        public bool ExtensionMatch { get; init; }

        // Da guardare subito: può essere "success" o "error".
        [JsonPropertyName("analysis_status")]
        public string AnalysisStatus { get; init; } = "error";

        [JsonPropertyName("error_message")]
        public string? ErrorMessage { get; init; }

        [JsonPropertyName("timestamp_utc")]
        public string TimestampUtc { get; init; } = string.Empty;

        // Flag calcolato dal motore Python per evidenziare visivamente la riga
        [JsonPropertyName("is_anomalous")]
        public bool IsAnomalous { get; init; }

        [JsonPropertyName("has_double_extension")]
        public bool HasDoubleExtension { get; init; }

        // Testo esplicativo dell'anomalia determinato dal motore Python
        [JsonPropertyName("verdict")]
        public string Verdict { get; init; } = "Sano";

        [JsonPropertyName("anomaly_code")]
        public string AnomalyCode { get; init; } = "NONE";
    }

    public class PythonAnalyzerService
    {
        private readonly string _pythonExecutable;
        private readonly string _analyzerScriptPath;

        // Creo le opzioni JSON una volta sola nel costruttore così è più veloce e non le ricreo ad ogni analisi.
        private readonly JsonSerializerOptions _jsonOptions;

        public PythonAnalyzerService(string pythonExecutable = "python", string? analyzerScriptPath = null)
        {
            _pythonExecutable = pythonExecutable;

            // Uso BaseDirectory così i percorsi funzionano sia da VS Studio che avviando l'exe normalmente.
            _analyzerScriptPath = analyzerScriptPath
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Python", "analyzer.py");

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            };
        }

        // Lancia Python passandogli il file e mi restituisce l'oggetto deserializzato pronto all'uso.
        public async Task<AnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _pythonExecutable,
                // Uso ArgumentList per non impazzire con gli spazi nei percorsi dei file.
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,  // obbligatorio per redirigere I/O
                CreateNoWindow         = true,
                // Forzo UTF-8 altrimenti i caratteri strani o accentati mi sballano il JSON.
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding  = System.Text.Encoding.UTF8,
            };

            startInfo.ArgumentList.Add(_analyzerScriptPath);
            startInfo.ArgumentList.Add(filePath);

            // Uso using così se crasha tutto libero la memoria del processo (evito processi zombie)
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            // Leggo output ed errori in parallelo per evitare che la pipe si intasi e si blocchi tutto all'infinito.
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask);

            // Aspetto che Python si chiuda DOPO aver letto tutto.
            await process.WaitForExitAsync();

            string jsonOutput   = stdoutTask.Result.Trim();
            string stderrOutput = stderrTask.Result.Trim();

            // Se Python non stampa nulla vuol dire che è crashato malissimo (es. errore di sintassi).
            if (string.IsNullOrWhiteSpace(jsonOutput))
            {
                string msg = string.IsNullOrWhiteSpace(stderrOutput)
                    ? "Il processo Python ha terminato senza output su stdout."
                    : $"Errore Python (stderr): {stderrOutput}";
                throw new InvalidOperationException(msg);
            }

            // Se per caso Deserialize mi dà null, lancio un'eccezione per non impazzire a cercare l'errore dopo.
            AnalysisResult result = JsonSerializer.Deserialize<AnalysisResult>(jsonOutput, _jsonOptions)
                ?? throw new JsonException("La deserializzazione ha restituito null inatteso.");

            return result;
        }
    }
}
