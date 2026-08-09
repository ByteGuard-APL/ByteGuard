// ByteGuard - PythonService.cs
// Gestisce tutta la comunicazione IPC con lo script Python:
// avvia il processo, legge lo stdout JSON e lo deserializza in un record C#.

using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ByteGuard.Services
{
    // Record C# 9+: immutabile per design (proprieta' init-only), value equality automatica.
    // Usiamo un record invece di una class perche' questo e' un DTO puro: riceve dati,
    // non li modifica mai. [JsonPropertyName] mappa snake_case Python -> PascalCase C#.
    public record AnalysisResult
    {
        [JsonPropertyName("file_path")]
        public string FilePath { get; init; } = string.Empty;

        // Proprieta' computata per la DataGrid (mostra solo il nome del file, non l'intero percorso)
        [JsonIgnore]
        public string FileName => System.IO.Path.GetFileName(FilePath);

        [JsonPropertyName("file_size_bytes")]
        public long FileSizeBytes { get; init; }

        // Proprieta' computata per la DataGrid (mostra la dimensione in formato leggibile)
        [JsonIgnore]
        public string DisplaySize
        {
            get
            {
                if (FileSizeBytes < 1024) return $"{FileSizeBytes} B";
                if (FileSizeBytes < 1024 * 1024) return $"{FileSizeBytes / 1024.0:F1} KB";
                if (FileSizeBytes < 1024L * 1024 * 1024) return $"{FileSizeBytes / (1024.0 * 1024):F2} MB";
                return $"{FileSizeBytes / (1024.0 * 1024 * 1024):F2} GB";
            }
        }

        [JsonPropertyName("declared_extension")]
        public string? DeclaredExtension { get; init; }

        /// <summary>Entropia di Shannon [0.0 - 8.0 bit/simbolo]. Sopra 7.0 e' sospetto.</summary>
        [JsonPropertyName("shannon_entropy")]
        public double ShannonEntropy { get; init; }

        /// <summary>True se il file superava 100 MB e l'entropia e' stata calcolata su un campione (inizio+meta'+fine).</summary>
        [JsonPropertyName("entropy_sampled")]
        public bool EntropySampled { get; init; }

        [JsonPropertyName("magic_number_hex")]
        public string? MagicNumberHex { get; init; }

        [JsonPropertyName("magic_number_ascii")]
        public string? MagicNumberAscii { get; init; }

        /// <summary>False se i magic byte non corrispondono all'estensione: possibile file mascherato.</summary>
        [JsonPropertyName("extension_match")]
        public bool ExtensionMatch { get; init; }

        /// <summary>"success" o "error". Controlla questo prima di leggere gli altri campi.</summary>
        [JsonPropertyName("analysis_status")]
        public string AnalysisStatus { get; init; } = "error";

        [JsonPropertyName("error_message")]
        public string? ErrorMessage { get; init; }

        [JsonPropertyName("timestamp_utc")]
        public string TimestampUtc { get; init; } = string.Empty;

        // Proprieta' calcolata, non deserializzata. La soglia 7.0 NON e' qui:
        // appartiene al layer UI (MainWindow.xaml.cs), non al DTO.
        [JsonIgnore]
        public bool IsSuccess => AnalysisStatus == "success";

        // Proprieta' computata per la DataGrid (mostra l'esito base o l'errore)
        [JsonIgnore]
        public string DisplayStatus => IsSuccess ? "Completato" : "Errore";
        
        // Flag calcolato dal motore Python per evidenziare visivamente la riga
        [JsonPropertyName("is_anomalous")]
        public bool IsAnomalous { get; init; }

        // Testo esplicativo dell'anomalia determinato dal motore Python
        [JsonPropertyName("verdict")]
        public string Verdict { get; init; } = "Sano";
    }

    public class PythonAnalyzerService
    {
        private readonly string _pythonExecutable;
        private readonly string _analyzerScriptPath;

        // JsonSerializerOptions e' costoso da creare (compila internamente dei converter):
        // lo istanziamo una sola volta nel costruttore e lo riusiamo ad ogni chiamata.
        private readonly JsonSerializerOptions _jsonOptions;

        public PythonAnalyzerService(
            string pythonExecutable = "python",
            string? analyzerScriptPath = null)
        {
            _pythonExecutable = pythonExecutable;

            // Usiamo BaseDirectory come ancora cosi' il percorso funziona sempre,
            // sia con 'dotnet run' che avviando direttamente l'exe dalla cartella di build.
            _analyzerScriptPath = analyzerScriptPath
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Python", "analyzer.py");

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            };
        }

        /// <summary>
        /// Avvia analyzer.py come sottoprocesso e restituisce il risultato deserializzato.
        /// Lancia InvalidOperationException se Python non si avvia, JsonException se l'output non e' JSON valido.
        /// </summary>
        public async Task<AnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _pythonExecutable,
                // ArgumentList gestisce automaticamente l'escaping degli spazi nei percorsi
                // (es. "C:\My Documents\file.pdf"), a differenza della proprieta' Arguments (stringa).
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,  // obbligatorio per redirigere I/O
                CreateNoWindow         = true,
                // Forza UTF-8 sul decoder della pipe: Python scrive UTF-8,
                // senza questa riga .NET userebbe cp1252 (default Windows) -> JSON corrotto.
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding  = System.Text.Encoding.UTF8,
            };

            startInfo.ArgumentList.Add(_analyzerScriptPath);
            startInfo.ArgumentList.Add(filePath);

            // 'using' garantisce Process.Dispose() anche in caso di eccezione,
            // rilasciando l'handle al processo del sistema operativo.
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            // Leggiamo stdout e stderr in parallelo con WhenAll: e' fondamentale.
            // Se aspettassimo prima uno poi l'altro, i buffer della pipe potrebbero
            // riempirsi e causare un deadlock (Python aspetta che C# svuoti il buffer,
            // C# aspetta che Python finisca -> stallo).
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask);

            // WaitForExitAsync va DOPO la lettura degli stream, non prima (vedi deadlock sopra).
            await process.WaitForExitAsync();

            string jsonOutput   = stdoutTask.Result.Trim();
            string stderrOutput = stderrTask.Result.Trim();

            // Stdout vuoto = Python e' crashato prima di stampare qualcosa (es. SyntaxError).
            // In quel caso lo stderr contiene il traceback Python.
            if (string.IsNullOrWhiteSpace(jsonOutput))
            {
                string msg = string.IsNullOrWhiteSpace(stderrOutput)
                    ? "Il processo Python ha terminato senza output su stdout."
                    : $"Errore Python (stderr): {stderrOutput}";
                throw new InvalidOperationException(msg);
            }

            // ?? throw: gestisce il caso estremo in cui il JSON sia il letterale "null"
            AnalysisResult result = JsonSerializer.Deserialize<AnalysisResult>(jsonOutput, _jsonOptions)
                ?? throw new JsonException("La deserializzazione ha restituito null inatteso.");

            return result;
        }
    }
}
