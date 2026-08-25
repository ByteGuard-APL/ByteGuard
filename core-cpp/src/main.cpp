#include "ByteGuardCrypto.hpp"

#include <iostream>      // std::cout, std::cerr — standard I/O streams
#include <format>        // std::format (C++20) — formattazione type-safe
#include <string>        // std::string
#include <string_view>   // std::string_view
#include <vector>        // std::vector — per memorizzare argv parsato
#include <optional>      // std::optional (C++17) — valore che potrebbe non esistere
#include <cstdlib>       // EXIT_SUCCESS, EXIT_FAILURE

#include <nlohmann/json.hpp>  // nlohmann::json — serializzazione JSON


// Namespace anonimo per conferire internal linkage alle funzioni helper, limitandone lo scope a questa translation uni
namespace {

struct CliArgs {
    bool encrypt = false;
    bool decrypt = false;
    bool show_help = false;
    std::optional<std::string> key;
    std::optional<std::string> file;
};


/*
 * ────────────────────────────────────────────────────────────────────────────
 *  print_usage — Stampa il Messaggio di Help della CLI
 * ────────────────────────────────────────────────────────────────────────────
 */
void print_usage()
{
    // Utilizziamo \n invece di std::endl per evitare flush del buffer non necessari

    std::cerr << R"(
╔══════════════════════════════════════════════════════════════╗
║               ByteGuard Crypto Module v1.0.0                ║
║          Cifratura/Decifratura e Autenticazione              ║
╚══════════════════════════════════════════════════════════════╝

USO:
    ByteGuardCrypto --encrypt --key "<chiave>" --file "<percorso>"
    ByteGuardCrypto --decrypt --key "<chiave>" --file "<percorso>"
    ByteGuardCrypto --help

OPZIONI:
    --encrypt       Cifra il file specificato. Produce un file .lock
    --decrypt       Decifra un file .lock. Ripristina il file originale
    --key "<val>"   Chiave di cifratura/decifratura (obbligatoria)
    --file "<path>" Percorso del file da processare (obbligatorio)
    --help          Mostra questo messaggio di aiuto

OUTPUT:
    JSON su stdout con i seguenti campi:
      - status:        "success" | "error"
      - message:       Descrizione dell'esito
      - original_file: Percorso del file sorgente
      - output_file:   Percorso del file prodotto (vuoto in caso di errore)

ESEMPI:
    ByteGuardCrypto --encrypt --key "MySecretKey" --file "documento.txt"
    ByteGuardCrypto --decrypt --key "MySecretKey" --file "documento.txt.lock"
)" << '\n';
}

auto parse_args(int argc, char* argv[]) -> CliArgs
{
    CliArgs args;

    /*
     * Convertiamo argv in un vector<string_view> per lavorare con tipi
     * C++ moderni. La conversione è O(n) ma n = argc è tipicamente < 10.
     *
     * Partiamo da indice 1: argv[0] è il nome dell'eseguibile, non un
     * argomento dell'utente.
     */
    std::vector<std::string_view> tokens;
    tokens.reserve(static_cast<std::size_t>(argc));
    for (int i = 1; i < argc; ++i) {
        tokens.emplace_back(argv[i]);
    }

    for (std::size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "--encrypt") {
            args.encrypt = true;
        } else if (tokens[i] == "--decrypt") {
            args.decrypt = true;
        } else if (tokens[i] == "--help" || tokens[i] == "-h") {
            args.show_help = true;
        } else if (tokens[i] == "--key") {
            /*
             * L'argomento successivo è il valore della chiave.
             * Verifichiamo che esista (i + 1 < tokens.size()) prima
             * di accedervi, per evitare out-of-bounds access.
             */
            if (i + 1 < tokens.size()) {
                ++i;  // Consumiamo il token successivo
                args.key = std::string(tokens[i]);
            }
            // Se manca il valore, key rimane std::nullopt (disengaged)
        } else if (tokens[i] == "--file") {
            if (i + 1 < tokens.size()) {
                ++i;
                args.file = std::string(tokens[i]);
            }
        }
        // Token non riconosciuti sono silenziosamente ignorati.
        // In una CLI di produzione, si emetterebbe un warning.
    }

    return args;
}

auto make_json_output(
    const byteguard::crypto::CryptoResult& result) -> nlohmann::json
{
    /*
     * nlohmann::json::object() crea un oggetto JSON vuoto.
     * L'uso di ordered_json (alias nlohmann::ordered_json) preserverebbe
     * l'ordine di inserimento dei campi. Usiamo il json standard
     * (std::map-based) per semplicità; l'ordine dei campi in JSON
     * è semanticamente irrilevante per il parser C#.
     */
    nlohmann::json output;

    output["status"] = result.success ? "success" : "error";
    output["message"] = result.message;
    output["original_file"] = result.source_file;
    output["output_file"] = result.output_file;

    return output;
}


/*
 * ────────────────────────────────────────────────────────────────────────────
 *  make_error_json — Costruisce un JSON di Errore da un Messaggio Testuale
 * ────────────────────────────────────────────────────────────────────────────
 *
 *  Funzione di supporto per errori che non hanno un CryptoResult
 *  (es. errori di parsing degli argomenti, errori di validazione pre-core).
 *
 * ────────────────────────────────────────────────────────────────────────────
 */
auto make_error_json(std::string_view message) -> nlohmann::json
{
    nlohmann::json output;

    output["status"] = "error";
    output["message"] = message;
    output["original_file"] = "";
    output["output_file"] = "";

    return output;
}

}

int main(int argc, char* argv[])
{
    try {
        // ── Parsing degli Argomenti ──────────────────────────────────────

        const auto args = parse_args(argc, argv);

        // ── Help ─────────────────────────────────────────────────────────

        if (args.show_help) {
            print_usage();
            return EXIT_SUCCESS;
        }

        // ── Validazione: modalità operativa ──────────────────────────────

        /*
         * Verifica mutua esclusività: encrypt e decrypt non possono
         * essere attivi contemporaneamente. Almeno uno deve essere attivo.
         */
        if (args.encrypt && args.decrypt) {
            const auto error_json = make_error_json(
                "Le opzioni --encrypt e --decrypt sono mutuamente esclusive. "
                "Specificarne una sola.");

            /*
             * dump(4) serializza il JSON con indentazione di 4 spazi.
             * Questo produce output leggibile per il debugging umano.
             * In produzione, si potrebbe usare dump() (senza argomenti)
             * per output compatto.
             */
            std::cout << error_json.dump(4) << std::endl;
            return EXIT_FAILURE;
        }

        if (!args.encrypt && !args.decrypt) {
            const auto error_json = make_error_json(
                "Nessuna operazione specificata. Usare --encrypt o --decrypt. "
                "Per l'aiuto: --help");
            std::cout << error_json.dump(4) << std::endl;
            return EXIT_FAILURE;
        }

        // ── Validazione: parametri obbligatori ───────────────────────────

        /*
         * has_value() verifica se l'optional è engaged (contiene un valore).
         * È equivalente a operator bool() ma più esplicito.
         */
        if (!args.key.has_value()) {
            const auto error_json = make_error_json(
                "Chiave mancante. Specificare --key \"<chiave>\"");
            std::cout << error_json.dump(4) << std::endl;
            return EXIT_FAILURE;
        }

        if (!args.file.has_value()) {
            const auto error_json = make_error_json(
                "File mancante. Specificare --file \"<percorso>\"");
            std::cout << error_json.dump(4) << std::endl;
            return EXIT_FAILURE;
        }

        // ── Invocazione del Core ─────────────────────────────────────────

        byteguard::crypto::CryptoResult result;

        if (args.encrypt) {
            result = byteguard::crypto::ByteGuardCrypto::encrypt(
                args.file.value(), args.key.value());
        } else {
            result = byteguard::crypto::ByteGuardCrypto::decrypt(
                args.file.value(), args.key.value());
        }

        // ── Output JSON ──────────────────────────────────────────────────

        const auto output_json = make_json_output(result);

        // Qui è richiesto esplicitamente std::endl per forzare il flush dello stream e trasmettere il JSON alla GUI chiamante
        std::cout << output_json.dump(4) << std::endl;

        return result.success ? EXIT_SUCCESS : EXIT_FAILURE;

    } catch (const std::exception& e) {
        /*
         * Catch di sicurezza per eccezioni non gestite dal Core.
         * Produce comunque JSON valido su stdout.
         */
        const auto error_json = make_error_json(
            std::format("Errore critico non gestito: {}", e.what()));
        std::cout << error_json.dump(4) << std::endl;
        return EXIT_FAILURE;

    } catch (...) {
        /*
         * Catch-all per eccezioni non-std (es. integer thrown, eccezioni
         * da librerie C wrappate). Questo è l'ultima linea di difesa.
         */
        const auto error_json = make_error_json(
            "Errore critico sconosciuto (eccezione non-standard).");
        std::cout << error_json.dump(4) << std::endl;
        return EXIT_FAILURE;
    }
}
