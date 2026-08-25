// Implementazione del Modulo di Cifratura Forense

#include "ByteGuardCrypto.hpp"

#include <fstream>       // std::ifstream, std::ofstream — RAII file streams
#include <stdexcept>     // std::runtime_error — eccezioni tipizzate
#include <format>        // std::format (C++20) — formattazione type-safe
#include <algorithm>     // std::equal — confronto di range
#include <utility>       // std::move — cast a rvalue reference


namespace byteguard::crypto {

auto ByteGuardCrypto::compute_fnv1a(
    std::span<const std::byte> data) -> std::uint64_t
{
    auto hash = FNV1A_OFFSET_BASIS;

    for (const auto byte : data) {
        hash ^= std::to_integer<std::uint64_t>(byte);
        hash *= FNV1A_PRIME;
    }

    return hash;
}

auto ByteGuardCrypto::compute_fnv1a_file(
    const std::filesystem::path& file_path) -> std::uint64_t
{
    // Sfruttiamo il pattern RAII (Resource Acquisition Is Initialization) con std::ifstream: la risorsa viene acquisita nel costruttore e il rilascio (close) avviene automaticamente nel distruttore,
    // garantendo l'exception safety

    std::ifstream in_file(file_path, std::ios::binary);
    if (!in_file) {
        throw std::runtime_error(
            std::format("Impossibile aprire il file per il calcolo dell'hash: {}",
                        file_path.string()));
    }

    auto hash = FNV1A_OFFSET_BASIS;

    std::vector<std::byte> buffer(CHUNK_SIZE);

    while (in_file.read(reinterpret_cast<char*>(buffer.data()),
                        static_cast<std::streamsize>(CHUNK_SIZE))) {
        const auto bytes_read = static_cast<std::size_t>(in_file.gcount());
        const std::span<const std::byte> chunk(buffer.data(), bytes_read);

        /*
         * Hashing incrementale: processiamo il chunk corrente aggiornando
         * lo stato dell'hash. L'ordine di elaborazione dei byte è preservato
         * (stream sequenziale), quindi l'hash finale è deterministico.
         */
        for (const auto byte : chunk) {
            hash ^= std::to_integer<std::uint64_t>(byte);
            hash *= FNV1A_PRIME;
        }
    }

    /*
     * Processamento dell'ultimo chunk parziale.
     * Dopo l'uscita dal while, gcount() contiene i byte dell'ultimo
     * read() parziale (se il file non è un multiplo esatto di CHUNK_SIZE).
     */
    const auto remaining = static_cast<std::size_t>(in_file.gcount());
    if (remaining > 0) {
        const std::span<const std::byte> last_chunk(buffer.data(), remaining);
        for (const auto byte : last_chunk) {
            hash ^= std::to_integer<std::uint64_t>(byte);
            hash *= FNV1A_PRIME;
        }
    }

    /*
     * Il distruttore di `in_file` chiude automaticamente il file descriptor
     * all'uscita dalla funzione (RAII). Non serve una chiamata esplicita
     * a close(). Anche se un'eccezione venisse lanciata prima di questo
     * punto, il distruttore verrebbe comunque invocato durante lo
     * stack unwinding, prevenendo resource leak.
     */
    return hash;
}

void ByteGuardCrypto::xor_transform_chunk(std::span<std::byte> chunk,
                                           std::string_view key,
                                           std::size_t key_offset)
{

     // Il modulo `%` implementa la cifratura polialfabetica: la chiave
     // si "ripete" ciclicamente per tutta la lunghezza dei dati.

    const auto key_len = key.size();

    for (std::size_t i = 0; i < chunk.size(); ++i) {
        chunk[i] ^= static_cast<std::byte>(key[(key_offset + i) % key_len]);
    }
}


/*
 *  Layout di Serializzazione
 *  ────────────────────────────────────────────
 *
 *    Offset  Dim.  Campo
 *    ──────  ────  ──────────────────────────────
 *     0       8    magic[8]           (BGUARD01)
 *     8       4    version            (uint32_t)
 *    12       8    original_size      (uint64_t)
 *    20       8    content_hash       (uint64_t)
 *    28       4    filename_length    (uint32_t)
 *    32       N    original_filename  (N byte, UTF-8)
 *    ──────  ────  ──────────────────────────────
 *    Totale: 32 + N byte
 *
 * ────────────────────────────────────────────────────────────────────────────
 */
void ByteGuardCrypto::write_header(std::ofstream& out_stream,
                                    const LockFileHeader& header)
{
    // Utilizzo di reinterpret_cast per una re-interpretazione bitwise low-level, necessaria per la serializzazione

    // 1. Magic Number — identificazione del formato
    out_stream.write(
        reinterpret_cast<const char*>(header.magic.data()),
        static_cast<std::streamsize>(header.magic.size()));

    // 2. Versione del protocollo
    out_stream.write(
        reinterpret_cast<const char*>(&header.version),
        sizeof(header.version));

    // 3. Dimensione del file originale
    out_stream.write(
        reinterpret_cast<const char*>(&header.original_size),
        sizeof(header.original_size));

    // 4. Hash FNV-1a del contenuto originale
    out_stream.write(
        reinterpret_cast<const char*>(&header.content_hash),
        sizeof(header.content_hash));

    // 5. Lunghezza del filename originale
    out_stream.write(
        reinterpret_cast<const char*>(&header.filename_length),
        sizeof(header.filename_length));

    // 6. Filename originale (N byte, senza null terminator)
    //    Usiamo header.filename_length anziché original_filename.size()
    //    per coerenza con il formato serializzato.
    out_stream.write(
        header.original_filename.data(),
        static_cast<std::streamsize>(header.filename_length));

    /*
     * Verifica che la scrittura sia andata a buon fine.
     * fail() restituisce true se si è verificato un errore logico
     * (es. disco pieno, permessi negati) durante le operazioni
     * di scrittura precedenti. Questo è preferibile a controllare
     * ogni singola write() perché gli stream I/O di C++ sono
     * "sticky": una volta in stato di errore, rimangono tali.
     */
    if (out_stream.fail()) {
        throw std::runtime_error("Errore durante la scrittura dell'header nel file .lock");
    }
}

auto ByteGuardCrypto::read_header(
    std::ifstream& in_stream) -> LockFileHeader
{
    LockFileHeader header;

    // 1. Lettura e validazione del Magic Number
    in_stream.read(
        reinterpret_cast<char*>(header.magic.data()),
        static_cast<std::streamsize>(header.magic.size()));

    if (in_stream.fail()) {
        throw std::runtime_error(
            "Errore di lettura: impossibile leggere il magic number. "
            "Il file potrebbe essere troncato o corrotto.");
    }

    // std::equal confronta due range elemento per elemento.
    if (!std::equal(header.magic.begin(), header.magic.end(),
                    MAGIC_BYTES.begin())) {
        throw std::runtime_error(
            "Magic number non valido: il file non è un file .lock ByteGuard. "
            "Atteso: BGUARD01");
    }

    // 2. Lettura e validazione della versione
    in_stream.read(
        reinterpret_cast<char*>(&header.version),
        sizeof(header.version));

    if (header.version != FORMAT_VERSION) {
        throw std::runtime_error(
            std::format("Versione del formato non supportata: {}. "
                        "Versione attesa: {}",
                        header.version, FORMAT_VERSION));
    }

    // 3. Lettura dei campi numerici
    in_stream.read(
        reinterpret_cast<char*>(&header.original_size),
        sizeof(header.original_size));

    in_stream.read(
        reinterpret_cast<char*>(&header.content_hash),
        sizeof(header.content_hash));

    in_stream.read(
        reinterpret_cast<char*>(&header.filename_length),
        sizeof(header.filename_length));

    if (in_stream.fail()) {
        throw std::runtime_error(
            "Errore di lettura: header del file .lock incompleto o corrotto.");
    }

    /*
     * Validiamo filename_length prima di usarlo per allocare memoria.
     * Un valore maliziosamente grande (es. 0xFFFFFFFF = ~4 GB) potrebbe
     * causare un'allocazione di memoria enorme (denial-of-service).
     *
     * Il limite di 4096 byte è ragionevole: la maggior parte dei filesystem
     * limita i nomi dei file a 255 byte. 4096 è generoso
     * ma previene allocazioni degeneri.
     */
    constexpr std::uint32_t MAX_FILENAME_LENGTH = 4096;
    if (header.filename_length > MAX_FILENAME_LENGTH) {
        throw std::runtime_error(
            std::format("Lunghezza del filename nell'header non valida: {} byte. "
                        "Massimo consentito: {} byte. Il file potrebbe essere corrotto.",
                        header.filename_length, MAX_FILENAME_LENGTH));
    }

    // 4. Lettura del filename originale
    //    resize() alloca esattamente filename_length byte nel buffer di std::string.
    //    Scriviamo direttamente nel buffer interno della stringa tramite data().
    header.original_filename.resize(header.filename_length);
    in_stream.read(
        header.original_filename.data(),
        static_cast<std::streamsize>(header.filename_length));

    if (in_stream.fail()) {
        throw std::runtime_error(
            "Errore di lettura: impossibile leggere il nome del file originale dall'header.");
    }

    return header;
}

auto ByteGuardCrypto::encrypt(std::string_view file_path,
                               std::string_view key) -> CryptoResult
{
    // Catturiamo le eccezioni per const reference (const std::exception&) per evitare l'object slicing e preservare il comportamento polimorfico
    try {
        // ── Fase 1: Validazione degli Input ──────────────────────────────

        if (key.empty()) {
            return CryptoResult{
                .success = false,
                .message = "La chiave di cifratura non puo' essere vuota.",
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        const std::filesystem::path input_path(file_path);

        if (!std::filesystem::exists(input_path)) {
            return CryptoResult{
                .success = false,
                .message = std::format("File non trovato: {}", file_path),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        if (!std::filesystem::is_regular_file(input_path)) {
            return CryptoResult{
                .success = false,
                .message = std::format("Il path non corrisponde a un file regolare: {}",
                                       file_path),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        /*
         * Costruzione del path di output: aggiunta dell'estensione .lock.
         * `output_path` è una copia di `input_path` (value semantics).
         * L'operatore += concatena direttamente alla stringa del path
         * SENZA aggiungere un separatore di directory.
         */
        auto output_path = input_path;
        output_path += ".lock";

        // ── Fase 2: Calcolo dell'Hash di Integrità ───────────────────────

        // La dimensione del file è letta tramite std::filesystem::file_size().

        const auto original_size = std::filesystem::file_size(input_path);
        const auto content_hash = compute_fnv1a_file(input_path);

        // ── Fase 3: Composizione e Scrittura dell'Header ─────────────────

        const auto original_filename = input_path.filename().string();

        const LockFileHeader header{
            .magic = MAGIC_BYTES,
            .version = FORMAT_VERSION,
            .original_size = original_size,
            .content_hash = content_hash,
            .filename_length = static_cast<std::uint32_t>(original_filename.size()),
            .original_filename = original_filename
        };

        /*
         * Apertura del file di output in modalità binaria.
         * std::ios::trunc tronca il file se esiste già (sovrascrittura).
         * Il file viene creato se non esiste.
         */
        std::ofstream out_file(output_path, std::ios::binary | std::ios::trunc);
        if (!out_file) {
            return CryptoResult{
                .success = false,
                .message = std::format("Impossibile creare il file di output: {}",
                                       output_path.string()),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        write_header(out_file, header);

        // ── Fase 4: Cifratura Chunked del Contenuto ──────────────────────

        std::ifstream in_file(input_path, std::ios::binary);
        if (!in_file) {
            return CryptoResult{
                .success = false,
                .message = std::format("Impossibile aprire il file sorgente per la cifratura: {}",
                                       file_path),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        /*
         * Buffer riutilizzabile per la lettura/cifratura dei chunk.
         * Allocato UNA VOLTA fuori dal loop per evitare allocazioni
         * ripetute (amortized O(1) per l'intero file).
         */
        std::vector<std::byte> buffer(CHUNK_SIZE);

        /*
         * key_offset tiene traccia della posizione nella chiave
         * attraverso i chunk successivi. Senza questo offset, ogni
         * chunk ripartirebbe dalla posizione 0 della chiave, creando
         * un pattern periodico nel ciphertext (vulnerabilità nota
         * del cifrario XOR con chiave corta).
         */
        std::size_t key_offset = 0;

        while (in_file.read(reinterpret_cast<char*>(buffer.data()),
                            static_cast<std::streamsize>(CHUNK_SIZE))) {
            const auto bytes_read = static_cast<std::size_t>(in_file.gcount());

            /*
             * Creiamo uno span di dimensione esatta sui byte letti.
             * Lo span è una view: non copia dati, punta al buffer esistente.
             */
            std::span<std::byte> chunk(buffer.data(), bytes_read);
            xor_transform_chunk(chunk, key, key_offset);

            out_file.write(reinterpret_cast<const char*>(chunk.data()),
                           static_cast<std::streamsize>(bytes_read));

            key_offset += bytes_read;
        }

        // Processamento dell'ultimo chunk parziale (se presente)
        const auto remaining = static_cast<std::size_t>(in_file.gcount());
        if (remaining > 0) {
            std::span<std::byte> last_chunk(buffer.data(), remaining);
            xor_transform_chunk(last_chunk, key, key_offset);

            out_file.write(reinterpret_cast<const char*>(last_chunk.data()),
                           static_cast<std::streamsize>(remaining));
        }

        // Verifica finale della scrittura
        out_file.flush();
        if (out_file.fail()) {
            return CryptoResult{
                .success = false,
                .message = "Errore durante la scrittura dei dati cifrati nel file .lock.",
                .source_file = std::string(file_path),
                .output_file = output_path.string()
            };
        }

        /*
         * I distruttori di in_file e out_file chiudono automaticamente
         * i file descriptor (RAII). Il return causa la distruzione di
         * tutte le variabili locali nell'ordine inverso di costruzione.
         */
        return CryptoResult{
            .success = true,
            .message = std::format("File cifrato con successo. Hash di integrita' FNV-1a: {:016X}",
                                   content_hash),
            .source_file = std::string(file_path),
            .output_file = output_path.string()
        };

    } catch (const std::exception& e) {
        /*
         * Exception Boundary: convertiamo qualsiasi eccezione in un
         * CryptoResult con success=false. Il messaggio dell'eccezione
         * viene preservato per la diagnostica.
         */
        return CryptoResult{
            .success = false,
            .message = std::format("Errore durante la cifratura: {}", e.what()),
            .source_file = std::string(file_path),
            .output_file = ""
        };
    }
}

auto ByteGuardCrypto::decrypt(std::string_view file_path,
                               std::string_view key) -> CryptoResult
{
    // Catturiamo le eccezioni per const reference (const std::exception&) per evitare l'object slicing e preservare il comportamento polimorfico
    try {
        // ── Fase 1: Validazione degli Input ──────────────────────────────

        if (key.empty()) {
            return CryptoResult{
                .success = false,
                .message = "La chiave di decifratura non puo' essere vuota.",
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        const std::filesystem::path input_path(file_path);

        if (!std::filesystem::exists(input_path)) {
            return CryptoResult{
                .success = false,
                .message = std::format("File .lock non trovato: {}", file_path),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        if (!std::filesystem::is_regular_file(input_path)) {
            return CryptoResult{
                .success = false,
                .message = std::format("Il path non corrisponde a un file regolare: {}",
                                       file_path),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        std::ifstream in_file(input_path, std::ios::binary);
        if (!in_file) {
            return CryptoResult{
                .success = false,
                .message = std::format("Impossibile aprire il file .lock: {}", file_path),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        // ── Fase 2: Lettura e Validazione dell'Header ────────────────────

        /*
         * read_header() lancia eccezioni se il magic number non è valido,
         * se la versione è incompatibile, o se l'header è troncato.
         * Queste eccezioni sono catturate dal catch esterno.
         */
        const auto header = read_header(in_file);

        /*
         * Costruzione del path di output nella stessa directory del .lock.
         * Usiamo il filename originale memorizzato nell'header, combinato
         * con la directory del file .lock.
         *
         * parent_path() restituisce la directory contenente il file.
         * operator/ concatena path con separatore (cross-platform).
         *
         * NOTA DI SICUREZZA: Il filename nell'header potrebbe contenere
         * path traversal (es. "../../etc/passwd"). In un contesto forense
         * reale, si dovrebbe validare che il filename non contenga
         * separatori di directory. Qui confidiamo nell'integrità dell'header
         * perché il file è stato generato dal nostro stesso tool.
         */
        const auto output_path =
            input_path.parent_path() / header.original_filename;

        // ── Fase 3: Decifratura Chunked del Contenuto ────────────────────

        std::ofstream out_file(output_path, std::ios::binary | std::ios::trunc);
        if (!out_file) {
            return CryptoResult{
                .success = false,
                .message = std::format("Impossibile creare il file di output: {}",
                                       output_path.string()),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        std::vector<std::byte> buffer(CHUNK_SIZE);
        std::size_t key_offset = 0;
        std::uint64_t total_bytes_written = 0;

        while (in_file.read(reinterpret_cast<char*>(buffer.data()),
                            static_cast<std::streamsize>(CHUNK_SIZE))) {
            const auto bytes_read = static_cast<std::size_t>(in_file.gcount());

            std::span<std::byte> chunk(buffer.data(), bytes_read);
            xor_transform_chunk(chunk, key, key_offset);

            out_file.write(reinterpret_cast<const char*>(chunk.data()),
                           static_cast<std::streamsize>(bytes_read));

            key_offset += bytes_read;
            total_bytes_written += bytes_read;
        }

        // Ultimo chunk parziale
        const auto remaining = static_cast<std::size_t>(in_file.gcount());
        if (remaining > 0) {
            std::span<std::byte> last_chunk(buffer.data(), remaining);
            xor_transform_chunk(last_chunk, key, key_offset);

            out_file.write(reinterpret_cast<const char*>(last_chunk.data()),
                           static_cast<std::streamsize>(remaining));

            total_bytes_written += remaining;
        }

        out_file.flush();
        if (out_file.fail()) {
            return CryptoResult{
                .success = false,
                .message = "Errore durante la scrittura dei dati decifrati.",
                .source_file = std::string(file_path),
                .output_file = output_path.string()
            };
        }

        /*
         * Chiudiamo esplicitamente il file di output PRIMA dell'integrity
         * check, perché compute_fnv1a_file() deve riaprire il file per
         * calcolarne l'hash. Su Windows, un file aperto in scrittura non
         * può essere riaperto in lettura (sharing violation).
         *
         * NOTA: close() è normalmente non necessario con RAII (il
         * distruttore lo fa automaticamente). Qui lo usiamo esplicitamente
         * perché abbiamo un requisito temporale: il file DEVE essere chiuso
         * PRIMA della prossima operazione. Questo è uno dei rari casi in
         * cui la chiusura esplicita è giustificata.
         */
        out_file.close();

        // ── Fase 4: Integrity Check ──────────────────────────────────────

        if (total_bytes_written != header.original_size) {
            /*
             * Cleanup: rimuoviamo il file di output parziale/corrotto.
             * std::filesystem::remove() è idempotente: non lancia
             * eccezioni se il file non esiste.
             *
             * NOTA: std::error_code ec è passato per catturare eventuali
             * errori di rimozione senza lanciare eccezioni (versione
             * non-throwing di std::filesystem::remove).
             */
            std::error_code ec;
            std::filesystem::remove(output_path, ec);

            return CryptoResult{
                .success = false,
                .message = std::format(
                    "Integrity check fallito: dimensione non corrispondente. "
                    "Attesa: {} byte, ottenuta: {} byte. "
                    "La chiave potrebbe essere errata o il file .lock corrotto.",
                    header.original_size, total_bytes_written),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        const auto decrypted_hash = compute_fnv1a_file(output_path);

        if (decrypted_hash != header.content_hash) {
            // Cleanup del file corrotto
            std::error_code ec;
            std::filesystem::remove(output_path, ec);

            return CryptoResult{
                .success = false,
                .message = std::format(
                    "Integrity check fallito: hash FNV-1a non corrispondente. "
                    "Hash atteso: {:016X}, hash calcolato: {:016X}. "
                    "La chiave di decifratura e' probabilmente errata.",
                    header.content_hash, decrypted_hash),
                .source_file = std::string(file_path),
                .output_file = ""
            };
        }

        // ── Fase 5: Successo ─────────────────────────────────────────────

        return CryptoResult{
            .success = true,
            .message = std::format(
                "File decifrato con successo. Integrity check superato "
                "(FNV-1a: {:016X}). File originale ripristinato: {}",
                decrypted_hash, output_path.string()),
            .source_file = std::string(file_path),
            .output_file = output_path.string()
        };

    } catch (const std::exception& e) {
        return CryptoResult{
            .success = false,
            .message = std::format("Errore durante la decifratura: {}", e.what()),
            .source_file = std::string(file_path),
            .output_file = ""
        };
    }
}

}
