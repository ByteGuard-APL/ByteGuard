// Interfaccia del Modulo di Cifratura ByteGuard

#pragma once

#include <cstdint>       // uint8_t, uint32_t, uint64_t — tipi a larghezza fissa (ISO/IEC 9899)
#include <string>        // std::string — stringa dinamica RAII
#include <string_view>   // std::string_view — view non-owning su sequenze di char
#include <vector>        // std::vector — array dinamico RAII
#include <filesystem>    // std::filesystem::path — astrazione cross-platform dei percorsi
#include <array>         // std::array — array a dimensione fissa, stack-allocated
#include <span>          // std::span (C++20) — view non-owning su sequenze contigue
#include <cstddef>       // std::byte — tipo semanticamente corretto per dati binari grezzi

// Nested namespace per raggruppare logicamente il codice ed evitare name collisions
namespace byteguard::crypto {

// Utilizziamo constexpr per l'inizializzazione a compile-time (compile-time constants)

/// Dimensione in byte del Magic Number nell'header del file .lock.
inline constexpr std::size_t MAGIC_SIZE = 8;

/// Magic Number: sequenza ASCII "BGUARD01" (42 47 55 41 52 44 30 31 hex).
/// Identifica univocamente un file cifrato.
inline constexpr std::array<std::uint8_t, MAGIC_SIZE> MAGIC_BYTES = {
    0x42, 0x47, 0x55, 0x41, 0x52, 0x44, 0x30, 0x31  // "BGUARD01"
};

/// Versione corrente del formato .lock.
inline constexpr std::uint32_t FORMAT_VERSION = 1;

/// Dimensione del chunk di lettura/scrittura in byte (4 KB).
inline constexpr std::size_t CHUNK_SIZE = 4096;


/*
 *  FNV-1a (Fowler–Noll–Vo, variante "alternate") è un hash non-crittografico
 *  scelto per il controllo di integrità.
 *
 *  IMPORTANTE: FNV-1a NON è un hash crittografico. Non offre resistenza
 *  alle pre-immagini né alle collisioni intenzionali. In un contesto
 *  forense reale si userebbe SHA-256 o BLAKE3. Qui lo usiamo come
 *  **integrity check** per rilevare corruzione accidentale, non attacchi.
 *
 */

/// FNV-1a offset basis (64-bit). Valore iniziale dell'hash, scelto per
/// le sue proprietà di distribuzione. Derivato empiricamente dagli autori
/// dell'algoritmo (Fowler, Noll, Vo).
inline constexpr std::uint64_t FNV1A_OFFSET_BASIS = 14695981039346656037ULL;

/// La scelta di un numero primo garantisce che la moltiplicazione modulo 2^64
/// generi un buon mixing dei bit (avalanche effect).
inline constexpr std::uint64_t FNV1A_PRIME = 1099511628211ULL;


// Definiamo un aggregato di dati (POD-like). Utilizziamo struct poiché i membri sono public di default e non ci sono invarianti da proteggere
struct LockFileHeader {
    /// Magic number per identificazione e anti-spoofing del formato.
    /// Tipo: array a dimensione fissa, stack-allocated, copiabile per valore.
    std::array<std::uint8_t, MAGIC_SIZE> magic = MAGIC_BYTES;

    /// Versione del protocollo di cifratura.
    /// Permette backward compatibility in future revisioni del formato.
    std::uint32_t version = FORMAT_VERSION;

    /// Dimensione in byte del file originale prima della cifratura.
    /// Necessario per verificare la completezza della decifratura
    /// e per pre-allocare il buffer di output.
    std::uint64_t original_size = 0;

    /// Hash FNV-1a a 64 bit del contenuto originale (plaintext).
    /// Usato come **Integrity Check**: dopo la decifratura, ricalcoliamo
    /// l'hash del plaintext e lo confrontiamo con questo valore.
    /// Se differiscono → corruzione o chiave errata.
    std::uint64_t content_hash = 0;

    /// Lunghezza in byte del nome del file originale (senza path).
    /// Serializzata separatamente perché il nome è a lunghezza variabile.
    std::uint32_t filename_length = 0;

    /// Nome del file originale (solo basename, senza directory).
    /// Memorizzato nell'header per consentire il ripristino del nome
    /// originale in fase di decifratura.
    ///
    /// NOTA: std::string è un tipo RAII che gestisce autonomamente la
    /// memoria dinamica per il suo buffer interno. Quando LockFileHeader
    /// viene distrutto, anche original_filename rilascia la sua memoria.
    /// Non serve un distruttore esplicito (Rule of Zero).
    std::string original_filename;
};


// Definiamo una struct per rappresentare il risultato di un'operazione di cifratura/decifratura.
struct CryptoResult {
    /// true se l'operazione è andata a buon fine, false altrimenti.
    bool success = false;

    /// Messaggio human-readable che descrive l'esito dell'operazione.
    /// In caso di errore, contiene la descrizione dell'errore.
    std::string message;

    /// Path del file sorgente (input dell'operazione).
    std::string source_file;

    /// Path del file prodotto (output dell'operazione).
    /// Vuoto in caso di errore (nessun file prodotto).
    std::string output_file;
};


// Utilizziamo class per garantire l'incapsulamento (i membri sono private di default) e nascondere i dettagli implementativi
class ByteGuardCrypto {
public:
    // Passaggio parametri per const value (std::string_view) per evitare overhead di copia.
    [[nodiscard]] static auto encrypt(std::string_view file_path,
                                      std::string_view key) -> CryptoResult;

    [[nodiscard]] static auto decrypt(std::string_view file_path,
                                      std::string_view key) -> CryptoResult;

private:
    [[nodiscard]] static auto compute_fnv1a(
        std::span<const std::byte> data) -> std::uint64_t;

    /*
     *  Per file di grandi dimensioni, non possiamo caricare l'intero
     *  contenuto in memoria e poi calcolare l'hash. Dobbiamo processare
     *  il file a chunk, aggiornando progressivamente lo stato dell'hash.
     *
     *  FNV-1a è particolarmente adatto all'hashing incrementale perché
     *  il suo stato è un singolo uint64_t (l'hash parziale). Ogni chunk
     *  aggiorna questo stato in modo indipendente dall'ordine di
     *  elaborazione dei byte all'interno dello stream.
     *
     */

    [[nodiscard]] static auto compute_fnv1a_file(
        const std::filesystem::path& file_path) -> std::uint64_t;

    static void xor_transform_chunk(std::span<std::byte> chunk,
                                    std::string_view key,
                                    std::size_t key_offset);

    static void write_header(std::ofstream& out_stream,
                             const LockFileHeader& header);

    [[nodiscard]] static auto read_header(
        std::ifstream& in_stream) -> LockFileHeader;
};

}
