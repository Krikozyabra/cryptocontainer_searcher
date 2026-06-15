#include <entropy/shannon_entropy.h>
#include <filesystem>
#include <fstream>
#include <cassert>

using namespace entropy;
using namespace std;
namespace fs = std::filesystem;

bool entropy::ShannonEncryptionChecker::interrupt_all_ = false;

// Kept only to satisfy the declaration in the header so we don't get a static member linker error
bool entropy::ShannonEncryptionChecker::load_uint8_codecvt_ = false;

std::map<ShannonEncryptionChecker::InformationEntropyEstimation, std::string> 
ShannonEncryptionChecker::entropy_string_description_ = {
    { Plain , "Plain"},
    { Binary , "Binary" },
    { Encrypted , "Encrypted" },
    { Unknown , "Unknown" } };

ShannonEncryptionChecker::ShannonEncryptionChecker()
{
    assert(entropy_string_description_.size() == EntropyLevelSize);
    // Fixed: Completely removed the problematic codecvt/locale manipulation!
}

void ShannonEncryptionChecker::interrupt()
{
    interrupt_all_ = true;
}

std::string ShannonEncryptionChecker::get_information_description(InformationEntropyEstimation ent) const
{
    std::string descr = entropy_string_description_[ent];
    
    // all descriptions must be provided!
    assert(!descr.empty());
    return descr;
}

size_t ShannonEncryptionChecker::min_compressed_size(double entropy, size_t sequence_size) const
{
    return static_cast<size_t>((entropy * sequence_size) / 8);
}

double entropy::ShannonEncryptionChecker::get_file_entropy(const std::string& file_path) const
{
    uintmax_t file_size = fs::file_size(file_path);
    std::vector<double> byte_probabilities = read_file_probabilities(file_path, file_size);
    return shannon_entropy(byte_probabilities.begin(), byte_probabilities.end());
}


void ShannonEncryptionChecker::set_callback(callback_t callback)
{
    callback_ = callback;
}

double ShannonEncryptionChecker::get_sequence_entropy(const uint8_t* sequence_start, size_t sequence_size) const
{
    std::vector<double> byte_probabilities = read_stream_probabilities(sequence_start, sequence_size);
    return shannon_entropy(byte_probabilities.begin(), byte_probabilities.end());
}

ShannonEncryptionChecker::InformationEntropyEstimation
ShannonEncryptionChecker::information_entropy_estimation(double entropy, size_t sequence_size) const
{
    double epsilon = estimated_epsilon(sequence_size);
    if ((8.0 - entropy) < epsilon) {
        return Encrypted;
    }
    if (entropy > 6.0) {
        return Binary;
    }
    if (entropy >= 0. && entropy <= 6.0) {
        return Plain;
    }
    // should not be here, entropy calculation error
    assert(false);
    return Unknown;
}

std::vector<double> ShannonEncryptionChecker::read_file_probabilities(const std::string& file_path, size_t file_size) const
{
    // probability of every byte of zero-sized file is 0
    if (0 == file_size) {
        return std::vector<double>(256);
    }

    uint8_t read_ahead_buffer[MAX_BUFFER_SIZE];

    std::vector<size_t> bytes_distribution(256);
    std::vector<double> bytes_frequencies(256);
    
    // Fixed: Use standard std::ifstream (which relies on std::codecvt<char, char, mbstate_t>, natively supported)
    std::ifstream file(file_path, std::ios::in | std::ios::binary);
    file.rdbuf()->pubsetbuf(reinterpret_cast<char*>(read_ahead_buffer), MAX_BUFFER_SIZE);

    char one_byte{};
    uintmax_t counter{};
    
    // Fixed: Loop runs strictly on successful byte reads, avoiding extra iteration at EOF
    while (file.read(&one_byte, sizeof(char))) {

        if (interrupt_all_) {
            return std::vector<double>{};
        }

        if (callback_) {
            callback_(++counter);
        }
        
        // Fixed: Safely cast the signed/unsigned char to uint8_t so it sits in 0-255 range
        ++bytes_distribution[static_cast<uint8_t>(one_byte)];
    }

    for (size_t i = 0; i != 256; ++i) {
        if (interrupt_all_) {
            return std::vector<double>{};
        }

        bytes_frequencies[i] = static_cast<double>(bytes_distribution[i]) / file_size;
    }

    return bytes_frequencies;
}

std::vector<double> ShannonEncryptionChecker::read_stream_probabilities(const uint8_t* sequence_start, size_t sequence_size) const
{
    if (0 == sequence_size) {
        return std::vector<double>(256);
    }

    std::vector<size_t> bytes_distribution(256);
    std::vector<double> bytes_frequencies(256);

    uintmax_t counter{};
    for (size_t i = 0; i < sequence_size; ++i) {
        if (interrupt_all_) {
            return std::vector<double>{};
        }

        if (callback_) {
            callback_(++counter);
        }

        ++bytes_distribution[sequence_start[i]];
    }

    for (size_t i = 0; i != 256; ++i) {
        if (interrupt_all_) {
            return std::vector<double>{};
        }

        bytes_frequencies[i] = static_cast<double>(bytes_distribution[i]) / sequence_size;
    }

    return bytes_frequencies;
}

double ShannonEncryptionChecker::estimated_epsilon(size_t sample_size) const
{
    // Note: numbers based on very approximate estimations (several test calculations)
    // More reliable statistic should be collected for more exact results
    if (sample_size < (1024 * 1024)) {
        return 0.001;
    }
    if (sample_size < (1024 * 1024 * 64)) {
        return 0.0001;
    }
    if (sample_size < (1024 * 1024 * 512)) {
        return 0.00001;
    }
    return 0.000001;
}
