#include <iostream>
#include <string>
#include <entropy/shannon_entropy.h>

int main() {
    std::string file_path = "test_file.bin"; 

    entropy::ShannonEncryptionChecker checker;

    try {
        double entropy_value = checker.get_file_entropy(file_path);
        std::cout << "Shannon Entropy of '" << file_path << "': " << entropy_value << " (out of 8.0)\n";

        auto estimation = checker.information_entropy_estimation(entropy_value, 1024);
        std::cout << "Estimated Type: " << checker.get_information_description(estimation) << "\n";
    } 
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
