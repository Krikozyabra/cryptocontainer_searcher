#include <filesystem>

namespace fs = std::filesystem;

namespace drive_manager{
    bool raw_to_vhd(const fs::path&);
} // namespace dirve_manager
