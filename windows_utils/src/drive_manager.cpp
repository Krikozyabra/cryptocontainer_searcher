#include "windows_utils/drive_manager.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <system_error>
#include <virtdisk.h>
#include <windows.h>
#ifdef LOG_ENABLED
#include <spdlog/spdlog.h>
#endif

namespace fs = std::filesystem;

namespace drive_manager {
bool raw_to_vhd(const fs::path &raw, const fs::path &vhd) {
    #ifdef LOG_ENABLED
       spdlog::info("VHD creating from " + raw.string() + " to " + vhd.string());
    #endif
    std::error_code ec;
    uint64_t rawSize = fs::file_size(raw, ec);
    if (ec) {
#ifdef LOG_ENABLED
        spdlog::error("Error caused while getting file size of " +
                      raw.string());
#endif
        return false;
    }

    VIRTUAL_STORAGE_TYPE storageType = {0};
    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
    storageType.VendorId = VIRTUAL_STORAGE_TPYE_VENDOR_MICROSOFT;

    CREATE_VIRTUAL_DISK_PARAMETERS params = {0};
    params.Version = CREATE_VIRTUAL_DISK_VERISON_1;
    params.Version1.MaximumSize = rawSize;
    params.Version1.BlockSizeInBytes =
        CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
    params.Version1.SectorSizeInBytes =
        CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;

    HANDLE hVhd = INVALID_HANDLE_VALUE;

    DWORD result = CreateVirtualDisl(
        &storageType, vhd.wstring().c_str(), VIRTUAL_DISK_ACCESS_CREATE, NULL,
        CREATE_VIRTUAL_DISK_FLAG_NONE, 0, &params, NULL, &hVhd);

    if (result != ERROR_SUCCESS) {
#ifdef LOG_ENABLED
        spdlog::error("Error caused while creating VHD");
#endif
        return false;
    }

    CloseHandle(hVhd);

    std::ifstream src(raw, std::ios::binary);
    std::ofstream dst(vhd, std::ios::binary | std::ios::in | std::ios::out);

    if (!src.is_open() || !dst.is_open()){
        #ifdef LOG_ENABLED
           spdlog::error("Error caused while openning files for data transfer");
        #endif
        return false;
    }

    constexpr size_t bufferSize = 1024*1024;
    std::unique_ptr<char[]> buffer(new char[bufferSize]);
    
    while(src.read(buffer.get(), bufferSize) || src.gcount() > 0){
        std::streamsize bytes = src.gcount();
        dst.write(buffer.get(), bytes);
        if (!dst){
            #ifdef LOG_ENABLED
               spdlog::error("Crtitical error caused while writing to VHD file");
            #endif
            return false;
        }
    }
    #ifdef LOG_ENABLED
       spdlog::info("VHD creation finished successefully");
    #endif
    return true;
}
} // namespace drive_manager
