#include "remax/FileLoader.hpp"

#if __linux__ || __APPLE__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace remax {

#if __linux__ || __APPLE__

std::expected<FileLoader, FileLoaderError> FileLoader::create(const std::filesystem::path& file_path) {
    if (!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path)) {
        return std::unexpected(FileLoaderError::FileNotFound);
    }

    FileLoader loader;
    loader.m_file_handle = open(file_path.c_str(), O_RDONLY);
    if (loader.m_file_handle == -1) {
        return std::unexpected(FileLoaderError::FileOpenError);
    }

    struct stat sb;
    if (fstat(loader.m_file_handle, &sb) == -1) {
        close(loader.m_file_handle);
        return std::unexpected(FileLoaderError::FileOpenError);
    }
    
    loader.m_size = sb.st_size;
    if (loader.m_size == 0) {
        close(loader.m_file_handle);
        return std::unexpected(FileLoaderError::FileEmpty);
    }

    loader.m_map_handle = mmap(NULL, loader.m_size, PROT_READ, MAP_PRIVATE, loader.m_file_handle, 0);
    if (loader.m_map_handle == MAP_FAILED) {
        close(loader.m_file_handle);
        return std::unexpected(FileLoaderError::FileMapError);
    }

    return loader;
}

FileLoader::FileLoader() = default;

FileLoader::~FileLoader() {
    if (m_map_handle) {
        munmap(m_map_handle, m_size);
    }
    if (m_file_handle != -1) {
        close(m_file_handle);
    }
}

FileLoader::FileLoader(FileLoader&& other) noexcept
    : m_map_handle(other.m_map_handle), m_size(other.m_size), m_file_handle(other.m_file_handle) {
    // Invalidate the other object
    other.m_map_handle = nullptr;
    other.m_file_handle = -1;
    other.m_size = 0;
}

FileLoader& FileLoader::operator=(FileLoader&& other) noexcept {
    if (this != &other) {
        // Release current resources
        if (m_map_handle) munmap(m_map_handle, m_size);
        if (m_file_handle != -1) close(m_file_handle);

        // Pilfer other's resources
        m_map_handle = other.m_map_handle;
        m_size = other.m_size;
        m_file_handle = other.m_file_handle;
        
        // Invalidate the other object
        other.m_map_handle = nullptr;
        other.m_file_handle = -1;
        other.m_size = 0;
    }
    return *this;
}

#else

// Windows or other unsupported platforms will fail at compile time for now.
// This makes it clear that a platform-specific implementation is required.
std::expected<FileLoader, FileLoaderError> FileLoader::create(const std::filesystem::path& file_path) {
    #error "Platform not supported for memory-mapped file loader."
    return std::unexpected(FileLoaderError::FileOpenError);
}

// Dummy implementations to satisfy the linker
FileLoader::FileLoader() = default;
FileLoader::~FileLoader() = default;
FileLoader::FileLoader(FileLoader&& other) noexcept = default;
FileLoader& FileLoader::operator=(FileLoader&& other) noexcept = default;


#endif


std::span<const std::byte> FileLoader::get_buffer() const noexcept {
    return {static_cast<const std::byte*>(m_map_handle), m_size};
}

size_t FileLoader::size() const noexcept {
    return m_size;
}

} // namespace remax
