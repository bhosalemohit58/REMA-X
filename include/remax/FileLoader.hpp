#pragma once

#include <cstddef>
#include <filesystem>
#include <expected>
#include <span>

namespace remax {

enum class FileLoaderError {
    FileNotFound,
    FileOpenError,
    FileMapError,
    FileEmpty,
};

class FileLoader {
public:
    // Factory function to create a FileLoader instance from a file path
    static std::expected<FileLoader, FileLoaderError> create(const std::filesystem::path& file_path);

    // Destructor to release the memory mapping
    ~FileLoader();

    // Prevent copying
    FileLoader(const FileLoader&) = delete;
    FileLoader& operator=(const FileLoader&) = delete;

    // Allow moving
    FileLoader(FileLoader&& other) noexcept;
    FileLoader& operator=(FileLoader&& other) noexcept;

    // Get a view of the entire file buffer
    [[nodiscard]] std::span<const std::byte> get_buffer() const noexcept;

    // Get the size of the loaded file
    [[nodiscard]] size_t size() const noexcept;

private:
    // Private constructor, to be called by the factory function
    FileLoader();

    // Platform-specific implementation details
    // On POSIX, m_map_handle is the memory-mapped pointer, m_file_handle is the file descriptor.
    void* m_map_handle = nullptr;
    size_t m_size = 0;
    int m_file_handle = -1;
};

} // namespace remax
