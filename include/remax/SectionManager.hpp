#pragma once

#include "remax/PE/PEHeaders.hpp"
#include "remax/HeaderParser.hpp"
#include <span>
#include <expected>
#include <vector>
#include <string>
#include <string_view>

namespace remax {

enum class SectionManagerError {
    InvalidNumberOfSections,
    SectionHeaderCorrupted,
    BufferTooSmallForSections,
    SectionNotFound,
};

// Forward declaration
class SectionManager;

// Advanced: Holds richer information and analysis about a section.
struct SectionInfo {
    const pe::IMAGE_SECTION_HEADER* header;
    std::string_view name;
    bool is_executable;
    bool is_writable;
    bool is_readable;
    bool is_suspicious; // True if characteristics are abnormal (e.g., W+X)
    std::vector<std::string> characteristics_flags;

    [[nodiscard]] bool rva_is_within(uint32_t rva) const;
};

class SectionManager {
public:
    static std::expected<SectionManager, SectionManagerError> create(
        std::span<const std::byte> file_buffer,
        const HeaderParser& header_parser
    );

    SectionManager(const SectionManager&) = delete;
    SectionManager& operator=(const SectionManager&) = delete;
    SectionManager(SectionManager&&) noexcept = default;
    SectionManager& operator=(SectionManager&&) noexcept = default;

    [[nodiscard]] const std::vector<SectionInfo>& get_sections() const noexcept;
    
    [[nodiscard]] std::expected<const SectionInfo*, SectionManagerError> 
        get_section_by_name(std::string_view name) const noexcept;

    [[nodiscard]] std::expected<const SectionInfo*, SectionManagerError> 
        get_section_by_rva(uint32_t rva) const noexcept;

private:
    SectionManager(std::vector<SectionInfo> sections);

    std::vector<SectionInfo> m_sections;
};

} // namespace remax
