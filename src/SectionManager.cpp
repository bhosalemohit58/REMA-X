#include "remax/SectionManager.hpp"
#include "remax/HeaderParser.hpp"
#include <algorithm>
#include <string_view>
#include <variant>
#include <cstring> // For memcpy

namespace remax {

// Implementation for the helper method in SectionInfo
bool SectionInfo::rva_is_within(uint32_t rva) const {
    return rva >= header->VirtualAddress && rva < (header->VirtualAddress + header->Misc.VirtualSize);
}

std::expected<SectionManager, SectionManagerError> SectionManager::create(
    std::span<const std::byte> file_buffer,
    const HeaderParser& header_parser) {

    std::vector<SectionInfo> sections;
    bool success = false;
    SectionManagerError error = SectionManagerError::SectionHeaderCorrupted;

    std::visit([&](const auto* nt_headers) {
        if (!nt_headers) {
            return;
        }

        const auto& file_header = nt_headers->FileHeader;
        const uint16_t number_of_sections = file_header.NumberOfSections;
        
        if (number_of_sections == 0) {
            // Not necessarily an error, could be a valid file without sections.
            success = true;
            return;
        }

        const auto* section_headers_start = IMAGE_FIRST_SECTION(nt_headers);

        if (!section_headers_start) {
            error = SectionManagerError::SectionHeaderCorrupted;
            return;
        }

        sections.reserve(number_of_sections);
        for (uint16_t i = 0; i < number_of_sections; ++i) {
            const auto* section_header = section_headers_start + i;

            if (reinterpret_cast<const std::byte*>(section_header) + sizeof(pe::IMAGE_SECTION_HEADER) > file_buffer.data() + file_buffer.size()) {
                 error = SectionManagerError::BufferTooSmallForSections;
                 return;
            }

            SectionInfo info{};
            info.header = section_header;

            // Get name safely from fixed-size, possibly not null-terminated buffer
            info.name = std::string_view(reinterpret_cast<const char*>(section_header->Name), 8);
            if(auto pos = info.name.find('\0'); pos != std::string_view::npos) {
                info.name = info.name.substr(0, pos);
            }

            // Analyze characteristics
            const auto& chars = section_header->Characteristics;
            info.is_readable = (chars & pe::IMAGE_SCN_MEM_READ) != 0;
            info.is_writable = (chars & pe::IMAGE_SCN_MEM_WRITE) != 0;
            info.is_executable = (chars & pe::IMAGE_SCN_MEM_EXECUTE) != 0;

            if (info.is_readable) info.characteristics_flags.emplace_back("READ");
            if (info.is_writable) info.characteristics_flags.emplace_back("WRITE");
            if (info.is_executable) info.characteristics_flags.emplace_back("EXECUTE");

            info.is_suspicious = info.is_writable && info.is_executable;
            if(info.is_suspicious) {
                info.characteristics_flags.emplace_back("SUSPICIOUS(W+X)");
            }
            
            sections.push_back(info);
        }
        success = true;

    }, header_parser.nt_headers());

    if (!success) {
        return std::unexpected(error);
    }
    return SectionManager(std::move(sections));
}

SectionManager::SectionManager(std::vector<SectionInfo> sections)
    : m_sections(std::move(sections)) {}

const std::vector<SectionInfo>& SectionManager::get_sections() const noexcept {
    return m_sections;
}

std::expected<const SectionInfo*, SectionManagerError> 
SectionManager::get_section_by_name(std::string_view name) const noexcept {
    for (const auto& section_info : m_sections) {
        if (section_info.name == name) {
            return &section_info;
        }
    }
    return std::unexpected(SectionManagerError::SectionNotFound);
}

std::expected<const SectionInfo*, SectionManagerError> 
SectionManager::get_section_by_rva(uint32_t rva) const noexcept {
    for (const auto& section_info : m_sections) {
        if (section_info.rva_is_within(rva)) {
            return &section_info;
        }
    }
    return std::unexpected(SectionManagerError::SectionNotFound);
}

} // namespace remax
