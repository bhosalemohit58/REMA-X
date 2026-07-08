#include "remax/RVAConverter.hpp"
#include "remax/HeaderParser.hpp"
#include "remax/SectionManager.hpp"
#include <variant>

namespace remax {

RVAConverter::RVAConverter(const HeaderParser& header_parser, const SectionManager& section_manager)
    : m_header_parser(header_parser), m_section_manager(section_manager) {}

std::expected<RVAConverter, RVAConverterError> RVAConverter::create(
    const HeaderParser& header_parser,
    const SectionManager& section_manager) {
    
    return RVAConverter(header_parser, section_manager);
}

std::expected<uint32_t, RVAConverterError> RVAConverter::rva_to_offset(uint32_t rva) const noexcept {
    // 1. First, check if the RVA is within the file headers.
    uint32_t size_of_headers = 0;
    std::visit([&size_of_headers](const auto* nt_headers) {
        if (nt_headers) {
            size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;
        }
    }, m_header_parser.nt_headers());

    if (rva < size_of_headers) {
        return rva; // RVA is within the header region, so the offset is the RVA itself.
    }

    // 2. Find which section the RVA belongs to.
    auto section_info_exp = m_section_manager.get_section_by_rva(rva);
    if (!section_info_exp) {
        // If it's not in the headers and not in any section, it's an invalid RVA.
        return std::unexpected(RVAConverterError::NoSectionFound);
    }
    
    const auto* section_info = *section_info_exp;
    const auto* header = section_info->header;

    // 3. Advanced check: Ensure the RVA points to a location backed by raw data on disk.
    const uint32_t offset_in_section = rva - header->VirtualAddress;
    if (offset_in_section >= header->SizeOfRawData) {
        // This RVA points to virtual-only memory for this section (e.g., .bss).
        return std::unexpected(RVAConverterError::InvalidRVA);
    }

    // 4. Calculate the final file offset.
    return header->PointerToRawData + offset_in_section;
}

} // namespace remax
