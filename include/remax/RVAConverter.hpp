#pragma once

#include <cstdint>
#include <expected>

#pragma once

#include <cstdint>
#include <expected>

namespace remax {

// Forward declarations to reduce header dependencies
class HeaderParser;
class SectionManager;

enum class RVAConverterError {
    InvalidRVA,
    NoSectionFound,
    SectionManagerError,
    HeaderParserError 
};

class RVAConverter {
public:
    static std::expected<RVAConverter, RVAConverterError> create(
        const HeaderParser& header_parser,
        const SectionManager& section_manager
    );

    RVAConverter(const RVAConverter&) = delete;
    RVAConverter& operator=(const RVAConverter&) = delete;
    RVAConverter(RVAConverter&&) noexcept = default;
    RVAConverter& operator=(RVAConverter&&) noexcept = delete; // References can't be reseated

    [[nodiscard]] std::expected<uint32_t, RVAConverterError> rva_to_offset(uint32_t rva) const noexcept;

private:
    RVAConverter(const HeaderParser& header_parser, const SectionManager& section_manager);

    const HeaderParser& m_header_parser;
    const SectionManager& m_section_manager;
};

} // namespace remax


} // namespace remax
