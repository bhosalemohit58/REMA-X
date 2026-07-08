#pragma once

#include "remax/PE/PEHeaders.hpp"
#include <span>
#include <expected>
#include <variant>

namespace remax {

enum class HeaderParserError {
    BufferTooSmall,
    InvalidDosSignature,
    InvalidNtSignature,
    UnsupportedArchitecture,
};

class HeaderParser {
public:
    using NtHeadersVariant = std::variant<const pe::IMAGE_NT_HEADERS32*, const pe::IMAGE_NT_HEADERS64*>;

    static std::expected<HeaderParser, HeaderParserError> create(std::span<const std::byte> buffer);

    HeaderParser(const HeaderParser&) = delete;
    HeaderParser& operator=(const HeaderParser&) = delete;
    HeaderParser(HeaderParser&&) = default;
    HeaderParser& operator=(HeaderParser&&) = default;

    [[nodiscard]] const pe::IMAGE_DOS_HEADER* dos_header() const noexcept;
    [[nodiscard]] NtHeadersVariant nt_headers() const noexcept;
    [[nodiscard]] bool is_64bit() const noexcept;

private:
    HeaderParser(const pe::IMAGE_DOS_HEADER* dos_header, NtHeadersVariant nt_headers);

    const pe::IMAGE_DOS_HEADER* m_dos_header;
    NtHeadersVariant m_nt_headers;
};

} // namespace remax
