#include "remax/HeaderParser.hpp"

namespace remax {

// Helper to safely get a pointer to a structure from a buffer
template <typename T>
const T* get_struct_at(std::span<const std::byte> buffer, size_t offset) {
    if (offset + sizeof(T) > buffer.size()) {
        return nullptr;
    }
    return reinterpret_cast<const T*>(buffer.data() + offset);
}

std::expected<HeaderParser, HeaderParserError> HeaderParser::create(std::span<const std::byte> buffer) {
    // 1. Get and validate DOS header
    const auto* dos_header = get_struct_at<pe::IMAGE_DOS_HEADER>(buffer, 0);
    if (!dos_header) {
        return std::unexpected(HeaderParserError::BufferTooSmall);
    }

    if (dos_header->e_magic != pe::IMAGE_DOS_SIGNATURE) {
        return std::unexpected(HeaderParserError::InvalidDosSignature);
    }

    // 2. Get and validate NT headers
    const auto nt_header_offset = static_cast<size_t>(dos_header->e_lfanew);
    
    // Just check for the signature first
    const auto* nt_signature = get_struct_at<uint32_t>(buffer, nt_header_offset);
    if (!nt_signature || *nt_signature != pe::IMAGE_NT_SIGNATURE) {
        return std::unexpected(HeaderParserError::InvalidNtSignature);
    }
    
    // Now determine architecture from the optional header's magic
    const auto* optional_magic = get_struct_at<uint16_t>(buffer, nt_header_offset + sizeof(uint32_t) + sizeof(pe::IMAGE_FILE_HEADER));
    if (!optional_magic) {
        return std::unexpected(HeaderParserError::BufferTooSmall);
    }

    NtHeadersVariant nt_headers_variant;
    if (*optional_magic == 0x10b) { // PE32
        const auto* nt_headers32 = get_struct_at<pe::IMAGE_NT_HEADERS32>(buffer, nt_header_offset);
        if (!nt_headers32) {
             return std::unexpected(HeaderParserError::BufferTooSmall);
        }
        nt_headers_variant = nt_headers32;
    } else if (*optional_magic == 0x20b) { // PE32+ (64-bit)
        const auto* nt_headers64 = get_struct_at<pe::IMAGE_NT_HEADERS64>(buffer, nt_header_offset);
        if (!nt_headers64) {
             return std::unexpected(HeaderParserError::BufferTooSmall);
        }
        nt_headers_variant = nt_headers64;
    } else {
        return std::unexpected(HeaderParserError::UnsupportedArchitecture);
    }
    
    return HeaderParser(dos_header, nt_headers_variant);
}

HeaderParser::HeaderParser(const pe::IMAGE_DOS_HEADER* dos_header, NtHeadersVariant nt_headers)
    : m_dos_header(dos_header), m_nt_headers(std::move(nt_headers)) {}

const pe::IMAGE_DOS_HEADER* HeaderParser::dos_header() const noexcept {
    return m_dos_header;
}

HeaderParser::NtHeadersVariant HeaderParser::nt_headers() const noexcept {
    return m_nt_headers;
}

bool HeaderParser::is_64bit() const noexcept {
    return std::holds_alternative<const pe::IMAGE_NT_HEADERS64*>(m_nt_headers);
}

} // namespace remax
