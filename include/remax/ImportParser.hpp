#pragma once

#include "remax/PE/PEHeaders.hpp"
#include "remax/HeaderParser.hpp"
#include "remax/RVAConverter.hpp"

#include <string>
#include <vector>
#include <expected>
#include <optional>

namespace remax {

enum class ImportParserError {
    NoImportDirectory,
    ImportDirectoryCorrupted,
    RVAConversionFailed,
    InvalidImportDescriptor,
    ThunkDataCorrupted,
    DllNameNotFound,
};

struct ImportedFunction {
    std::string name;
    uint16_t ordinal = 0;
    bool imported_by_ordinal = false;
    std::optional<std::string> forwarded_to; // Advanced: e.g., "ntdll.RtlAllocateHeap"
};

struct ImportedModule {
    std::string name;
    std::vector<ImportedFunction> functions;
};


class ImportParser {
public:
    static std::expected<ImportParser, ImportParserError> create(
        std::span<const std::byte> file_buffer,
        const HeaderParser& header_parser,
        const RVAConverter& rva_converter
    );

    ImportParser(const ImportParser&) = delete;
    ImportParser& operator=(const ImportParser&) = delete;
    ImportParser(ImportParser&&) noexcept = default;
    ImportParser& operator=(ImportParser&&) noexcept = default;

    [[nodiscard]] std::span<const ImportedModule> get_modules() const noexcept;

private:
    ImportParser(std::vector<ImportedModule> modules);
    
    std::vector<ImportedModule> m_modules;
};


} // namespace remax
