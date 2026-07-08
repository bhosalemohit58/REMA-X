#include "remax/ImportParser.hpp"
#include <string_view>
#include <algorithm>
#include <variant>

namespace remax {

// Helper to safely get a pointer to a structure from a buffer
template <typename T>
static const T* get_struct_at(std::span<const std::byte> buffer, size_t offset) {
    if (offset > 0 && offset + sizeof(T) <= buffer.size()) {
        return reinterpret_cast<const T*>(buffer.data() + offset);
    }
    return nullptr;
}

// Helper to read a null-terminated string from a given offset
static std::string read_string_at(std::span<const std::byte> buffer, size_t offset) {
    if (offset == 0 || offset >= buffer.size()) {
        return "";
    }
    const char* start = reinterpret_cast<const char*>(buffer.data() + offset);
    size_t max_len = buffer.size() - offset;
    // Use string_view to find the null terminator within the buffer bounds
    std::string_view view(start, max_len);
    size_t end_pos = view.find('\0');
    if (end_pos == std::string_view::npos) {
        // This could indicate a corrupt file, return what we can
        return std::string(start, max_len);
    }
    return std::string(start, end_pos);
}

// Primary implementation is inside a templated lambda to handle both PE32 and PE32+
std::expected<ImportParser, ImportParserError> ImportParser::create(
    std::span<const std::byte> file_buffer,
    const HeaderParser& header_parser,
    const RVAConverter& rva_converter) {

    std::vector<ImportedModule> modules;
    bool success = false;
    ImportParserError last_error = ImportParserError::NoImportDirectory;

    std::visit([&](const auto* nt_headers) {
        if (!nt_headers) {
            success = false;
            last_error = ImportParserError::ImportDirectoryCorrupted;
            return;
        }
        using NtHeaderType = std::remove_pointer_t<decltype(nt_headers)>;
        using ThunkDataType = std::conditional_t<std::is_same_v<NtHeaderType, pe::IMAGE_NT_HEADERS32>,
            pe::IMAGE_THUNK_DATA32,
            pe::IMAGE_THUNK_DATA64>;
        
        constexpr auto ordinal_flag = std::is_same_v<NtHeaderType, pe::IMAGE_NT_HEADERS32>
            ? pe::IMAGE_ORDINAL_FLAG32
            : pe::IMAGE_ORDINAL_FLAG64;

        const auto& data_directory = nt_headers->OptionalHeader.DataDirectory;
        const auto& import_directory = data_directory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT];
        const auto& iat_directory = data_directory[pe::IMAGE_DIRECTORY_ENTRY_IAT];

        if (import_directory.VirtualAddress == 0) {
            success = true; // No imports is not an error
            return;
        }

        auto import_dir_offset_exp = rva_converter.rva_to_offset(import_directory.VirtualAddress);
        if (!import_dir_offset_exp) {
            last_error = ImportParserError::RVAConversionFailed;
            return;
        }

        for (size_t desc_offset = *import_dir_offset_exp; ; desc_offset += sizeof(pe::IMAGE_IMPORT_DESCRIPTOR)) {
            const auto* desc = get_struct_at<pe::IMAGE_IMPORT_DESCRIPTOR>(file_buffer, desc_offset);
            if (!desc || (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0)) {
                break; // End of descriptors
            }

            auto dll_name_offset_exp = rva_converter.rva_to_offset(desc->Name);
            if (!dll_name_offset_exp) {
                last_error = ImportParserError::DllNameNotFound;
                continue; // Try next DLL
            }

            ImportedModule current_module;
            current_module.name = read_string_at(file_buffer, *dll_name_offset_exp);
            if (current_module.name.empty()) {
                last_error = ImportParserError::DllNameNotFound;
                continue;
            }

            uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            auto thunk_offset_exp = rva_converter.rva_to_offset(thunk_rva);
            if (!thunk_offset_exp) {
                last_error = ImportParserError::RVAConversionFailed;
                continue;
            }

            uint32_t iat_rva = desc->FirstThunk;
            auto iat_offset_exp = rva_converter.rva_to_offset(iat_rva);
            if (!iat_offset_exp) {
                 last_error = ImportParserError::RVAConversionFailed;
                 continue;
            }

            for (size_t i = 0; ; ++i) {
                size_t thunk_offset = *thunk_offset_exp + i * sizeof(ThunkDataType);
                const auto* thunk = get_struct_at<ThunkDataType>(file_buffer, thunk_offset);
                if (!thunk || thunk->u1.AddressOfData == 0) {
                    break; // End of thunks for this module
                }

                ImportedFunction func;
                if (thunk->u1.Ordinal & ordinal_flag) {
                    func.imported_by_ordinal = true;
                    func.ordinal = static_cast<uint16_t>(thunk->u1.Ordinal & 0xFFFF);
                } else {
                    auto name_rva = static_cast<uint32_t>(thunk->u1.AddressOfData);
                    auto name_offset_exp = rva_converter.rva_to_offset(name_rva);
                    if (!name_offset_exp) continue;

                    const auto* import_by_name = get_struct_at<pe::IMAGE_IMPORT_BY_NAME>(file_buffer, *name_offset_exp);
                    if (!import_by_name) continue;

                    func.name = std::string(import_by_name->Name);
                    func.ordinal = import_by_name->Hint;
                }

                // Advanced: Check for forwarded imports
                size_t iat_entry_offset = *iat_offset_exp + i * sizeof(ThunkDataType);
                const auto* iat_thunk = get_struct_at<ThunkDataType>(file_buffer, iat_entry_offset);
                if (iat_thunk) {
                    uint32_t iat_entry_rva = static_cast<uint32_t>(iat_thunk->u1.AddressOfData);
                    if (iat_entry_rva >= import_directory.VirtualAddress && 
                        iat_entry_rva < import_directory.VirtualAddress + import_directory.Size) {
                        // RVA is inside the import directory, it might be a forwarder string.
                        auto forwarded_name_offset_exp = rva_converter.rva_to_offset(iat_entry_rva);
                        if(forwarded_name_offset_exp) {
                            std::string potential_forward = read_string_at(file_buffer, *forwarded_name_offset_exp);
                            if (potential_forward.find('.') != std::string::npos) {
                                func.forwarded_to = std::move(potential_forward);
                            }
                        }
                    }
                }

                current_module.functions.push_back(std::move(func));
            }
            if(!current_module.functions.empty()){
                 modules.push_back(std::move(current_module));
            }
        }
        success = true;
    });

    if (!success) {
        return std::unexpected(last_error);
    }
    return ImportParser(std::move(modules));
}

ImportParser::ImportParser(std::vector<ImportedModule> modules)
    : m_modules(std::move(modules)) {}

std::span<const ImportedModule> ImportParser::get_modules() const noexcept {
    return m_modules;
}

} // namespace remax
