#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

#include "remax/FileLoader.hpp"
#include "remax/HeaderParser.hpp"
#include "remax/SectionManager.hpp"
#include "remax/RVAConverter.hpp"
#include "remax/ImportParser.hpp"

// Helper to join a vector of strings with a separator
std::string join_strings(const std::vector<std::string>& vec, const std::string& sep) {
    if (vec.empty()) {
        return "";
    }
    std::string s;
    for (const auto& i : vec) {
        s += i + sep;
    }
    s.erase(s.size() - sep.size());
    return s;
}

void print_error(remax::FileLoaderError error);
void print_error(remax::HeaderParserError error);
void print_error(remax::SectionManagerError error);
void print_error(remax::RVAConverterError error);
void print_error(remax::ImportParserError error);

void process_file(const std::filesystem::path& file_path) {
    // 1. Load the file
    auto loader_or_error = remax::FileLoader::create(file_path);
    if (!loader_or_error) {
        print_error(loader_or_error.error());
        return;
    }
    const auto& loader = *loader_or_error;
    std::cout << "Successfully loaded file '" << file_path << "' (" << loader.size() << " bytes)." << std::endl;

    // 2. Parse headers
    auto parser_or_error = remax::HeaderParser::create(loader.get_buffer());
    if (!parser_or_error) {
        print_error(parser_or_error.error());
        return;
    }
    const auto& parser = *parser_or_error;
    std::cout << "Architecture: " << (parser.is_64bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)") << std::endl;

    // 3. Parse and analyze sections
    auto section_manager_or_error = remax::SectionManager::create(loader.get_buffer(), parser);
    if (!section_manager_or_error) {
        print_error(section_manager_or_error.error());
        return;
    }
    const auto& section_manager = *section_manager_or_error;
    std::cout << "\n--- Section Analysis (" << section_manager.get_sections().size() << ") ---" << std::endl;
    for (const auto& section : section_manager.get_sections()) {
        std::cout << "  - Name: " << std::left << std::setw(10) << section.name
                  << "RVA: 0x" << std::hex << std::setw(8) << std::setfill('0') << section.header->VirtualAddress << "  "
                  << "Size: 0x" << std::setw(8) << section.header->Misc.VirtualSize << std::dec << std::setfill(' ')
                  << "  Characteristics: " << join_strings(section.characteristics_flags, ", ");
        if (section.is_suspicious) {
            std::cout << "  <-- SUSPICIOUS";
        }
        std::cout << std::endl;
    }
    std::cout << "--------------------------" << std::endl;

    // 4. Create RVA Converter
    auto rva_converter_or_error = remax::RVAConverter::create(parser, section_manager);
    if (!rva_converter_or_error) {
        print_error(rva_converter_or_error.error());
        return;
    }
    const auto& rva_converter = *rva_converter_or_error;

    // 5. Parse Imports
    auto import_parser_or_error = remax::ImportParser::create(loader.get_buffer(), parser, rva_converter);
    if (!import_parser_or_error) {
        print_error(import_parser_or_error.error());
    } else {
        const auto& import_parser = *import_parser_or_error;
        std::cout << "\n--- Import Analysis ---" << std::endl;
        if (import_parser.get_modules().empty()) {
            std::cout << "  No imported modules found." << std::endl;
        } else {
            for (const auto& mod : import_parser.get_modules()) {
                std::cout << "  [DLL] " << mod.name << std::endl;
                for (const auto& func : mod.functions) {
                    std::cout << "    - ";
                    if (func.imported_by_ordinal) {
                        std::cout << "Ordinal: " << func.ordinal;
                    } else {
                        std::cout << func.name;
                    }
                    if (func.forwarded_to) {
                        std::cout << "  (Forwarded to -> " << *func.forwarded_to << ")";
                    }
                    std::cout << std::endl;
                }
            }
        }
        std::cout << "-----------------------" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "REMA-X: Phase 2 - Advanced Structural Analysis" << std::endl;
    std::cout << "================================================" << std::endl;
    
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_pe_file>" << std::endl;
        return 1;
    }

    process_file(argv[1]);

    return 0;
}


// Error printing implementations
void print_error(remax::FileLoaderError error) {
    switch (error) {
        case remax::FileLoaderError::FileNotFound: std::cerr << "[Error] File not found or is not a regular file." << std::endl; break;
        case remax::FileLoaderError::FileOpenError: std::cerr << "[Error] Could not open the file." << std::endl; break;
        case remax::FileLoaderError::FileMapError: std::cerr << "[Error] Could not map the file to memory." << std::endl; break;
        case remax::FileLoaderError::FileEmpty: std::cerr << "[Error] File is empty." << std::endl; break;
    }
}
void print_error(remax::HeaderParserError error) {
    switch (error) {
        case remax::HeaderParserError::BufferTooSmall: std::cerr << "[Error] Buffer too small for PE headers." << std::endl; break;
        case remax::HeaderParserError::InvalidDosSignature: std::cerr << "[Error] Invalid DOS 'MZ' signature." << std::endl; break;
        case remax::HeaderParserError::InvalidNtSignature: std::cerr << "[Error] Invalid 'PE' signature." << std::endl; break;
        case remax::HeaderParserError::UnsupportedArchitecture: std::cerr << "[Error] Unsupported PE architecture." << std::endl; break;
    }
}
void print_error(remax::SectionManagerError error) {
    switch (error) {
        case remax::SectionManagerError::InvalidNumberOfSections: std::cerr << "[Error] Invalid number of sections." << std::endl; break;
        case remax::SectionManagerError::SectionHeaderCorrupted: std::cerr << "[Error] Section header info is corrupted." << std::endl; break;
        case remax::SectionManagerError::BufferTooSmallForSections: std::cerr << "[Error] Buffer too small for section headers." << std::endl; break;
        case remax::SectionManagerError::SectionNotFound: std::cerr << "[Error] Requested section not found." << std::endl; break;
    }
}
void print_error(remax::RVAConverterError error) {
    switch(error) {
        case remax::RVAConverterError::NoSectionFound: std::cerr << "[Error] RVA does not map to any section." << std::endl; break;
        case remax::RVAConverterError::InvalidRVA: std::cerr << "[Error] RVA points to virtual-only memory." << std::endl; break;
        default: std::cerr << "[Error] Unknown RVA conversion error." << std::endl; break;
    }
}
void print_error(remax::ImportParserError error) {
    switch(error) {
        case remax::ImportParserError::NoImportDirectory: std::cout << "[Info] No import directory found." << std::endl; break;
        case remax::ImportParserError::RVAConversionFailed: std::cerr << "[Error] Import parsing failed: RVA conversion error." << std::endl; break;
        case remax::ImportParserError::DllNameNotFound: std::cerr << "[Error] Import parsing failed: Could not read DLL name." << std::endl; break;
        default: std::cerr << "[Error] Failed to parse import directory." << std::endl; break;
    }
}
