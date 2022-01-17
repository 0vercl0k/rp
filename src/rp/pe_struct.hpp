// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "coloshell.hpp"
#include "platform.h"
#include "rpexception.hpp"
#include "toolbox.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <vector>

// Calculate the byte offset of a field in a structure of type |type|.
#define RP_FIELD_OFFSET(type, field)                                           \
  ((uint32_t)(uintptr_t) & (((type *)0)->field))

const uint16_t RP_IMAGE_DOS_SIGNATURE = 0x5A4D;    // MZ
const uint32_t RP_IMAGE_NT_SIGNATURE = 0x00004550; // PE00

#ifdef WINDOWS
#pragma pack(push)
#pragma pack(1)
#endif

struct RP_IMAGE_DOS_HEADER {       // DOS .EXE header
  uint16_t e_magic;                // Magic number
  uint16_t e_cblp;                 // Bytes on last page of file
  uint16_t e_cp;                   // Pages in file
  uint16_t e_crlc;                 // Relocations
  uint16_t e_cparhdr;              // Size of header in paragraphs
  uint16_t e_minalloc;             // Minimum extra paragraphs needed
  uint16_t e_maxalloc;             // Maximum extra paragraphs needed
  uint16_t e_ss;                   // Initial (relative) SS value
  uint16_t e_sp;                   // Initial SP value
  uint16_t e_csum;                 // Checksum
  uint16_t e_ip;                   // Initial IP value
  uint16_t e_cs;                   // Initial (relative) CS value
  uint16_t e_lfarlc;               // File address of relocation table
  uint16_t e_ovno;                 // Overlay number
  std::array<uint16_t, 4> e_res;   // Reserved words
  uint16_t e_oemid;                // OEM identifier (for e_oeminfo)
  uint16_t e_oeminfo;              // OEM information; e_oemid specific
  std::array<uint16_t, 10> e_res2; // Reserved words
  uint32_t e_lfanew;               // File address of new exe header

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> IMAGE_DOS_HEADER:");

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_2fields_lf(e_magic, e_cblp);
      display_hex_2fields_lf(e_cp, e_crlc);
      display_hex_field_lf(e_cparhdr);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(e_minalloc, e_maxalloc);
      display_hex_2fields_lf(e_ss, e_sp);
      display_hex_2fields_lf(e_csum, e_ip);
      display_hex_2fields_lf(e_cs, e_lfarlc);
      display_hex_2fields_lf(e_oemid, e_oeminfo);
    }

    display_hex_field_lf(e_lfanew);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

const uint16_t RP_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
const uint16_t RP_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
const uint16_t RP_IMAGE_FILE_MACHINE_I386 = 0x14c;
const uint16_t RP_IMAGE_FILE_MACHINE_ARMTHUMB2LE = 0x1c4;

struct RP_IMAGE_FILE_HEADER {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;

  uint16_t get_size_of_optionnal_header() const { return SizeOfOptionalHeader; }

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> IMAGE_FILE_HEADER:");

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_2fields_lf(Machine, SizeOfOptionalHeader);
      display_hex_field_lf(PointerToSymbolTable);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(TimeDateStamp, Characteristics);
    }

    display_hex_field_lf(NumberOfSections);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

//
// Directory format.
//

struct RP_IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t Size;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

const uint32_t RP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

//
// Optional header format.
//

const uint16_t RP_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x40;
const uint16_t RP_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x100;

template <class T> struct RP_IMAGE_OPTIONAL_HEADER {};

template <> struct RP_IMAGE_OPTIONAL_HEADER<x86Version> {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  std::array<RP_IMAGE_DATA_DIRECTORY, RP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES>
      DataDirectory;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> IMAGE_OPTIONAL_HEADER32:");

    fmt::print(" ASLR: ");
    w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE)
                 ? "Yes"
                 : "No");

    fmt::print(" NX: ");
    w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT)
                 ? "Yes"
                 : "No");

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_2fields_lf(SectionAlignment, FileAlignment);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(SizeOfInitializedData, SizeOfUninitializedData);
      display_hex_field_lf(Magic);
    }

    display_hex_2fields_lf(SizeOfCode, AddressOfEntryPoint);
    display_hex_2fields_lf(BaseOfCode, BaseOfCode);
    display_hex_field_lf(ImageBase);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template <> struct RP_IMAGE_OPTIONAL_HEADER<x64Version> {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  std::array<RP_IMAGE_DATA_DIRECTORY, RP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES>
      DataDirectory;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> IMAGE_OPTIONAL_HEADERS64:");

    fmt::print(" ASLR: ");
    w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE)
                 ? "Yes"
                 : "No");

    fmt::print(" NX: ");
    w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT)
                 ? "Yes"
                 : "No");

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_2fields_lf(SizeOfInitializedData, SizeOfUninitializedData);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(SectionAlignment, FileAlignment);
      display_hex_field_lf(Magic);
    }

    display_hex_2fields_lf(SizeOfCode, AddressOfEntryPoint);
    display_hex_field_lf(BaseOfCode);
    display_hex_field_lf(ImageBase);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using RP_IMAGE_OPTIONAL_HEADER32 = RP_IMAGE_OPTIONAL_HEADER<x86Version>;
using RP_IMAGE_OPTIONAL_HEADER64 = RP_IMAGE_OPTIONAL_HEADER<x64Version>;

//
// Section header format.
//

const uint32_t RP_IMAGE_SCN_MEM_EXECUTE = 0x00000020;
const uint32_t RP_IMAGE_SIZEOF_SHORT_NAME = 8;

struct RP_IMAGE_SECTION_HEADER {
  std::array<uint8_t, RP_IMAGE_SIZEOF_SHORT_NAME> Name;
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;

  std::string get_name() const {
    uint8_t name_null_terminated[RP_IMAGE_SIZEOF_SHORT_NAME + 1] = {};
    memcpy(name_null_terminated, Name.data(), Name.size());
    return (char *)name_null_terminated;
  }

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> IMAGE_SECTION_HEADER");

    fmt::print("     {}\n", get_name());

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_field_lf(Characteristics);
    }

    display_hex_2fields_lf(Misc.PhysicalAddress, VirtualAddress);
    display_hex_2fields_lf(SizeOfRawData, PointerToRawData);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template <class T> struct RP_IMAGE_NT_HEADERS {
  uint32_t Signature;
  RP_IMAGE_FILE_HEADER FileHeader;
  RP_IMAGE_OPTIONAL_HEADER<T> OptionalHeader;

  // Keep in mind this offset is relative to the NT Header! So if you want the
  // PA of the first section: get_offset_first_section() +
  // IMAGE_DOS_HEADER.e_lfanew
  uintptr_t get_offset_first_section() const {
    return uintptr_t(RP_FIELD_OFFSET(RP_IMAGE_NT_HEADERS<T>, OptionalHeader) +
                     FileHeader.SizeOfOptionalHeader);
  }

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> IMAGE_NT_HEADERS:");

    if (lvl > VERBOSE_LEVEL_1) {
      if (FileHeader.get_size_of_optionnal_header() >= sizeof(OptionalHeader))
        OptionalHeader.display(lvl);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_field_lf(Signature);
    }

    FileHeader.display(lvl);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using RP_IMAGE_NT_HEADERS32 = RP_IMAGE_NT_HEADERS<x86Version>;
using RP_IMAGE_NT_HEADERS64 = RP_IMAGE_NT_HEADERS<x64Version>;

#ifdef WINDOWS
#pragma pack(pop)
#endif

struct PortableExecutableLayout {
  RP_IMAGE_DOS_HEADER imgDosHeader;
  std::vector<RP_IMAGE_SECTION_HEADER> imgSectionHeaders;

  virtual ~PortableExecutableLayout() = default;
  virtual void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    imgDosHeader.display(lvl);
  }

  uint32_t get_image_dos_header_size() const {
    return sizeof(RP_IMAGE_DOS_HEADER);
  }

  uint32_t get_image_section_header_size() const {
    return sizeof(RP_IMAGE_SECTION_HEADER);
  }

  virtual uint32_t get_nt_headers_size() const = 0;
  virtual void fill_nt_structures(std::ifstream &file) = 0;
  virtual uint64_t get_image_base_address() const = 0;
};

/* Some magic..and ABSTRACTION */
template <class T> struct PELayout : public PortableExecutableLayout {
  RP_IMAGE_NT_HEADERS<T> imgNtHeaders;

  uint32_t get_nt_headers_size() const override {
    return sizeof(RP_IMAGE_NT_HEADERS<T>);
  }

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const override {
    PortableExecutableLayout::display(lvl);
    imgNtHeaders.display(lvl);
    if (lvl > VERBOSE_LEVEL_1) {
      for (const auto &sectionheader : imgSectionHeaders)
        sectionheader.display();
    }
  }

  void fill_nt_structures(std::ifstream &file) override {
    // Remember where the caller was in the file
    std::streampos off = file.tellg();

    file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
    file.read((char *)&imgNtHeaders, get_nt_headers_size());

    file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
    // This offset is relative to the NT Header, do not forget to move the file
    // pointer on it
    file.seekg(imgNtHeaders.get_offset_first_section(), std::ios::cur);

    for (uint32_t i = 0; i < imgNtHeaders.FileHeader.NumberOfSections; ++i) {
      RP_IMAGE_SECTION_HEADER imgSectionHeader;
      file.read((char *)&imgSectionHeader, get_image_section_header_size());
      imgSectionHeaders.push_back(std::move(imgSectionHeader));
    }

    file.seekg(off);
  }

  uint64_t get_image_base_address() const override {
    return imgNtHeaders.OptionalHeader.ImageBase;
  }
};

using PELayout32 = PELayout<x86Version>;
using PELayout64 = PELayout<x64Version>;
