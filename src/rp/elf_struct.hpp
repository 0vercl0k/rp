// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "coloshell.hpp"
#include "platform.h"
#include "rpexception.hpp"
#include "section.hpp"
#include "toolbox.hpp"
#include <array>
#include <cstring>
#include <fmt/printf.h>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>

const uint32_t EI_NIDENT = 16;

#ifdef WINDOWS
#pragma pack(push)
#pragma pack(1)
#endif

template <class T> struct Elf_Ehdr {
  std::array<uint8_t, EI_NIDENT> e_ident;
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  T e_entry;
  T e_phoff;
  T e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> ELF_Ehdr:");

    display_short_hex_field_lf(e_phoff);
    display_short_hex_field_lf(e_shoff);

    display_short_hex_field_lf(e_flags);

    display_short_hex_2fields_lf(e_phentsize, e_phnum);
    display_short_hex_2fields_lf(e_shentsize, e_shnum);
    display_short_hex_2fields_lf(e_shstrndx, e_ehsize);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using Elf32_Ehdr = Elf_Ehdr<x86Version>;
using Elf64_Ehdr = Elf_Ehdr<x64Version>;

const uint32_t EI_OSABI = 7;
const uint32_t EI_CLASS = 4;
const uint32_t ELFCLASS32 = 1;
const uint32_t ELFCLASS64 = 2;

template <class T> struct Elf_Phdr {
}
#ifdef LINUX
__attribute__((packed))
#endif
;

static std::string type_to_str(const uint32_t p_type) {
  switch (p_type) {
  case 0: {
    return "NULL";
  }

  case 1: {
    return "LOAD";
  }

  case 2: {
    return "DYNAMIC";
  }

  case 3: {
    return "INTERP";
  }

  case 4: {
    return "NOTE";
  }

  case 5: {
    return "SHLIB";
  }

  case 6: {
    return "PHDR";
  }

  case 7: {
    return "TLS";
  }

  case 8: {
    return "NUM";
  }

  case 0x60000000: {
    return "LOOS";
  }

  case 0x6fffffff: {
    return "HIOS";
  }

  case 0x70000000: {
    return "LOPROC";
  }

  case 0x7fffffff: {
    return "HIPROC";
  }

  case 0x6474e550: {
    return "EH_FRAME";
  }

  case 0x6474e551: {
    return "STACK";
  }

  case 0x6474e552: {
    return "RELRO";
  }

  case 0x6474e553: {
    return "PROPERTY";
  }

  case 0x65041580: {
    return "PAX_FLAGS";
  }
  }

  std::abort();
  return "unknown type";
}

static std::string flags_to_str(const uint32_t p_flags) {
  std::string ret(3, '-');

  if (p_flags & 4) {
    ret[0] = 'r';
  }

  if (p_flags & 2) {
    ret[1] = 'w';
  }

  if (p_flags & 1) {
    ret[2] = 'x';
  }

  return ret;
}

template <> struct Elf_Phdr<x86Version> {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> Elf_Phdr32: ");
    fmt::print("     {} {}\n", type_to_str(p_type), flags_to_str(p_flags));

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_2fields_lf(p_vaddr, p_filesz);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(p_align, p_flags);
    }

    display_hex_2fields_lf(p_offset, p_paddr);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template <> struct Elf_Phdr<x64Version> {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    w_yel_lf("-> Elf_Phdr64:");
    fmt::print("     {} {}\n", type_to_str(p_type), flags_to_str(p_flags));

    if (lvl > VERBOSE_LEVEL_1) {
      display_short_hex_2fields_lf(p_vaddr, p_filesz);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_short_hex_2fields_lf(p_align, p_flags);
    }

    display_short_hex_2fields_lf(p_offset, p_paddr);
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using Elf32_Phdr = Elf_Phdr<x86Version>;
using Elf64_Phdr = Elf_Phdr<x64Version>;

template <class T> struct Elf_Shdr {
  uint32_t sh_name;
  uint32_t sh_type;
  T sh_flags;
  T sh_addr;
  T sh_offset;
  T sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  T sh_addralign;
  T sh_entsize;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using Elf32_Shdr = Elf_Shdr<x86Version>;
using Elf64_Shdr = Elf_Shdr<x64Version>;

#ifdef WINDOWS
#pragma pack(pop)
#endif

template <class T> struct Elf_Shdr_Abstraction {
  Elf_Shdr<T> header;
  std::string name;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const {
    fmt::print("0x{:<15x}0x{:<15x}{:32}\n", header.sh_addr, header.sh_size,
               name);
  }
};

using Elf_Shdr32_Abstraction = Elf_Shdr_Abstraction<x86Version>;
using Elf_Shdr64_Abstraction = Elf_Shdr_Abstraction<x64Version>;

struct ExecutableLinkingFormatLayout {
  virtual ~ExecutableLinkingFormatLayout() = default;
  virtual void fill_structures(std::ifstream &file) = 0;
  virtual void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const = 0;
  virtual uint64_t get_image_base_address(void) const = 0;
  virtual std::vector<Section>
  get_executable_section(std::ifstream &file, const uint64_t base) const = 0;
  virtual uint16_t get_cpu(void) const = 0;
};

const uint32_t SHT_SYMTAB = 2;
const uint32_t SHT_STRTAB = 3;

const uint32_t RP_ELFEM_386 = 0x03;
const uint32_t RP_ELFEM_X86_64 = 0x3e;
const uint32_t RP_ELFEM_ARM = 0x28;

template <class T> struct ELFLayout : public ExecutableLinkingFormatLayout {
  Elf_Ehdr<T> elfHeader;
  std::vector<std::unique_ptr<Elf_Phdr<T>>> elfProgramHeaders;
  std::vector<std::unique_ptr<Elf_Shdr_Abstraction<T>>> elfSectionHeaders;
  T offset_string_table, size_string_table;
  uint64_t image_base = 0;

  void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const override {
    uint32_t i = 0;
    elfHeader.display(lvl);

    for (const auto &programheader : elfProgramHeaders) {
      programheader->display(lvl);
    }

    w_yel_lf("-> Elf Headers:");
    w_gre("id");
    fmt::print("{:10}", "");
    w_gre("addr");
    fmt::print("{:13}", "");
    w_gre("size");
    fmt::print("{:13}", "");
    w_gre("name");
    fmt::print("{:32}\n", "");
    fmt::print("{:-<70}-\n", "");

    for (const auto &sectionheader : elfSectionHeaders) {
      fmt::print("0x{:<10x}", i++);
      sectionheader->display(lvl);
    }
  }

  T find_string_table(std::ifstream &file) {
    Elf_Shdr<T> elf_shdr;
    std::streampos off = file.tellg();

    file.seekg(std::streamoff(elfHeader.e_shoff), std::ios::beg);

    for (uint32_t i = 0; i < elfHeader.e_shnum; ++i) {
      file.read((char *)&elf_shdr, sizeof(Elf_Shdr<T>));
      if (elf_shdr.sh_addr == 0 && elf_shdr.sh_type == SHT_STRTAB) {
        offset_string_table = elf_shdr.sh_offset;
        size_string_table = elf_shdr.sh_size;
        break;
      }
    }

    file.seekg(off);
    return offset_string_table;
  }

  void fill_structures(std::ifstream &file) override {
    // Remember where the caller was in the file
    std::streampos off = file.tellg();

    // Dump the Elf Header
    file.seekg(0, std::ios::beg);
    file.read((char *)&elfHeader, sizeof(Elf_Ehdr<T>));

    // Goto the first Program Header, and dump them
    file.seekg(std::streamoff(elfHeader.e_phoff), std::ios::beg);
    for (uint32_t i = 0; i < elfHeader.e_phnum; ++i) {
      auto pElfProgramHeader = std::make_unique<Elf_Phdr<T>>();

      file.read((char *)pElfProgramHeader.get(), sizeof(Elf_Phdr<T>));

      // Here we assume that the first LOAD program header encountered will
      // hold the image base address and I guess this assumption is quite wrong
      // https://stackoverflow.com/questions/18296276/base-address-of-elf
      if (type_to_str(pElfProgramHeader->p_type) == "LOAD" && image_base == 0) {
        image_base = pElfProgramHeader->p_vaddr;
      }
      elfProgramHeaders.push_back(std::move(pElfProgramHeader));
    }

    // If we want to know the name of the different section, we need to find the
    // string table section
    find_string_table(file);

    // Keep the string table in memory
    file.seekg(std::streamoff(offset_string_table), std::ios::beg);

    std::vector<char> string_table_section;
    string_table_section.resize(uint32_t(size_string_table));
    file.read(string_table_section.data(), std::streamsize(size_string_table));

    // Goto the first Section Header, and dump them !
    file.seekg(std::streamoff(elfHeader.e_shoff), std::ios::beg);
    for (uint32_t i = 0; i < elfHeader.e_shnum; ++i) {
      auto pElfSectionHeader = std::make_unique<Elf_Shdr_Abstraction<T>>();

      file.read((char *)&pElfSectionHeader->header, sizeof(Elf_Shdr<T>));

      // Resolve the name of the section
      if (pElfSectionHeader->header.sh_name < size_string_table) {
        // Yeah we know where is the string
        char *name_section =
            string_table_section.data() + pElfSectionHeader->header.sh_name;
        pElfSectionHeader->name =
            (std::strlen(name_section) == 0) ? "unknown section" : name_section;
      }

      elfSectionHeaders.push_back(std::move(pElfSectionHeader));
    }

    // Set correctly the pointer
    file.seekg(off);
  }

  std::vector<Section>
  get_executable_section(std::ifstream &file,
                         const uint64_t base) const override {
    std::vector<Section> exec_sections;

    for (const auto &programheader : elfProgramHeaders) {
      if (!(programheader->p_flags & 1)) {
        continue;
      }

      const auto vaddr = programheader->p_vaddr - image_base;
      const auto p_offset = programheader->p_offset;
      const auto p_filesz = programheader->p_filesz;
      Section sec(type_to_str(programheader->p_type).c_str(), p_offset,
                  base + vaddr, p_filesz);

      sec.dump(file);
      sec.set_props(Section::Executable);
      exec_sections.push_back(std::move(sec));
    }

    return exec_sections;
  }

  uint64_t get_image_base_address() const override { return image_base; }

  uint16_t get_cpu() const override { return elfHeader.e_machine; }
};
