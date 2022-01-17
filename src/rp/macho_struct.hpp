// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "coloshell.hpp"
#include "platform.h"
#include "section.hpp"
#include "toolbox.hpp"
#include <array>
#include <cstring>
#include <fmt/printf.h>
#include <vector>

#ifdef WINDOWS
#pragma pack(push)
#pragma pack(1)
#endif

const uint32_t CPU_TYPE_x86_64 = 0x1000007;
const uint32_t CPU_TYPE_I386 = 7;

template <class T> struct RP_MACH_HEADER {};

template <> struct RP_MACH_HEADER<x86Version> {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;

  void display(const VerbosityLevel lvl) const {
    w_yel_lf("-> mach_header32:");

    display_hex_2fields_lf(ncmds, sizeofcmds);

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_field_lf(cpusubtype);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(magic, cpusubtype);
      display_hex_2fields_lf(filetype, flags);
    }
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template <> struct RP_MACH_HEADER<x64Version> {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;

  void display(const VerbosityLevel lvl) const {
    w_yel_lf("-> mach_header64:");

    display_hex_2fields_lf(ncmds, sizeofcmds);

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_field_lf(cpusubtype);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(magic, cpusubtype);
      display_hex_2fields_lf(filetype, flags);
      display_hex_field_lf(reserved);
    }
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

const uint32_t LC_SEGMENT = 1;
const uint32_t LC_SEGMENT_64 = 0x19;

struct RP_LOAD_COMMAND {
  uint32_t cmd;
  uint32_t cmdsize;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template <class T> struct RP_SEGMENT_COMMAND {
  std::array<char, 16> segname;
  T vmaddr;
  T vmsize;
  T fileoff;
  T filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;

  void display(VerbosityLevel lvl) const {
    w_yel_lf("-> segment_command");
    fmt::print("     {}\n", segname.data());

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_field_lf(vmaddr);
      display_hex_field_lf(vmsize);
      display_hex_field_lf(fileoff);
      display_hex_field_lf(filesize);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(maxprot, initprot);
      display_hex_2fields_lf(nsects, flags);
    }
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

using SegmentCommand32 = RP_SEGMENT_COMMAND<x86Version>;
using SegmentCommand64 = RP_SEGMENT_COMMAND<x64Version>;

const uint32_t S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
const uint32_t S_ATTR_SOME_INSTRUCTIONS = 0x400;

template <class T> struct RP_SECTION {};

template <> struct RP_SECTION<x86Version> {
  std::array<char, 16> sectname;
  std::array<char, 16> segname;
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;

  void display(VerbosityLevel lvl) const {
    w_yel_lf("-> section32");
    fmt::print("     {}.{}\n", segname.data(), sectname.data());

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_2fields_lf(addr, size);
      display_hex_2fields_lf(offset, align);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(reloff, nreloc);
      display_hex_2fields_lf(flags, reserved1);
    }
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template <> struct RP_SECTION<x64Version> {
  std::array<char, 16> sectname;
  std::array<char, 16> segname;
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;

  void display(VerbosityLevel lvl) const {
    w_yel_lf("-> section64");
    fmt::print("     {}.{}\n", segname.data(), sectname.data());

    if (lvl > VERBOSE_LEVEL_1) {
      display_hex_field_lf(addr);
      display_hex_field_lf(size);
      display_hex_2fields_lf(offset, align);
    }

    if (lvl > VERBOSE_LEVEL_2) {
      display_hex_2fields_lf(reloff, nreloc);
      display_hex_2fields_lf(flags, reserved1);
      display_hex_2fields_lf(reserved2, reserved3);
    }
  }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

#ifdef WINDOWS
#pragma pack(pop)
#endif

struct MachoLayout {
  virtual ~MachoLayout() = default;
  virtual void fill_structures(std::ifstream &file) = 0;
  virtual uint32_t get_size_mach_header() const = 0;
  virtual void display(const VerbosityLevel lvl = VERBOSE_LEVEL_1) const = 0;
  virtual std::vector<Section>
  get_executable_section(std::ifstream &file, const uint64_t base) const = 0;
  virtual uint64_t get_image_base_address() const = 0;
};

template <class T> struct MachoArchLayout : public MachoLayout {
  uint64_t base = 0;
  RP_MACH_HEADER<T> header;
  std::vector<std::unique_ptr<RP_SEGMENT_COMMAND<T>>> seg_commands;
  std::vector<std::unique_ptr<RP_SECTION<T>>> sections;

  uint32_t get_size_mach_header() const override {
    return sizeof(RP_MACH_HEADER<T>);
  }

  void fill_structures(std::ifstream &file) override {
    bool is_all_section_walked = false;
    std::streampos off = file.tellg();

    // Fill the header structure
    file.seekg(0, std::ios::beg);
    file.read((char *)&header, sizeof(RP_MACH_HEADER<T>));

    // The load commands now
    for (uint32_t i = 0; i < header.ncmds; ++i) {
      RP_LOAD_COMMAND loadcmd;

      file.read((char *)&loadcmd, sizeof(RP_LOAD_COMMAND));
      switch (loadcmd.cmd) {
      case LC_SEGMENT:
      case LC_SEGMENT_64: {
        auto seg_cmd = std::make_unique<RP_SEGMENT_COMMAND<T>>();

        file.read((char *)seg_cmd.get(), sizeof(RP_SEGMENT_COMMAND<T>));

        if (strcasecmp((char *)seg_cmd->segname.data(), "__TEXT") == 0) {
          // If this is the __text segment, we populate the base address of the
          // program
          base = uint64_t(seg_cmd->vmaddr);
        }

        // Directly following a segment_command data structure is an array of
        // section data structures, with the exact count determined by the
        // nsects field of the segment_command structure.
        for (uint32_t j = 0; j < seg_cmd->nsects; ++j) {
          auto sect = std::make_unique<RP_SECTION<T>>();
          file.read((char *)sect.get(), sizeof(RP_SECTION<T>));
          sections.push_back(std::move(sect));
        }

        seg_commands.push_back(std::move(seg_cmd));
        break;
      }

      default: {
        // We assume that all SEGMENT_HEADER[_64] are in first, and they
        // are all contiguous The proper way should be add cases for each
        // COMMAND possible, and increment the file pointer of the size of the
        // COMMAND read
        is_all_section_walked = true;
        break;
      }
      }

      if (is_all_section_walked) {
        break;
      }
    }

    file.seekg(off);
  }

  std::vector<Section>
  get_executable_section(std::ifstream &file,
                         const uint64_t base) const override {
    std::vector<Section> exc_sect;

    for (const auto &section : sections) {
      if (!(section->flags & S_ATTR_PURE_INSTRUCTIONS) &&
          !(section->flags & S_ATTR_SOME_INSTRUCTIONS)) {
        continue;
      }

      const auto vaddr = section->addr - base;
      const auto offset = section->offset;
      const auto size = section->size;
      Section s((char *)section->sectname.data(), offset, base + vaddr, size);
      s.dump(file);
      s.set_props(Section::Executable);
      exc_sect.push_back(std::move(s));
    }
    return exc_sect;
  }

  void display(const VerbosityLevel lvl = VERBOSE_LEVEL_1) const override {
    header.display(lvl);

    for (const auto &segcommand : seg_commands) {
      segcommand->display(lvl);
    }

    for (const auto &section : sections) {
      section->display(lvl);
    }
  }

  uint64_t get_image_base_address() const override { return base; }
};
