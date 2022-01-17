// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"
#include "pe_struct.hpp"
#include "rpexception.hpp"

class PE : public ExecutableFormat {
public:
  std::unique_ptr<CPU> get_cpu(std::ifstream &file) override {
    CPU::E_CPU cpu_type = extract_information_from_binary(file);
    switch (cpu_type) {
    case CPU::CPU_x86: {
      return std::make_unique<x86>();
    }

    case CPU::CPU_x64: {
      return std::make_unique<x64>();
    }

    case CPU::CPU_ARM: {
      return std::make_unique<ARM>();
    }

    default: {
      RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    }
  }

  void display_information(const VerbosityLevel lvl) const override {
    ExecutableFormat::display_information(lvl);
    fmt::print("PE Information:\n");
    m_pPELayout->display(lvl);
  }

  std::string get_class_name() const override { return "PE"; }

  std::vector<Section>
  get_executables_section(std::ifstream &file,
                          const uint64_t base) const override {
    std::vector<Section> exec_sections;

    for (const auto &sectionheader : m_pPELayout->imgSectionHeaders) {
      if (!(sectionheader.Characteristics & RP_IMAGE_SCN_MEM_EXECUTE)) {
        continue;
      }

      const auto pointertorawdata = sectionheader.PointerToRawData;
      const auto virtualaddress = sectionheader.VirtualAddress;
      const auto sizeofrawdata = sectionheader.SizeOfRawData;
      Section sec(sectionheader.get_name().c_str(), pointertorawdata,
                  base + virtualaddress, sizeofrawdata);
      sec.dump(file);
      sec.set_props(Section::Executable);
      exec_sections.push_back(std::move(sec));
    }
    return exec_sections;
  }

private:
  uint64_t get_image_base_address() const override {
    return m_pPELayout->get_image_base_address();
  }

  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override {
    RP_IMAGE_DOS_HEADER imgDosHeader;
    RP_IMAGE_NT_HEADERS32 imgNtHeaders32;
    CPU::E_CPU cpu = CPU::CPU_UNKNOWN;

    fmt::print("Loading PE information..\n");

    // Remember where the caller was in the file
    std::streampos off = file.tellg();

    file.seekg(0, std::ios::beg);
    file.read((char *)&imgDosHeader, sizeof(RP_IMAGE_DOS_HEADER));

    file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
    // Yeah, in fact, we don't know yet if it is a x86/x64 PE; so just we grab
    // the signature field, FILE_HEADER and the field Magic
    file.read((char *)&imgNtHeaders32, sizeof(uint32_t) +
                                           sizeof(RP_IMAGE_FILE_HEADER) +
                                           sizeof(uint32_t));

    if (imgNtHeaders32.Signature != RP_IMAGE_NT_SIGNATURE) {
      RAISE_EXCEPTION(
          "This file doesn't seem to be a correct PE (bad IMAGE_NT_SIGNATURE)");
    }

    switch (imgNtHeaders32.OptionalHeader.Magic) {
    case RP_IMAGE_NT_OPTIONAL_HDR32_MAGIC: {
      switch (imgNtHeaders32.FileHeader.Machine) {
      case RP_IMAGE_FILE_MACHINE_I386: {
        cpu = CPU::CPU_x86;
        break;
      }

      case RP_IMAGE_FILE_MACHINE_ARMTHUMB2LE: {
        cpu = CPU::CPU_ARM;
        break;
      }

      default: {
        RAISE_EXCEPTION("Cannot determine the CPU type");
      }
      }
      break;
    }

    case RP_IMAGE_NT_OPTIONAL_HDR64_MAGIC: {
      cpu = CPU::CPU_x64;
      break;
    }

    default: {
      RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    }

    // Ok, now we can allocate the good version of the PE Layout the 32bits
    // version there!
    if (cpu == CPU::CPU_x64) {
      init_properly_PELayout<x64Version>();
    } else {
      init_properly_PELayout<x86Version>();
    }

    // Now we can fill the structure
    std::memcpy(&m_pPELayout->imgDosHeader, &imgDosHeader,
                m_pPELayout->get_image_dos_header_size());

    m_pPELayout->fill_nt_structures(file);

    file.seekg(off);
    return cpu;
  }

  template <class T> void init_properly_PELayout() {
    m_pPELayout = std::make_unique<PELayout<T>>();
    if (m_pPELayout == nullptr) {
      RAISE_EXCEPTION("m_PELayout allocation failed");
    }
  }

  std::unique_ptr<PortableExecutableLayout> m_pPELayout;
};
