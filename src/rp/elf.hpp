// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"

#include "arm.hpp"
#include "elf_struct.hpp"
#include "rpexception.hpp"
#include "x64.hpp"
#include "x86.hpp"

class Elf : public ExecutableFormat {
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
    fmt::print("Elf Information:\n");
    m_ELFLayout->display(lvl);
  }

  std::string get_class_name() const override { return "Elf"; }

  std::vector<Section>
  get_executables_section(std::ifstream &file,
                          const uint64_t base) const override {
    return m_ELFLayout->get_executable_section(file, base);
  }

  uint64_t get_image_base_address() const override {
    return m_ELFLayout->get_image_base_address();
  }

private:
  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override {
    uint32_t size_init = 0;
    std::array<uint8_t, EI_NIDENT> buf;
    CPU::E_CPU cpu = CPU::CPU_UNKNOWN;
    fmt::print("Loading ELF information..\n");

    std::streampos off = file.tellg();
    file.seekg(0, std::ios::beg);
    file.read((char *)buf.data(), EI_NIDENT);

    switch (buf.at(EI_CLASS)) {
    case ELFCLASS32: {
      size_init = 4;
      break;
    }

    case ELFCLASS64: {
      size_init = 8;
      break;
    }

    default: {
      RAISE_EXCEPTION("Cannot determine the architecture size");
    }
    }

    if (size_init == 8) {
      init_properly_ELFLayout<x64Version>();
    } else {
      init_properly_ELFLayout<x86Version>();
    }

    // Filling the structure now
    m_ELFLayout->fill_structures(file);

    // Set correctly the pointer
    file.seekg(off);

    switch (m_ELFLayout->get_cpu()) {
    case RP_ELFEM_386: {
      cpu = CPU::CPU_x86;
      break;
    }

    case RP_ELFEM_X86_64: {
      cpu = CPU::CPU_x64;
      break;
    }

    case RP_ELFEM_ARM: {
      cpu = CPU::CPU_ARM;
      break;
    }

    default: {
      RAISE_EXCEPTION("Cannot determine the CPU type");
    }
    }

    return cpu;
  }

  template <class T> void init_properly_ELFLayout() {
    m_ELFLayout = std::make_unique<ELFLayout<T>>();
    if (m_ELFLayout == nullptr) {
      RAISE_EXCEPTION("m_ELFLayout allocation failed");
    }
  }

  std::unique_ptr<ExecutableLinkingFormatLayout> m_ELFLayout;
};
