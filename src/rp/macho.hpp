// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"
#include "macho_struct.hpp"

class Macho : public ExecutableFormat {
public:
  std::shared_ptr<CPU> get_cpu(std::ifstream &file) override {
    std::shared_ptr<CPU> cpu;
    RP_MACH_HEADER<x86Version> header32;

    std::cout << "Loading Mach-O information.." << std::endl;

    // Remember where the caller was in the file
    std::streampos off = file.tellg();

    file.seekg(0, std::ios::beg);
    file.read((char *)&header32, sizeof(RP_MACH_HEADER<x86Version>));

    switch (header32.cputype) {
    case CPU_TYPE_x86_64: {
      cpu = std::make_shared<x64>();
      init_properly_macho_layout<x64Version>();
      break;
    }

    case CPU_TYPE_I386: {
      cpu = std::make_shared<x86>();
      init_properly_macho_layout<x86Version>();
      break;
    }

    default: {
      RAISE_EXCEPTION(
          "Cannot determine which architecture is used in this Mach-O file");
    }
    }

    file.seekg(off);

    if (cpu == nullptr) {
      RAISE_EXCEPTION("Cannot allocate cpu");
    }

    // Now we can fill the structure
    m_MachoLayout->fill_structures(file);
    return cpu;
  }

  std::string get_class_name() const override { return "Mach-o"; }

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const override {
    return m_MachoLayout->get_executable_section(file);
  }

  void display_information(const VerbosityLevel lvl) const override {
    ExecutableFormat::display_information(lvl);
    m_MachoLayout->display(lvl);
  }

  uint64_t get_image_base_address() const override {
    return m_MachoLayout->get_image_base_address();
  }

private:
  template <class T> void init_properly_macho_layout() {
    m_MachoLayout = std::make_shared<MachoArchLayout<T>>();
  }

  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override {
    return CPU::CPU_UNKNOWN;
  }

  std::shared_ptr<MachoLayout> m_MachoLayout;
};
