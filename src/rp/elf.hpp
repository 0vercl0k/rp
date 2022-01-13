// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "elf_struct.hpp"
#include "executable_format.hpp"
#include "rpexception.hpp"

class Elf : public ExecutableFormat {
public:
  std::shared_ptr<CPU> get_cpu(std::ifstream &file) override;

  void display_information(const VerbosityLevel lvl) const override;

  std::string get_class_name(void) const override;

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const override;

  uint64_t get_image_base_address(void) const override;

private:
  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override;

  template <class T> void init_properly_ELFLayout(void) {
    m_ELFLayout = std::make_shared<ELFLayout<T>>();
    if (m_ELFLayout == nullptr)
      RAISE_EXCEPTION("m_ELFLayout allocation failed");
  }

  std::shared_ptr<ExecutableLinkingFormatLayout> m_ELFLayout;
};
