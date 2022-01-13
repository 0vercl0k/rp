// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"
#include "macho_struct.hpp"

class Macho : public ExecutableFormat {
public:
  std::shared_ptr<CPU> get_cpu(std::ifstream &file) override;

  std::string get_class_name(void) const override;

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const override;

  uint64_t raw_offset_to_va(const uint64_t absolute_raw_offset,
                            const uint64_t absolute_raw_offset_section) const;

  void display_information(const VerbosityLevel lvl) const override;

  uint64_t get_image_base_address(void) const override;

private:
  template <class T> void init_properly_macho_layout() {
    m_MachoLayout = std::make_shared<MachoArchLayout<T>>();
  }

  std::shared_ptr<MachoLayout> m_MachoLayout;

  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override;
};
