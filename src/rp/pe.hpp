// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"
#include "pe_struct.hpp"
#include "rpexception.hpp"

class PE : public ExecutableFormat {
public:
  std::shared_ptr<CPU> get_cpu(std::ifstream &file) override;

  void display_information(const VerbosityLevel lvl) const override;

  std::string get_class_name(void) const override;

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const override;

  uint64_t get_image_base_address(void) const override;

private:
  CPU::E_CPU extract_information_from_binary(std::ifstream &file) override;

  template <class T> void init_properly_PELayout() {
    m_pPELayout = std::make_shared<PELayout<T>>();
    if (m_pPELayout == nullptr)
      RAISE_EXCEPTION("m_PELayout allocation failed");
  }

  std::shared_ptr<PortableExecutableLayout> m_pPELayout;
};
