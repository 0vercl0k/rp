// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"

class Raw : public ExecutableFormat {
public:
  std::unique_ptr<CPU> get_cpu(std::ifstream &file) override {
    // Don't need this method
    return nullptr;
  }

  std::string get_class_name() const override { return "raw"; }

  std::vector<std::unique_ptr<Section>>
  get_executables_section(std::ifstream &file,
                          const uint64_t base) const override {
    std::vector<std::unique_ptr<Section>> executable_sections;

    uint64_t raw_file_size = get_file_size(file);

    // It is a raw file -> we have only one "virtual" section
    auto sect = std::make_unique<Section>(".raw", 0, base, raw_file_size);
    sect->dump(file);
    sect->set_props(Section::Executable);
    executable_sections.push_back(std::move(sect));
    return executable_sections;
  }

  uint64_t get_image_base_address() const override { return 0; }

private:
  uint64_t raw_offset_to_va(const uint64_t absolute_raw_offset,
                            const uint64_t absolute_raw_offset_section) const {
    return absolute_raw_offset;
  }
};
