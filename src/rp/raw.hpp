// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"

class Raw : public ExecutableFormat {
public:
  std::shared_ptr<CPU> get_cpu(std::ifstream &file) override {
    /* Don't need this method */
    return nullptr;
  }

  std::string get_class_name() const { return "raw"; }

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const {
    std::vector<std::shared_ptr<Section>> executable_sections;

    uint64_t raw_file_size = get_file_size(file);

    /* It is a raw file -> we have only one "virtual" section */
    std::shared_ptr<Section> sect =
        std::make_shared<Section>(".raw", 0, 0, raw_file_size);

    sect->dump(file);
    sect->set_props(Section::Executable);

    executable_sections.push_back(sect);

    return executable_sections;
  }

  uint64_t raw_offset_to_va(const uint64_t absolute_raw_offset,
                            const uint64_t absolute_raw_offset_section) const {
    return absolute_raw_offset;
  }

  uint64_t get_image_base_address() const { return 0; }
};
