// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "executable_format.hpp"

class Raw : public ExecutableFormat {
public:
  std::shared_ptr<CPU> get_cpu(std::ifstream &file) override {
    /* Don't need this method */
    return nullptr;
  }

  std::string get_class_name(void) const override;

  std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const override;

  uint64_t raw_offset_to_va(const uint64_t absolute_raw_offset,
                            const uint64_t absolute_raw_offset_section) const;

  uint64_t get_image_base_address(void) const override;
};
