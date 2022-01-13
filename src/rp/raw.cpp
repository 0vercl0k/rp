// Axel '0vercl0k' Souchet - January 12 2022
#include "raw.hpp"
#include "rpexception.hpp"

std::string Raw::get_class_name(void) const { return "raw"; }

std::vector<std::shared_ptr<Section>>
Raw::get_executables_section(std::ifstream &file) const {
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

uint64_t
Raw::raw_offset_to_va(const uint64_t absolute_raw_offset,
                      const uint64_t absolute_raw_offset_section) const {
  return absolute_raw_offset;
}

uint64_t Raw::get_image_base_address(void) const { return 0; }