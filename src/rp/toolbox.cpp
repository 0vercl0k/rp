// Axel '0vercl0k' Souchet - January 12 2022
#include "toolbox.hpp"
#include "elf.hpp"
#include "macho.hpp"
#include "pe.hpp"
#include "rpexception.hpp"
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

std::string verbosity_to_string(const VerbosityLevel lvl) {
  switch (lvl) {
  case VERBOSE_LEVEL_1: {
    return "VERBOSE_LEVEL_1";
  }

  case VERBOSE_LEVEL_2: {
    return "VERBOSE_LEVEL_2";
  }

  case VERBOSE_LEVEL_3: {
    return "VERBOSE_LEVEL_3";
  }
  }

  std::abort();
  return "Unknwon";
}

std::streampos get_file_size(std::ifstream &file) {
  std::streampos backup = file.tellg();

  file.seekg(0, std::ios::beg);
  std::streampos fsize = file.tellg();

  file.seekg(0, std::ios::end);
  fsize = file.tellg() - fsize;

  file.seekg(backup);
  return fsize;
}

// this function is completely inspirated from the previous work of jonathan
// salwan
bool is_matching(const std::string &str, const std::string &pattern) {
  // we have to check the *entire* pattern
  if (pattern.size() > str.size()) {
    return false;
  }

  size_t i = 0, max = std::min(str.length(), pattern.length());
  bool it_matches = true;

  while (i < max) {
    if (pattern.at(i) != '?' && pattern.at(i) != str.at(i)) {
      it_matches = false;
      break;
    }

    ++i;
  }

  return it_matches;
}

bool is_hex_char(const char c) {
  return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'));
}

std::vector<uint8_t> string_to_hex(const std::string &hex) {
  const size_t len = hex.size();
  std::vector<uint8_t> bytes;
  if (len == 0) {
    return bytes;
  }

  for (size_t i = 0; i < len; i++) {
    uint8_t byte = 0;
    if (hex[i] == '\\') {
      if ((i + 3) >= len) {
        RAISE_EXCEPTION("Your hex values aren't formated correctly");
      }

      const bool hex_chars = is_hex_char(hex[i + 2]) && is_hex_char(hex[i + 3]);
      if (hex[i + 1] != 'x' || !hex_chars) {
        RAISE_EXCEPTION("Your hex values aren't formated correctly");
      }

      const char str_byte[3] = {hex[i + 2], hex[i + 3], 0};
      byte = uint8_t(strtoul(str_byte, nullptr, 16));
      i += 3;
    } else {
      byte = hex[i];
    }

    bytes.push_back(byte);
  }

  return bytes;
}

GadgetSet only_unique_gadgets(GadgetMultiset &list_gadgets) {
  GadgetSet unique_gadgets;
  // Now we have a list of gadget, cool, but we want to keep only the unique!
  for (size_t i = 0; i < list_gadgets.size(); i++) {
    auto node = list_gadgets.extract(list_gadgets.begin());
    const uint64_t first_offset = node.value().get_first_offset();
    const uint64_t first_va_section = node.value().get_first_va_section();
    auto [g, inserted] = unique_gadgets.insert(std::move(node.value()));
    if (inserted) {
      continue;
    }

    // we have found the same gadget in memory, so we just store its offset
    // & its va section maybe you can ask yourself 'Why do we store its va
    // section ?' and the answer is: because you can find the same gadget in
    // another executable sections!
    g->add_new_one(first_offset, first_va_section);
  }

  return unique_gadgets;
}

bool does_badbytes_filter_apply(const uint64_t va,
                                const std::vector<uint8_t> &badbytes) {
  const uint8_t f = (va >> 24) & 0xff;
  const uint8_t s = (va >> 16) & 0xff;
  const uint8_t t = (va >> 8) & 0xff;
  const uint8_t l = (va >> 0) & 0xff;

  for (const auto &badbyte : badbytes) {
    if ((f == badbyte) || (s == badbyte) || (t == badbyte) || (l == badbyte)) {
      return true;
    }
  }

  return false;
}

std::unique_ptr<ExecutableFormat>
get_executable_format(const uint32_t magic_dword) {
  if (uint16_t(magic_dword) == RP_IMAGE_DOS_SIGNATURE) {
    return std::make_unique<PE>();
  }

  switch (magic_dword) {
  case 0x464C457F: {
    return std::make_unique<Elf>();
  }

  // this is for x64
  case 0xFEEDFACF:
  // this one for x86
  case 0xFEEDFACE: {
    return std::make_unique<Macho>();
  }

  case 0xBEBAFECA: {
    RAISE_EXCEPTION("Hmm, actually I don't handle OSX Universal binaries. "
                    "You must extract them manually.");
    break;
  }

  default: {
    RAISE_EXCEPTION("Cannot determine the executable format used");
  }
  }
}
