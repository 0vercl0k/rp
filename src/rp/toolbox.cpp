// Axel '0vercl0k' Souchet - January 12 2022
#include "toolbox.hpp"
#include "rpexception.hpp"
#include <cstdlib>
#include <cstring>
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

std::vector<uint8_t> string_to_hex(const char *hex) {
  uint32_t len = uint32_t(std::strlen(hex)), i = 0;
  std::vector<uint8_t> bytes;

  if (len == 0) {
    return bytes;
  }

  while (i < len) {
    uint8_t byte = 0;
    if (hex[i] == '\\' && hex[i + 1] == 'x') {
      if (is_hex_char(hex[i + 2]) && is_hex_char(hex[i + 3])) {
        const char str_byte[3] = {hex[i + 2], hex[i + 3], 0};
        byte = uint8_t(strtoul(str_byte, nullptr, 16));
        i += 4;
      } else {
        RAISE_EXCEPTION("Your hex values aren't formated correctly");
      }
    } else {
      byte = hex[i];
      i++;
    }

    bytes.push_back(byte);
  }

  return bytes;
}

void only_unique_gadgets(
    const std::multiset<std::shared_ptr<Gadget>> &list_gadgets,
    std::set<std::shared_ptr<Gadget>, Gadget::Sort> &unique_gadgets) {
  // Now we have a list of gadget, cool, but we want to keep only the unique!
  for (const auto &gadget : list_gadgets) {
    auto g = unique_gadgets.insert(gadget);
    // If a gadget, with the same disassembly, has already been found; just its
    // offset in the existing one
    if (g.second == false) {
      // we have found the same gadget in memory, so we just store its offset &
      // its va section maybe you can ask yourself 'Why do we store its va
      // section ?' and the answer is: because you can find the same gadget in
      // another executable sections!
      (*g.first)->add_new_one(gadget->get_first_offset(),
                              gadget->get_first_va_section());
    }
  }
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