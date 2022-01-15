// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "gadget.hpp"
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

/* Choose your verbosity level */
enum VerbosityLevel {
  VERBOSE_LEVEL_1 = 1,
  VERBOSE_LEVEL_2 = 2,
  VERBOSE_LEVEL_3 = 3
};

/**
 * \fn std::string verbosity_to_string(const VerbosityLevel lvl)
 * \brief Convert a verbosity level in a string representation
 *
 * \param lvl: the verbosity level
 *
 * \return the string representation
 */
std::string verbosity_to_string(const VerbosityLevel lvl);

/**
 * \fn std::streampos get_file_size(std::ifstream &file)
 * \brief Get the size in byte of your file
 *
 * \param file: the file
 *
 * \return the size in byte of the file
 */
std::streampos get_file_size(std::ifstream &file);

/**
 * \fn std::vector<uint8_t> string_to_hex(const std::string &hex)
 * \brief Enable a color in your shell
 *
 * \param hex: The string that represents your raw hex values -- for example
 * \x41BC\x90 => we want [0x41, 0x42, 0x43, 0x90] in memory
 *
 * \return a vector that contains the converted bytes
 */
std::vector<uint8_t> string_to_hex(const std::string &hex);

/**
 * \fn bool is_matching(const std::string &disass, const char* p)
 * \brief Try to match a string with a pattern: in this pattern you can use the
 * special character '?' that represents anything
 *
 * \paraqm str: the string
 * \param p: the pattern you will apply to str
 *
 * \return true if the pattern matches with str, else false
 */
bool is_matching(const std::string &str, const std::string &p);

/**
 * \fn bool is_hex_char(const char c)
 * \brief Is the character c is an hexadecimal character ?
 *
 * \param c: the character
 *
 * \return true if the character is an hexadecimal char, else false
 */
bool is_hex_char(const char c);

/**
 * \fn GadgetOrderedSet only_unique_gadgets(GadgetSet &list_gadgets)
 * \brief It keeps only the unique gadgets
 *
 * \param list_gadgets: It is the gadget list with duplicates
 * \param unique_gadgets: The list of unique gadgets
 *
 */
GadgetSet only_unique_gadgets(GadgetMultiset &list_gadgets);

/**
 * \fn bool does_badbytes_filter_apply(const uint64_t va, const
 * std::vector<uint8_t> &badbytes)
 *
 * \brief Return true if va has a bad byte (taken from badbytes)
 *
 * \param va: It is the VA to check
 * \param badbytes: The list of bytes you don't want in va
 *
 * \return true if va has at least one bad byte, else false
 */
bool does_badbytes_filter_apply(const uint64_t va,
                                const std::vector<uint8_t> &badbytes);

/*!
 *  \brief Give you a PE/ELF instance (based mostly on the magic signature)
 *
 *  \param magic_dword: It is a dword that allows to deduce which
 * ExecutableFormat is used by the binary
 *
 *  \return A pointer on the correct ExecutableFormat deduced thanks to the
 * magic_dword argument
 */
class ExecutableFormat;
std::unique_ptr<ExecutableFormat>
get_executable_format(const uint32_t magic_dword);
