#ifndef TOOLBOX_H
#define TOOLBOX_H

#include <string>
#include <fstream>
#include <map>
#include <string>
#include "gadget.hpp"

/* Choose your verbosity level */
enum VerbosityLevel
{
    VERBOSE_LEVEL_1 = 1,
    VERBOSE_LEVEL_2 = 2,
    VERBOSE_LEVEL_3 = 3
};

/**
 * \fn std::string verbosity_to_string(VerbosityLevel lvl)
 * \brief Convert a verbosity level in a string representation
 *
 * \param lvl: the verbosity level
 *
 * \return the string representation
 */
std::string verbosity_to_string(VerbosityLevel lvl);

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
 * \fn unsigned char * string_to_hex(const char* hex, unsigned int * size)
 * \brief Enable a color in your shell
 *
 * \param hex: The string that represents your raw hex values -- for example \x41BC\x90 => we want [0x41, 0x42, 0x43, 0x90] in memory
 * \param size: A pointer on a variable that will hold the number of bytes composing your buffer
 *
 * \return a pointer on a buffer that contains size bytes
 */
unsigned char * string_to_hex(const char* hex, unsigned int * size);

/**
 * \fn bool is_matching(std::string &disass, const char* p)
 * \brief Try to match a string with a pattern: in this pattern you can use the special character '?' that represents anything
 *
 * \param str: the string
 * \param p: the pattern you will apply to str
 *
 * \return true if the pattern matches with str, else false
 */
bool is_matching(std::string &str, const char* p);

/**
 * \fn bool is_hex_char(char c)
 * \brief Is the character c is an hexadecimal character ?
 *
 * \param c: the character
 *
 * \return true if the character is an hexadecimal char, else false
 */
bool is_hex_char(char c);


/**
 * \fn std::map<std::string, Gadget*> only_unique_gadgets(std::list<Gadget*> &list_gadgets)
 * \brief It keeps only the unique gadgets
 *
 * \param list_gadgets: It is the gadget list with duplicates
 *
 * \return The list of unique gadgets
 */
std::map<std::string, Gadget*> only_unique_gadgets(std::list<Gadget*> &list_gadgets);

#endif
