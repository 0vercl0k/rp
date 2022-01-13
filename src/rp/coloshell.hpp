// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "platform.h"
#include "rpexception.hpp"
#include <fmt/printf.h>
#include <iomanip>
#include <iostream>

#ifdef WINDOWS
#include <fileapi.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

extern bool g_colors_desired;

// Here you will find all you need to display the data in a cute way on a
// windows/unix terminal

#ifdef WINDOWS
enum Colors {
  COLO_RED = FOREGROUND_RED | FOREGROUND_INTENSITY,
  COLO_GREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
  COLO_YELLOW = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
  COLO_DEFAULT = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED
};

#else
enum Colors { COLO_RED = 0, COLO_GREEN = 1, COLO_YELLOW = 2, COLO_DEFAULT = 3 };

#endif

/**
 * \def should_emit_color(void)
 * Return whether or not the caller should enable colorized output. For
 * example, if stdout is redirected to a file then the output won't be colored.
 */
#ifdef WINDOWS
inline bool should_emit_color() {
  return GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR;
}
#else
inline bool should_emit_color() { return isatty(STDOUT_FILENO); }
#endif

inline bool g_are_colors_enabled() {
  return g_colors_desired && should_emit_color();
}

/**
 * \fn static void enable_color_(const Colors colo)
 * \brief Enable a color in your shell
 *
 * \param colo: the color you want to activate
 */
static inline void enable_color_(const Colors colo) {
#ifdef WINDOWS
  HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hStdOutput == INVALID_HANDLE_VALUE) {
    RAISE_EXCEPTION("Cannot find a STD_OUTPUT_HANDLE valid value");
  }

  SetConsoleTextAttribute(hStdOutput, uint16_t(colo));
#else
  const char *colors[]{"\x1b[91m", "\x1b[92m", "\x1b[93m", "\x1b[0m"};
  std::cout << colors[colo];
#endif
}

/**
 * \fn static void enable_color(const Colors colo)
 * \brief Enable a color in your shell
 *
 * \param colo: the color you want to activate
 */
static inline void enable_color(const Colors colo) {
  if (!g_are_colors_enabled()) {
    return;
  }

  enable_color_(colo);
}

/**
 * \fn static void disable_color_(const Colors colo)
 * \brief Unset the color you have previously set
 */
static void disable_color_() {
#ifdef WINDOWS
  HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hStdOutput == INVALID_HANDLE_VALUE) {
    RAISE_EXCEPTION("Cannot find a STD_OUTPUT_HANDLE valid value");
  }

  SetConsoleTextAttribute(hStdOutput, COLO_DEFAULT);
#else
  const char *colors[]{"\x1b[91m", "\x1b[92m", "\x1b[93m", "\x1b[0m"};
  std::cout << colors[COLO_DEFAULT];
#endif
}

/**
 * \fn static void disable_color_(const Colors colo)
 * \brief Unset the color you have previously set
 */
static inline void disable_color() {
  if (!g_are_colors_enabled()) {
    return;
  }

  disable_color_();
}

/**
 * \fn static void coloshell(const T t, const Colors colo)
 * \brief Display "t" on the stdout with the color "colo"
 *
 * \param t: the thing you want to output
 * \param colo: the color you want to enable
 */
template <class T> static void coloshell(const T t, const Colors colo) {
  enable_color(colo);
  fmt::print("{}", t);
  disable_color();
}

/**
 * \def w_red(text)
 *  Display text in red on stdout
 *
 * \param text: the text you want to display
 */
#define w_red(text)                                                            \
  { coloshell(text, COLO_RED); }

/**
 * \def w_yel(text)
 *  Display text in yellow on stdout
 *
 * \param text: the text you want to display
 */
#define w_yel(text)                                                            \
  { coloshell(text, COLO_YELLOW); }

/**
 * \def w_gre(text)
 *  Display text in green on stdout
 *
 * \param text: the text you want to display
 */
#define w_gre(text)                                                            \
  { coloshell(text, COLO_GREEN); }

/**
 * \def w_red_lf(text)
 *  Display text in red on stdout with a line feed
 *
 * \param text: the text you want to display
 */
#define w_red_lf(text)                                                         \
  {                                                                            \
    w_red(text);                                                               \
    fmt::print("\n");                                                          \
  }

/**
 * \def w_yel_lf(text)
 *  Display text in yellow on stdout with a line feed
 *
 * \param text: the text you want to display
 */
#define w_yel_lf(text)                                                         \
  {                                                                            \
    w_yel(text);                                                               \
    fmt::print("\n");                                                          \
  }

/**
 * \def w_gre_lf(text)
 *  Display text in green on stdout with a line feed
 *
 * \param text: the text you want to display
 */
#define w_gre_lf(text)                                                         \
  {                                                                            \
    w_gre_lf(text);                                                            \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_hex_field(field, n)
 *  Display an hex value in red with 0 filling etc.
 *
 * \param field: It is the hex value you want to output
 * \param n: It is the size of the column
 */
#define display_hex_field(field, n)                                            \
  {                                                                            \
    std::cout << std::setw(n) << std::left << std::setfill(' ') << " " #field  \
              << ": ";                                                         \
    enable_color(COLO_RED);                                                    \
    std::cout << "0x" << std::setw(sizeof(field) * 2) << std::right            \
              << std::setfill('0');                                            \
    std::cout << std::hex << field;                                            \
    disable_color();                                                           \
  }

/**
 * \def display_hex_field_lf(field, n)
 *  Display an hex value in red with 0 filling, a line feed and 25b column.
 *
 * \param field: It is the hex value you want to output
 */
#define display_hex_field_lf(field)                                            \
  {                                                                            \
    display_hex_field(field, 25);                                              \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_hex_2fields_lf(field1, field2)
 *  Display two hex values in red on a same line.
 *
 * \param field1: It is the first hex value you want to output
 * \param field2: It is the second hex value you want to output
 */
#define display_hex_2fields_lf(field1, field2)                                 \
  {                                                                            \
    display_hex_field(field1, 25);                                             \
    display_hex_field(field2, 25);                                             \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_short_hex_field(field)
 *  Display a short hex value in red.
 *
 * \param field: It is the short hex value you want to output
 */
#define display_short_hex_field(field)                                         \
  { display_hex_field(field, 14); }

/**
 * \def display_short_hex_field_lf(field)
 *  Display a short hex value in red with a line feed.
 *
 * \param field: It is the short hex value you want to output
 */
#define display_short_hex_field_lf(field)                                      \
  {                                                                            \
    display_short_hex_field(field);                                            \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_short_hex_2fields_lf(field1, field2)
 *  Display two short hex values in red with a line feed.
 *
 * \param field1: It is the first short hex value you want to output
 * \param field2: It is the second short hex value you want to output
 */
#define display_short_hex_2fields_lf(field1, field2)                           \
  {                                                                            \
    display_short_hex_field(field1);                                           \
    display_short_hex_field(field2);                                           \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_string(field_name, field)
 *  Display a field with its name.
 *
 * \param field_name: It is the field name
 * \param field: It is the field
 */
#define display_string(field_name, field)                                      \
  {                                                                            \
    std::cout << std::setw(15) << std::right << std::setfill(' ')              \
              << field_name;                                                   \
    std::cout << ": " << field;                                                \
  }

/**
 * \def display_string_lf(field_name, field)
 *  Display a field with its name and a line feed.
 *
 * \param field_name: It is the field name
 * \param field: It is the field
 */
#define display_string_lf(field_name, field)                                   \
  {                                                                            \
    display_string(field_name, field);                                         \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_2strings_lf(field_name1, field1, field_name2, field2)
 *  Display two fields with their names and a line feed.
 *
 * \param field_name1: It is the first field name
 * \param field1: It is the first field
 * \param field_name2: It is the second field name
 * \param field2: It is the second field
 */
#define display_2strings_lf(field_name1, field1, field_name2, field2)          \
  {                                                                            \
    display_string(field_name1, field1);                                       \
    display_string(field_name2, field2);                                       \
    fmt::print("\n");                                                          \
  }

/**
 * \def display_gadget_lf(va, gadget)
 *  Display a gadget with a line feed and its VA.
 *
 * \param va: It is the gadget VA
 * \param gadget: It is the gadget you want to output
 */
#define display_gadget_lf(va, gadget)                                          \
  {                                                                            \
    if (does_badbytes_filter_apply(va, badbyte_list) == false) {               \
      enable_color(COLO_RED);                                                  \
      std::cout << "0x" << std::setw(sizeof(va)) << std::right                 \
                << std::setfill('0');                                          \
      std::cout << std::hex << ((va - base) + new_base);                       \
      disable_color();                                                         \
      fmt::print(": ");                                                        \
      enable_color(COLO_GREEN);                                                \
      (gadget)->display_disassembly();                                         \
      fmt::print(" ");                                                         \
      (gadget)->print_bytes();                                                 \
      fmt::print(" ({} found)\n", (gadget)->get_nb());                         \
      disable_color();                                                         \
    } else                                                                     \
      nb_gadgets_filtered++;                                                   \
  }

/**
 * \def display_offset_lf(va, hex_val, size)
 *  Display an offset with a line feed and the hex values.
 *
 * \param va: It is the gadget VA
 * \param hex_val: It is the hex values
 * \param size: It is the size of the hex values
 */
#define display_offset_lf(va, hex_val, size)                                   \
  {                                                                            \
    enable_color(COLO_RED);                                                    \
    std::cout << "0x" << std::setw(sizeof(va)) << std::right                   \
              << std::setfill('0');                                            \
    std::cout << std::hex << va;                                               \
    disable_color();                                                           \
    fmt::print(": ");                                                          \
    enable_color(COLO_GREEN);                                                  \
    for (uint32_t i = 0; i < size; ++i) {                                      \
      if (isprint(hex_val[i]))                                                 \
        std::cout << hex_val[i];                                               \
      else {                                                                   \
        uint32_t b = hex_val[i];                                               \
        std::cout << "\\x" << std::setw(2) << std::right << std::setfill('0')  \
                  << std::hex << b;                                            \
      }                                                                        \
    }                                                                          \
    fmt::print("\n");                                                          \
    disable_color();                                                           \
  }
