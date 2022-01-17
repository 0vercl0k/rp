// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "platform.h"
#include "rpexception.hpp"
#include <fmt/printf.h>
#include <iomanip>

#ifdef WINDOWS
#include <windows.h>
#endif

static bool g_colors_desired = false;

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

inline bool g_are_colors_enabled() { return g_colors_desired; }

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
  const char *colors[] = {"\x1b[91m", "\x1b[92m", "\x1b[93m", "\x1b[0m"};
  fmt::print("{}", colors[colo]);
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
  fmt::print("{}", colors[COLO_DEFAULT]);
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
    fmt::print("{:{}}: ", #field, n);                                          \
    enable_color(COLO_RED);                                                    \
    fmt::print("0x{:0{}x} ", field, sizeof(field) * 2);                        \
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
 * \def display_gadget_lf(va, gadget)
 *  Display a gadget with a line feed and its VA.
 *
 * \param va: It is the gadget VA
 * \param gadget: It is the gadget you want to output
 */
#define display_gadget_lf(va, gadget)                                          \
  {                                                                            \
    if (!does_badbytes_filter_apply(va, badbyte_list)) {                       \
      enable_color(COLO_RED);                                                  \
      fmt::print("0x{:x}", va);                                                \
      disable_color();                                                         \
      fmt::print(": ");                                                        \
      enable_color(COLO_GREEN);                                                \
      (gadget).display_disassembly();                                          \
      (gadget).print_bytes();                                                  \
      fmt::print(" ({} found)\n", (gadget).get_nb());                          \
      disable_color();                                                         \
    } else {                                                                   \
      nb_gadgets_filtered++;                                                   \
    }                                                                          \
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
    fmt::print("0x{:x}", va);                                                  \
    disable_color();                                                           \
    fmt::print(": ");                                                          \
    enable_color(COLO_GREEN);                                                  \
    for (uint32_t i = 0; i < size; ++i) {                                      \
      if (isprint(hex_val[i])) {                                               \
        fmt::print("{}", hex_val[i]);                                          \
      } else {                                                                 \
        fmt::print("\\x{:02x}", hex_val[i]);                                   \
      }                                                                        \
    }                                                                          \
    fmt::print("\n");                                                          \
    disable_color();                                                           \
  }
