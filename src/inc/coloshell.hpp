/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef COLOSHELL_HPP
#define COLOSHELL_HPP

#include "platform.h"
#include "rpexception.hpp"
#include <iostream>
#include <iomanip>

#ifdef WINDOWS
#include <windows.h>
#include <fileapi.h>
#else
#include <unistd.h>
#endif

#define COLORS_ENABLED                     // remove this define if you don't want color in your shell

/* Here you will find all you need to display the data in a cute way on a windows/unix terminal */

#ifdef WINDOWS
    enum Colors
    {
        COLO_RED = FOREGROUND_RED | FOREGROUND_INTENSITY,
        COLO_GREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        COLO_YELLOW = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        COLO_DEFAULT = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED
    };
    
#else
    enum Colors
    {
        COLO_RED = 0,
        COLO_GREEN = 1,
        COLO_YELLOW = 2,
        COLO_DEFAULT = 3
    };

#endif

 /**
 * \def should_emit_color(void)
 * Return whether or not the caller should enable colorized output. For
 * example, if stdout is redirected to a file then the output won't be colored.
 */
#ifdef WINDOWS
#define should_emit_color() (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR)
#else
#define should_emit_color() (isatty(STDOUT_FILENO))
#endif

/**
 * \fn static void enable_color(const Colors colo)
 * \brief Enable a color in your shell
 *
 * \param colo: the color you want to activate
 */
static inline void enable_color(const Colors colo)
{
#ifdef COLORS_ENABLED
    if (!should_emit_color())
        return;

#ifdef WINDOWS
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if(hStdOutput == INVALID_HANDLE_VALUE)
        RAISE_EXCEPTION("Cannot find a STD_OUTPUT_HANDLE valid value");

    SetConsoleTextAttribute(
        hStdOutput,
        (unsigned short)colo
        );
#else
    const char *colors[] = {
        "\x1b[91m", "\x1b[92m",
        "\x1b[93m", "\x1b[0m"
    };
    std::cout << colors[colo];
#endif

#else
#endif
}

/**
 * \fn static void disable_color(const Colors colo)
 * \brief Unset the color you have previously set
 */
static inline void disable_color(void)
{
#ifdef COLORS_ENABLED
    if (!should_emit_color())
        return;

#ifdef WINDOWS
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if(hStdOutput == INVALID_HANDLE_VALUE)
        RAISE_EXCEPTION("Cannot find a STD_OUTPUT_HANDLE valid value");

    SetConsoleTextAttribute(
        hStdOutput,
        COLO_DEFAULT
        );
#else
    const char *colors[] = {
        "\x1b[91m", "\x1b[92m",
        "\x1b[93m", "\x1b[0m"
    };
    std::cout << colors[COLO_DEFAULT];
#endif
#else
#endif
}

/**
 * \fn static void coloshell(const T t, const Colors colo)
 * \brief Display "t" on the stdout with the color "colo"
 *
 * \param t: the thing you want to output
 * \param colo: the color you want to enable
 */
template<class T>
static void coloshell(const T t, const Colors colo)
{
    enable_color(colo);
    std::cout << t;
    disable_color();
}

/**
 * \def w_red(text)
 *  Display text in red on stdout
 *
 * \param text: the text you want to display
 */
#define w_red(text) {          \
    coloshell(text, COLO_RED); \
}

/**
 * \def w_yel(text)
 *  Display text in yellow on stdout
 *
 * \param text: the text you want to display
 */
#define w_yel(text) {              \
    coloshell(text, COLO_YELLOW);  \
}

/**
 * \def w_gre(text)
 *  Display text in green on stdout
 *
 * \param text: the text you want to display
 */
#define w_gre(text) {            \
    coloshell(text, COLO_GREEN); \
}

/**
 * \def w_red_lf(text)
 *  Display text in red on stdout with a line feed
 *
 * \param text: the text you want to display
 */
#define w_red_lf(text) {     \
    w_red(text);             \
    std::cout << std::endl;  \
}

/**
 * \def w_yel_lf(text)
 *  Display text in yellow on stdout with a line feed
 *
 * \param text: the text you want to display
 */
#define w_yel_lf(text) {     \
    w_yel(text);             \
    std::cout << std::endl;  \
}

/**
 * \def w_gre_lf(text)
 *  Display text in green on stdout with a line feed
 *
 * \param text: the text you want to display
 */
#define w_gre_lf(text) {     \
    w_gre_lf(text);          \
    std::cout << std::endl;  \
}

/**
 * \def display_hex_field(field, n)
 *  Display an hex value in red with 0 filling etc.
 *
 * \param field: It is the hex value you want to output
 * \param n: It is the size of the column
 */
#define display_hex_field(field, n) {                                                         \
    std::cout << std::setw(n) << std::left << std::setfill(' ') << " "#field << ": ";         \
    enable_color(COLO_RED);                                                                   \
    std::cout << "0x" << std::setw(sizeof(field) * 2) << std::right << std::setfill('0');     \
    std::cout << std::hex << field;                                                           \
    disable_color();                                                                          \
}

/**
 * \def display_hex_field_lf(field, n)
 *  Display an hex value in red with 0 filling, a line feed and 25b column.
 *
 * \param field: It is the hex value you want to output
 */
#define display_hex_field_lf(field) { \
    display_hex_field(field, 25);     \
    std::cout << std::endl;           \
}

/**
 * \def display_hex_2fields_lf(field1, field2)
 *  Display two hex values in red on a same line.
 *
 * \param field1: It is the first hex value you want to output
 * \param field2: It is the second hex value you want to output
 */
#define display_hex_2fields_lf(field1, field2) { \
    display_hex_field(field1, 25);               \
    display_hex_field(field2, 25);               \
    std::cout << std::endl;                      \
}

/**
 * \def display_short_hex_field(field)
 *  Display a short hex value in red.
 *
 * \param field: It is the short hex value you want to output
 */
#define display_short_hex_field(field) {    \
    display_hex_field(field, 14);           \
}

/**
 * \def display_short_hex_field_lf(field)
 *  Display a short hex value in red with a line feed.
 *
 * \param field: It is the short hex value you want to output
 */
#define display_short_hex_field_lf(field) { \
    display_short_hex_field(field);         \
    std::cout << std::endl;                 \
}

/**
 * \def display_short_hex_2fields_lf(field1, field2)
 *  Display two short hex values in red with a line feed.
 *
 * \param field1: It is the first short hex value you want to output
 * \param field2: It is the second short hex value you want to output
 */
#define display_short_hex_2fields_lf(field1, field2) { \
    display_short_hex_field(field1);                   \
    display_short_hex_field(field2);                   \
    std::cout << std::endl;                            \
}

/**
 * \def display_string(field_name, field)
 *  Display a field with its name.
 *
 * \param field_name: It is the field name
 * \param field: It is the field
 */
#define display_string(field_name, field) {                                      \
    std::cout << std::setw(15) << std::right << std::setfill(' ') << field_name; \
    std::cout << ": " << field;                                                  \
}

/**
 * \def display_string_lf(field_name, field)
 *  Display a field with its name and a line feed.
 *
 * \param field_name: It is the field name
 * \param field: It is the field
 */
#define display_string_lf(field_name, field) { \
    display_string(field_name, field);         \
    std::cout << std::endl;                    \
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
#define display_2strings_lf(field_name1, field1, field_name2, field2) { \
    display_string(field_name1, field1);                                \
    display_string(field_name2, field2);                                \
    std::cout << std::endl;                                             \
}

/**
 * \def display_gadget_lf(va, gadget)
 *  Display a gadget with a line feed and its VA.
 *
 * \param va: It is the gadget VA
 * \param gadget: It is the gadget you want to output
 */
#define display_gadget_lf(va, gadget) {                                                                             \
    enable_color(COLO_RED);                                                                                         \
    std::cout << "0x" << std::setw(sizeof(va)) << std::right << std::setfill('0');                                  \
    std::cout << std::hex << va;                                                                                    \
    disable_color();                                                                                                \
    std::cout << ": ";                                                                                              \
    enable_color(COLO_GREEN);                                                                                       \
    std::cout << (gadget)->get_disassembly() << " (" << std::dec << (gadget)->get_nb() << " found)" << std::endl;   \
    disable_color();                                                                                                \
}

/**
 * \def display_offset_lf(va, hex_val, size)
 *  Display an offset with a line feed and the hex values.
 *
 * \param va: It is the gadget VA
 * \param hex_val: It is the hex values
 * \param size: It is the size of the hex values
 */
#define display_offset_lf(va, hex_val, size) {                                                            \
    enable_color(COLO_RED);                                                                               \
    std::cout << "0x" << std::setw(sizeof(va)) << std::right << std::setfill('0');                        \
    std::cout << std::hex << va;                                                                          \
    disable_color();                                                                                      \
    std::cout << ": ";                                                                                    \
    enable_color(COLO_GREEN);                                                                             \
    for(unsigned int i = 0; i < size; ++i)                                                                \
    {                                                                                                     \
        if(isprint(hex_val[i]))                                                                           \
            std::cout << hex_val[i];                                                                      \
        else                                                                                              \
        {                                                                                                 \
            unsigned int b = hex_val[i];                                                                  \
            std::cout << "\\x" << std::setw(2) << std::right << std::setfill('0') << std::hex << b;       \
        }                                                                                                 \
    }                                                                                                     \
    std::cout << std::endl;                                                                               \
    disable_color();                                                                                      \
}

#endif
