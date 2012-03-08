#ifndef COLOSHELL_HPP
#define COLOSHELL_HPP

#include "platform.h"
#include <iostream>

#ifdef WINDOWS
#include <windows.h>
#endif

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


static void enable_color(const Colors colo)
{
#ifdef WINDOWS
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if(hStdOutput == INVALID_HANDLE_VALUE)
        throw std::string("Cannot find a STD_OUTPUT_HANDLE valid value");

    SetConsoleTextAttribute(
        hStdOutput,
        colo
        );
#else
    const char *colors[] = {
        "\x1b[91m", "\x1b[92m",
        "\x1b[93m", "\x1b[0m"
    };
    std::cout << colors[colo];
#endif
}

static void disable_color(void)
{
#ifdef WINDOWS
    HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if(hStdOutput == INVALID_HANDLE_VALUE)
        throw std::string("Cannot find a STD_OUTPUT_HANDLE valid value");

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
}

template<class T>
static void coloshell(const T t, const Colors colo)
{
    enable_color(colo);
    std::cout << t;
    disable_color();
}

#define w_red(text) {          \
    coloshell(text, COLO_RED); \
}

#define w_yel(text) {              \
    coloshell(text, COLO_YELLOW);  \
}

#define w_gre(text) {            \
    coloshell(text, COLO_GREEN); \
}


#define w_red_lf(text) {     \
    w_red(text);             \
    std::cout << std::endl;  \
}

#define w_yel_lf(text) {     \
    w_yel(text);             \
    std::cout << std::endl;  \
}

#define w_gre_lf(text) {     \
    w_gre_lf(text);          \
    std::cout << std::endl;  \
}

/* Utility for displaying easily the structure fields */
#define display_hex_field(field, n) {                                                         \
    std::cout << std::setw(n) << std::left << std::setfill(' ') << " "#field << ": ";         \
    enable_color(COLO_RED);                                                                   \
    std::cout << "0x" << std::setw(sizeof(field) * 2) << std::right << std::setfill('0');     \
    std::cout << std::hex << field;                                                           \
    disable_color();                                                                          \
}

#define display_hex_field_lf(field) { \
    display_hex_field(field, 25);     \
    std::cout << std::endl;           \
}

#define display_hex_2fields_lf(field1, field2) { \
    display_hex_field(field1, 25);               \
    display_hex_field(field2, 25);               \
    std::cout << std::endl;                      \
}

#define display_short_hex_field(field) {    \
    display_hex_field(field, 14);           \
}

#define display_short_hex_field_lf(field) { \
    display_short_hex_field(field);         \
    std::cout << std::endl;                 \
}

#define display_short_hex_2fields_lf(field1, field2) { \
    display_short_hex_field(field1);                   \
    display_short_hex_field(field2);                   \
    std::cout << std::endl;                            \
}

#define display_string(field_name, field) {                                      \
    std::cout << std::setw(15) << std::right << std::setfill(' ') << field_name; \
    std::cout << ": " << field;                                                  \
}

#define display_string_lf(field_name, field) { \
    display_string(field_name, field);         \
    std::cout << std::endl;                    \
}

#define display_2strings_lf(field_name1, field1, field_name2, field2) { \
    display_string(field_name1, field1);                                \
    display_string(field_name2, field2);                                \
    std::cout << std::endl;                                             \
}

#define display_gadget_lf(va, gadget) {                                                                       \
    enable_color(COLO_RED);                                                                                   \
    std::cout << "0x" << std::setw(sizeof(va)) << std::right << std::setfill('0');                            \
    std::cout << std::hex << va;                                                                              \
    disable_color();                                                                                          \
    std::cout << ": ";                                                                                        \
    enable_color(COLO_GREEN);                                                                                 \
    std::cout << (gadget)->first << " (" << std::dec << (gadget)->second->get_nb() << " one)" << std::endl;   \
    disable_color();                                                                                          \
}

#endif