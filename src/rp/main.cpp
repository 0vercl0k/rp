// Axel '0vercl0k' Souchet - January 12 2022
#include "main.hpp"
#include "argtable3.h"
#include "coloshell.hpp"
#include "program.hpp"
#include "toolbox.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>

int main(int argc, char *argv[]) {
  struct arg_file *file =
      arg_file0("f", "file", "<binary path>", "give binary path");
  struct arg_int *display = arg_int0(
      "i", "info", "<1,2,3>", "display information about the binary header");
  struct arg_int *rop =
      arg_int0("r", "rop", "<positive int>",
               "find useful gadget for your future exploits, arg is the gadget "
               "maximum size in instructions");
  struct arg_str *raw = arg_str0(nullptr, "raw", "<archi>",
                                 "find gadgets in a raw file, 'archi' must be "
                                 "in the following list: x86, x64, arm");
  struct arg_lit *unique =
      arg_lit0(nullptr, "unique", "display only unique gadget");
  struct arg_str *shexa = arg_str0(nullptr, "search-hexa", "<\\x90A\\x90>",
                                   "try to find hex values");
  struct arg_str *maxth = arg_str0(
      nullptr, "max-thread", "<int>",
      "set the maximum number of threads that can be used (default: 2)");
  struct arg_str *badbytes =
      arg_str0(nullptr, "bad-bytes", "<\\x90A\\x90>",
               "the bytes you don't want to see in the gadgets' addresses");
  struct arg_str *sint =
      arg_str0(nullptr, "search-int", "<int in hex>",
               "try to find a pointer on a specific integer value");
  struct arg_lit *help = arg_lit0("h", "help", "print this help and exit");
  struct arg_lit *version =
      arg_lit0("v", "version", "print version information and exit");
  struct arg_lit *colors = arg_lit0(nullptr, "colors", "enable colors");
  struct arg_lit *thumb = arg_lit0(
      nullptr, "thumb", "enable thumb mode when looking for ARM gadgets");
  struct arg_str *va =
      arg_str0(nullptr, "va", "<0xdeadbeef>",
               "don't use the image base of the binary, but yours instead");
  struct arg_end *end = arg_end(20);
  void *argtable[]{file,    display, rop, raw,      unique, shexa, sint, help,
                   version, colors,  va,  badbytes, thumb,  maxth, end};

  if (arg_nullcheck(argtable) != 0)
    RAISE_EXCEPTION("Cannot allocate long option structures");

  int nerrors = arg_parse(argc, argv, argtable);
  if (nerrors > 0) {
    arg_print_errors(stdout, end, "rp++");
    std::cout << "Try './rp++ --help' for more information." << std::endl;
    return -1;
  }

  if (colors->count > 0)
    g_colors_desired = true;

  try {
    if (help->count > 0 || argc == 1) {
      w_yel_lf("DESCRIPTION:");
      w_red("rp++");
      std::cout << " allows you to find ROP gadgets in pe/elf/mach-o "
                   "x86/x64/ARM binaries."
                << std::endl;
      std::cout << "NB: The original idea comes from (@jonathansalwan) and his "
                   "'ROPGadget' tool."
                << std::endl
                << std::endl;

      w_yel_lf("USAGE:");
      std::cout << "./rp++";
      arg_print_syntax(stdout, argtable, "\n");

      std::cout << std::endl;
      w_yel_lf("OPTIONS:");
      arg_print_glossary(stdout, argtable, "  %-25s %s\n");
    }

    if (version->count > 0)
      std::cout << "You are currently using the version " << VERSION
                << " of rp++." << std::endl;

    /* If we've asked the help or version option, we assume the program is
     * terminated */
    if (version->count > 0 || help->count > 0)
      return 0;

    if (file->count > 0) {
      std::string program_path(file->filename[0]);
      CPU::E_CPU arch(CPU::CPU_UNKNOWN);

      if (raw->count > 0) {
        const char *architecture = raw->sval[0];

        if (std::strcmp(architecture, "x86") == 0)
          arch = CPU::CPU_x86;
        else if (std::strcmp(architecture, "x64") == 0)
          arch = CPU::CPU_x64;
        else if (std::strcmp(architecture, "arm") == 0)
          arch = CPU::CPU_ARM;
        else
          RAISE_EXCEPTION(
              "You must use an architecture supported, read the help");
      }

      Program p(program_path, arch);

      if (display->count > 0) {
        if (display->ival[0] < VERBOSE_LEVEL_1 ||
            display->ival[0] > VERBOSE_LEVEL_3)
          display->ival[0] = VERBOSE_LEVEL_1;

        p.display_information((VerbosityLevel)display->ival[0]);
      }

      if (rop->count > 0) {
        if (rop->ival[0] < 0)
          rop->ival[0] = 0;

        if (rop->ival[0] > MAXIMUM_INSTRUCTION_PER_GADGET)
          RAISE_EXCEPTION("You specified a maximum number of instruction too "
                          "important for the --rop option");

        uint32_t options = 0;
        if (thumb->count > 0)
          options = 1;

        size_t n_max_thread = 2;
        if (maxth->count > 0)
          n_max_thread = atoi(maxth->sval[0]);

        if (n_max_thread == 0)
          n_max_thread = 2;

        std::cout << std::endl
                  << "Wait a few seconds, rp++ is looking for gadgets ("
                  << n_max_thread << " threads max).." << std::endl;
        std::multiset<std::shared_ptr<Gadget>> all_gadgets;
        p.find_gadgets(rop->ival[0], all_gadgets, options, n_max_thread);

        // Here we set the base beeing 0 if we want to have absolute virtual
        // memory address displayed
        uint64_t base = 0;
        uint64_t new_base = 0;
        if (va->count > 0) {
          // If not we will substract the base address to every gadget to keep
          // only offsets
          base = p.get_image_base_address();
          // And we will use your new base address
          new_base = strtoul(va->sval[0], nullptr,
                             16); // XXX: Only valid with VS2k13
                                  // strtoull(rva->sval[0], NULL, 16);
        }

        std::cout << "A total of " << all_gadgets.size() << " gadgets found."
                  << std::endl;
        std::vector<uint8_t> badbyte_list;
        if (badbytes->count > 0)
          badbyte_list = string_to_hex(badbytes->sval[0]);

        uint64_t nb_gadgets_filtered = 0;
        if (unique->count > 0) {
          std::set<std::shared_ptr<Gadget>, Gadget::Sort> unique_gadgets;
          only_unique_gadgets(all_gadgets, unique_gadgets);

          std::cout << "You decided to keep only the unique ones, "
                    << unique_gadgets.size() << " unique gadgets found."
                    << std::endl;

          /* Now we walk the gadgets found and set the VA */
          for (const auto &unique_gadget : unique_gadgets)
            display_gadget_lf(unique_gadget->get_first_absolute_address(),
                              unique_gadget);
        } else {
          for (const auto &gadget : all_gadgets)
            display_gadget_lf(gadget->get_first_absolute_address(), gadget);
        }

        if (badbytes->count > 0)
          std::cout << std::endl
                    << nb_gadgets_filtered
                    << " gadgets have been filtered because of your bad-bytes."
                    << std::endl;
      }

      if (shexa->count > 0) {
        std::vector<uint8_t> hex_values = string_to_hex(shexa->sval[0]);
        p.search_and_display(hex_values.data(), (uint32_t)hex_values.size());
      }

      if (sint->count > 0) {
        uint32_t val = std::strtoul(sint->sval[0], nullptr, 16);
        p.search_and_display((const uint8_t *)&val, sizeof(uint32_t));
      }
    }
  } catch (const std::exception &e) {
    enable_color(COLO_RED);
    std::cout << e.what() << std::endl;
    disable_color();
  }

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
  return 0;
}