// Axel '0vercl0k' Souchet - January 12 2022
#include "coloshell.hpp"
#include "platform.h"
#include "program.hpp"
#include <CLI11.hpp>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fmt/printf.h>
#include <iostream>

#define NUM_V "2.0"
#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#endif

#define VERSION_TM VERSION_TMP " for " SYSTEM_PLATFORM

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

int main(int argc, char *argv[]) {
  struct {
    std::string file;
    uint8_t display = 0;
    uint32_t rop = 0;
    std::string raw;
    bool unique;
    std::string shexa;
    uint32_t maxth = 0;
    std::string badbytes;
    std::string sint;
    bool version = false;
    bool thumb = false;
    uint64_t va = 0;
  } opts;

  CLI::App rp("rp++: a fast ROP gadget finder by Axel '0vercl0k' Souchet.\n");
  rp.add_option("--file", opts.file, "<binary path>")
      ->description("Binary path")
      ->required();
  rp.add_option("--info", opts.display, "<1, 2, 3>")
      ->description("display information about the binary header");
  rp.add_option("--rop", opts.rop, "<positive int>")
      ->description("find useful gadget for your future exploits, arg is the "
                    "gadget maximum size in instructions");
  rp.add_option("--raw", opts.raw, "<archi>")
      ->description("find gadgets in a raw file, 'archi' must be in the "
                    "following list: x86, x64, arm");
  rp.add_flag("--unique", opts.unique, "display only unique gadget");
  rp.add_option("--search-hexa", opts.shexa, "<\\x90A\\x90>")
      ->description("try to find hex values");
  rp.add_option("--max-thread", opts.maxth, "<int>")
      ->description("set the maximum number of threads that can be used")
      ->default_val(2);
  rp.add_option("--bad-bytes", opts.badbytes, "<\\x90A\\x90>")
      ->description(
          "the bytes you don't want to see in the gadgets' addresses");
  rp.add_option("--search-int", opts.sint, "<int in hex>")
      ->description("try to find a pointer on a specific integer value");
  rp.add_flag("--version", opts.version, "print version information");
  rp.add_flag("--colors", g_colors_desired, "enable colors")
      ->default_val(false);
  rp.add_flag("--thumb", opts.thumb,
              "enable thumb mode when looking for ARM gadgets");
  rp.add_flag("--va", opts.va, "<0xdeadbeef>")
      ->description(
          "don't use the image base of the binary, but yours instead");

  CLI11_PARSE(rp, argc, argv);

  try {
    if (opts.version) {
      fmt::print("You are currently using the version {} of rp++.\n", VERSION);
    }

    CPU::E_CPU arch(CPU::CPU_UNKNOWN);

    if (opts.raw.size() > 0) {
      if (opts.raw == "x86") {
        arch = CPU::CPU_x86;
      } else if (opts.raw == "x64") {
        arch = CPU::CPU_x64;
      } else if (opts.raw == "arm") {
        arch = CPU::CPU_ARM;
      } else {
        RAISE_EXCEPTION(
            "You must use an architecture supported, read the help");
      }
    }

    Program p(opts.file, arch);

    if (opts.display >= VERBOSE_LEVEL_1 && opts.display <= VERBOSE_LEVEL_3) {
      p.display_information(VerbosityLevel(opts.display));
    }

    if (opts.rop > 0) {
      const uint32_t options = opts.thumb ? 1 : 0;
      fmt::print("\nWait a few seconds, rp++ is looking for gadgets ({} "
                 "threads max)..\n");
      std::multiset<std::shared_ptr<Gadget>> all_gadgets;
      p.find_gadgets(opts.rop, all_gadgets, options, opts.maxth);

      // Here we set the base beeing 0 if we want to have absolute virtual
      // memory address displayed
      uint64_t base = 0;
      uint64_t new_base = 0;
      if (opts.va > 0) {
        // If not we will substract the base address to every gadget to keep
        // only offsets
        base = p.get_image_base_address();
        // And we will use your new base address
        new_base = opts.va;
      }

      fmt::print("A total of {} gadgets found.\n", all_gadgets.size());
      std::vector<uint8_t> badbyte_list;
      if (opts.badbytes.size() > 0) {
        badbyte_list = string_to_hex(opts.badbytes);
      }

      uint64_t nb_gadgets_filtered = 0;
      if (opts.unique) {
        auto unique_gadgets = only_unique_gadgets(all_gadgets);

        fmt::print("You decided to keep only the unique ones, {}  unique "
                   "gadgets found.\n",
                   unique_gadgets.size());

        // Now we walk the gadgets found and set the VA
        for (const auto &unique_gadget : unique_gadgets) {
          display_gadget_lf(unique_gadget->get_first_absolute_address(),
                            unique_gadget);
        }
      } else {
        for (const auto &gadget : all_gadgets) {
          display_gadget_lf(gadget->get_first_absolute_address(), gadget);
        }
      }

      if (opts.badbytes.size() > 0) {
        fmt::print(
            "\n{} gadgets have been filtered because of your bad-bytes.\n");
      }
    }

    if (opts.shexa.size() > 0) {
      const std::vector<uint8_t> &hex_values = string_to_hex(opts.shexa);
      p.search_and_display(hex_values.data(), hex_values.size());
    }

    if (opts.sint.size() > 0) {
      const uint32_t val = std::strtoul(opts.sint.c_str(), nullptr, 16);
      p.search_and_display((const uint8_t *)&val, sizeof(val));
    }
  } catch (const std::exception &e) {
    enable_color(COLO_RED);
    fmt::print("{}\n", e.what());
    disable_color();
  }

  return 0;
}
