// Axel '0vercl0k' Souchet - January 12 2022
#include "coloshell.hpp"
#include "options.hpp"
#include "platform.h"
#include "program.hpp"
#include <CLI11.hpp>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fmt/printf.h>
#include <unordered_map>

#define NUM_V "2.0"
#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#elif defined ARCH_X86
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " arm64 built the " __DATE__ " " __TIME__
#endif

#define VERSION_TM VERSION_TMP " for " SYSTEM_PLATFORM

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

Options_t g_opts;

int main(int argc, char *argv[]) {
  CLI::App rp("rp++: a fast ROP gadget finder for pe/elf/mach-o x86/x64/ARM "
              "binaries\nby Axel '0vercl0k' Souchet.\n");
  rp.add_option("-f,--file", g_opts.file, "Binary path")->required();
  rp.add_option("-i,--info", g_opts.display,
                "display information about the binary header");
  rp.add_option("-r,--rop", g_opts.rop,
                "find useful gadget for your future exploits, arg is the "
                "gadget maximum size in instructions");
  const std::unordered_map<std::string, CPU::E_CPU> raw_archi_map = {
      {"x86", CPU::CPU_x86},
      {"x64", CPU::CPU_x64},
      {"arm", CPU::CPU_ARM},
      {"arm64", CPU::CPU_ARM64}};
  rp.add_option("--raw", g_opts.raw, "find gadgets in a raw file")
      ->transform(CLI::CheckedTransformer(raw_archi_map, CLI::ignore_case));
  rp.add_flag("--unique", g_opts.unique, "display only unique gadget");
  rp.add_option("--search-hexa", g_opts.shexa, "try to find hex values");
  rp.add_option("--max-thread", g_opts.maxth,
                "set the maximum number of threads that can be used");
  rp.add_option("--bad-bytes", g_opts.badbytes,
                "the bytes you don't want to see in the gadgets' addresses");
  rp.add_option("--search-int", g_opts.sint,
                "try to find a pointer on a specific integer value");
  rp.add_flag("-v,--version", g_opts.version, "print version information");
  rp.add_flag("--colors", g_colors_desired, "enable colors");
  rp.add_flag("--thumb", g_opts.thumb,
              "enable thumb mode when looking for ARM gadgets");
  rp.add_flag("--va", g_opts.va,
              "don't use the image base of the binary, but yours instead");
  rp.add_flag("--allow-branches", g_opts.allow_branches,
              "allow branches in a gadget");
  rp.add_flag("--print-bytes", g_opts.print_bytes, "print the gadget bytes");

  CLI11_PARSE(rp, argc, argv);

  try {
    if (g_opts.version) {
      fmt::print("You are currently using the version {} of rp++.\n", VERSION);
    }

    Program p(g_opts.file, g_opts.raw);
    if (g_opts.display >= VERBOSE_LEVEL_1 &&
        g_opts.display <= VERBOSE_LEVEL_3) {
      p.display_information(VerbosityLevel(g_opts.display));
    }

    // Here we set the base being 0 if we want to have absolute virtual
    // memory address displayed
    const uint64_t base = g_opts.va.size() > 0
                              ? std::strtoull(g_opts.va.c_str(), nullptr, 0)
                              : p.get_image_base_address();
    if (g_opts.rop > 0) {
      const uint32_t options = g_opts.thumb ? 1 : 0;
      fmt::print("\nWait a few seconds, rp++ is looking for gadgets ({} "
                 "threads max)..\n",
                 g_opts.maxth);

      GadgetMultiset all_gadgets =
          p.find_gadgets(g_opts.rop, options, g_opts.maxth, base);

      fmt::print("A total of {} gadgets found.\n", all_gadgets.size());
      std::vector<uint8_t> badbyte_list;
      if (g_opts.badbytes.size() > 0) {
        badbyte_list = string_to_hex(g_opts.badbytes);
      }

      uint64_t nb_gadgets_filtered = 0;
      if (g_opts.unique) {
        auto unique_gadgets = only_unique_gadgets(all_gadgets);

        fmt::print("You decided to keep only the unique ones, {} unique "
                   "gadgets found.\n",
                   unique_gadgets.size());

        // Now we walk the gadgets found and set the VA
        for (const auto &unique_gadget : unique_gadgets) {
          display_gadget_lf(unique_gadget.get_first_absolute_address(),
                            unique_gadget);
        }
      } else {
        for (const auto &gadget : all_gadgets) {
          display_gadget_lf(gadget.get_first_absolute_address(), gadget);
        }
      }

      if (g_opts.badbytes.size() > 0) {
        fmt::print(
            "\n{} gadgets have been filtered because of your bad-bytes.\n",
            nb_gadgets_filtered);
      }
    }

    if (g_opts.shexa.size() > 0) {
      const std::vector<uint8_t> &hex_values = string_to_hex(g_opts.shexa);
      p.search_and_display(hex_values.data(), hex_values.size(), base);
    }

    if (g_opts.sint.size() > 0) {
      const uint32_t val = std::strtoul(g_opts.sint.c_str(), nullptr, 16);
      p.search_and_display((const uint8_t *)&val, sizeof(val), base);
    }
  } catch (const std::exception &e) {
    enable_color(COLO_RED);
    fmt::print("{}\n", e.what());
    disable_color();
  }

  return 0;
}
