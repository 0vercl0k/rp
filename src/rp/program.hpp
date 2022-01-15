// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include <fstream>
#include <set>
#include <string>

#include "elf.hpp"

/*! \class Program
 *
 *  A program is the combination between two things: a CPU which will be used by
 * the disassembler, and an ExecutableFormat in order to correctly extract the
 * code (to find cool stuff in)
 */
class Program {
public:
  /*!
   *  \brief Program instanciation requires a path where it can find your binary
   *
   *  \param program_path: The path of your binary
   */
  Program(const std::string &program_path,
          const CPU::E_CPU arch = CPU::CPU_UNKNOWN);

  /*!
   *  \brief Display information concerning the executable format (section
   * address, entry point, stuff like that)
   *
   *  \param lvl: Set the verbosity level you want
   */
  void display_information(const VerbosityLevel lvl = VERBOSE_LEVEL_1);

  /*!
   *  \brief Find all the rop gadgets
   *
   *  \param depth: Set the depth of the research (don't forget the ending
   * instruction doesn't count -- so if you want only ending instruction, depth
   * = 0)
   * \param gadgets: The gadgets found \param disass_engine_options:
   * Options you want to pass to the disassembly engine
   *
   */
  GadgetMultiset find_gadgets(const uint32_t depth,
                         const uint32_t disass_engine_options,
                         const size_t n_max_thread, const uint64_t base);

  /*!
   *  \brief Find hex values in the section of the program
   *
   * \param hex_values: It is a pointer on where it can find the bytes to find
   * in memory
   * \param size: It is the size of the buffer hex_values
   */
  void search_and_display(const uint8_t *hex_values, const size_t size,
                          const uint64_t base);

  /*!
   *  \brief Get the base address of the program
   *
   *  \return size: Base address of the program
   */
  uint64_t get_image_base_address() const;

private:
  std::unique_ptr<CPU> m_cpu; /*!< a pointer on the CPU used by your program*/

  std::unique_ptr<ExecutableFormat>
      m_exformat; /*!< a pointer on the ExecutableFormat used by your program*/

  std::ifstream m_file; /*!< the file descriptor*/
};
