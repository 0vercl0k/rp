// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"
#include "rpexception.hpp"
#include "section.hpp"
#include <fmt/printf.h>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

/*! \class ExecutableFormat
 *
 *  An ExecutableFormat is the second part composing a Program instance ; it is
 * required to parse correctly the binary file, to know where you can find its
 * executable sections, etc.
 */
class ExecutableFormat {
public:
  /* The format RP++ handles */
  enum E_ExecutableFormat { FORMAT_PE, FORMAT_ELF, FORMAT_UNKNOWN };

  virtual ~ExecutableFormat() = default;

  /*!
   *  \brief Obtain the CPU ; for that it parses the executable format of your
   * binary
   *
   *  \return a pointer on the correct CPU
   */
  virtual std::unique_ptr<CPU> get_cpu(std::ifstream &file) = 0;

  /*!
   *  \brief Display information concerning the executable format: where
   * sections begin, entry point, etc.
   *
   *  \param lvl: Set a verbosity level
   */
  virtual void display_information(const VerbosityLevel lvl) const {
    fmt::print("Verbose level: {}\n", verbosity_to_string(lvl));
  }

  /*!
   *  \brief Retrieve the name of the class, useful when using polymorphism
   *
   *  \return the class name
   */
  virtual std::string get_class_name() const = 0;

  /*!
   *  \brief Get the executable sections of you binary ; it is where we will
   * look for gadgets
   *
   *  \param file: it is a file handle on your binary file
   *  \param base: it is the base address to use
   *
   *  \return A vector of Section instances
   */
  virtual std::vector<Section>
  get_executables_section(std::ifstream &file, const uint64_t base) const = 0;

  /*!
   *  \brief Give you the base address of the executable
   *
   *  \return The prefered base address of the executable
   */
  virtual uint64_t get_image_base_address() const = 0;

private:
  /*!
   *  \brief Fill the structures you need, parse your executable format to
   * extract the useful information
   *
   *  \param file: It is your binary file
   *
   *  \return The CPU type used in your binary file
   */
  virtual CPU::E_CPU extract_information_from_binary(std::ifstream &) {
    RAISE_EXCEPTION(
        "This method should not be called ; you're doing it wrong!");
    return CPU::CPU_UNKNOWN;
  }
};
