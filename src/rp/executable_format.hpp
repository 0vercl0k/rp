// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"
#include "rpexception.hpp"
#include "section.hpp"
#include "toolbox.hpp"
#include <fstream>
#include <iostream>
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

  /*!
   *  \brief Obtain the CPU ; for that it parses the executable format of your
   * binary
   *
   *  \return a pointer on the correct CPU
   */
  virtual std::shared_ptr<CPU> get_cpu(std::ifstream &file) = 0;

  /*!
   *  \brief Display information concerning the executable format: where
   * sections begin, entry point, etc.
   *
   *  \param lvl: Set a verbosity level
   */
  virtual void display_information(const VerbosityLevel lvl) const {
    std::cout << "Verbose level: " << verbosity_to_string(lvl) << std::endl;
  }

  /*!
   *  \brief Retrieve the name of the class, useful when using polymorphism
   *
   *  \return the class name
   */
  virtual std::string get_class_name(void) const = 0;

  /*!
   *  \brief Get the executable sections of you binary ; it is where we will
   * look for gadgets
   *
   *  \param file: it is a file handle on your binary file
   *
   *  \return A vector of Section instances
   */
  virtual std::vector<std::shared_ptr<Section>>
  get_executables_section(std::ifstream &file) const = 0;

  /*!
   *  \brief Give you a PE/ELF instance (based mostly on the magic signature)
   *
   *  \param magic_dword: It is a dword that allows to deduce which
   * ExecutableFormat is used by the binary
   *
   *  \return A pointer on the correct ExecutableFormat deduced thanks to the
   * magic_dword argument
   */
  static std::shared_ptr<ExecutableFormat>
  GetExecutableFormat(uint32_t magic_dword);

  /*!
   *  \brief Give you the base address of the executable
   *
   *  \return The prefered base address of the executable
   */
  virtual uint64_t get_image_base_address(void) const = 0;

private:
  /*!
   *  \brief Fill the structures you need, parse your executable format to
   * extract the useful information
   *
   *  \param file: It is your binary file
   *
   *  \return The CPU type used in your binary file
   */
  virtual CPU::E_CPU extract_information_from_binary(std::ifstream &file) {
    RAISE_EXCEPTION(
        "This method should not be called ; you're doing it wrong!");
    return CPU::CPU_UNKNOWN;
  }
};