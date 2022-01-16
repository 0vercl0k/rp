// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include <fmt/printf.h>
#include <string>
#include <vector>

/*! \class Instruction
 *
 *  Each instruction instance holds a disassembly, an offset (where we can find
 * it in memory) and a size
 */
class Instruction {
public:
  /*!
   *  \brief Build an instruction
   *
   *  \param disass: The disassembly of the instruction
   *  \param mnemonic: The mnemonic of the instruction
   *  \param offset: A raw offset (relative to a section) where you can find
   * this instruction
   *  \param size: It is the size of the instruction
   */
  Instruction(const std::string &disass, const std::vector<uint8_t> &b)
      : m_disass(disass), m_bytes(b) {}

  /*!
   *  \brief Get the size of the instruction
   *
   *  \return the size of the instruction
   */
  uint32_t get_size() const { return m_bytes.size(); }

  /*!
   *  \brief Get the disassembly of the instruction
   *
   *  \return the disassembly of the instruction
   */
  const std::string &get_disassembly() const { return m_disass; }

  void print_bytes() const {
    for (const auto &byte : m_bytes) {
      fmt::print("\\x{:02x}", byte);
    }
  }

  const std::vector<uint8_t> &bytes() const { return m_bytes; }

private:
  std::vector<uint8_t> m_bytes;
  std::string m_disass; /*!< the disassembly of the instruction */
};
