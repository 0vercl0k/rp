// Axel '0vercl0k' Souchet - January 12 2022
#include "instruction.hpp"

Instruction::Instruction(const std::string &disass, uint32_t size,
                         std::vector<uint8_t> b)
    : m_disass(std::move(disass)), m_size(size) {
  for (auto i : b)
    bytes.push_back(i);
}

uint32_t Instruction::get_size(void) const { return m_size; }

const std::string &Instruction::get_disassembly(void) const {
  return m_disass.get();
}

void Instruction::print_bytes(void) {
  for (size_t i = 0; i < m_size; ++i)
    printf("\\x%.2x", bytes.at(i));
}