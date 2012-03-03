#include "instruction.hpp"

Instruction::Instruction(const char* ins, const char* ops, unsigned int size)
: m_instructions_name(ins), m_opcodes(ops), m_size(size)
{
}

Instruction::~Instruction(void)
{
}