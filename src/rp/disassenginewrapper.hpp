// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include <string>
#include <vector>

struct InstructionInformation {
  // Generic fields
  std::string disassembly;
  std::string mnemonic;
  uint32_t size;
  uintptr_t address;
  uintptr_t virtual_address_in_memory;

  std::vector<uint8_t> bytes;

  // Capstone field
  bool cap_is_branch;
  bool cap_is_valid_ending_instr;

  // BeaEngine fields
  uint32_t bea_branch_type; // This is used by BeaEngine ; and this will hold
                            // DISASM.Instruction.BranchType
  uint64_t bea_addr_value;  // This is used by BeaEngine, DISASM.Instruction
};

enum DisassEngineReturn { UnknownInstruction, OutOfBlock, AllRight };

class DisassEngineWrapper {
public:
  virtual ~DisassEngineWrapper(){};
  virtual InstructionInformation disass(const uint8_t *data, uint64_t len,
                                        uint64_t vaddr,
                                        DisassEngineReturn &ret) = 0;
  virtual bool
  is_valid_ending_instruction(InstructionInformation &instr) const = 0;
  virtual bool is_valid_instruction(InstructionInformation &instr) const = 0;
  virtual uint32_t get_size_biggest_instruction(void) const = 0;
  virtual uint32_t get_alignement(void) const = 0;
};
