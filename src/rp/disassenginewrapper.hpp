// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct InstructionInformation {
  // Generic fields
  std::string disassembly;
  std::string mnemonic;
  uint32_t size = 0;
  uintptr_t address = 0;
  uintptr_t virtual_address_in_memory = 0;
  std::vector<uint8_t> bytes;
  bool is_branch = false;
  bool is_valid_ending_instr = false;
};

enum DisassEngineReturn { UnknownInstruction, OutOfBlock, AllRight };

class DisassEngineWrapper {
public:
  DisassEngineWrapper() = default;
  virtual ~DisassEngineWrapper() = default;

  DisassEngineWrapper(const DisassEngineWrapper &) = delete;
  DisassEngineWrapper &operator=(const DisassEngineWrapper &) = delete;
  DisassEngineWrapper(DisassEngineWrapper &&) = delete;
  DisassEngineWrapper &operator=(DisassEngineWrapper &&) = delete;

  virtual InstructionInformation disass(const uint8_t *data, uint64_t len,
                                        const uint64_t vaddr,
                                        DisassEngineReturn &ret) = 0;
  virtual uint32_t get_size_biggest_instruction() const = 0;
  virtual uint32_t get_alignement() const = 0;
};
