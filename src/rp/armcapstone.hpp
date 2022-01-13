// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "capstone.h"
#include "disassenginewrapper.hpp"

class ArmCapstone : public DisassEngineWrapper {
public:
  explicit ArmCapstone(uint32_t thumb_mode);
  ~ArmCapstone() override;
  InstructionInformation disass(const uint8_t *data, uint64_t len,
                                uint64_t vaddr,
                                DisassEngineReturn &ret) override;
  bool
  is_valid_ending_instruction(InstructionInformation &instr) const override;
  bool is_valid_instruction(InstructionInformation &instr) const override;
  uint32_t get_size_biggest_instruction(void) const override;
  uint32_t get_alignement(void) const override;

private:
  csh m_handle;
  bool is_thumb;
};
