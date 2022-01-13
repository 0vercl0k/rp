// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#define BEA_ENGINE_STATIC
#include "beaengine/BeaEngine.h"
#include "disassenginewrapper.hpp"

class IntelBeaEngine : public DisassEngineWrapper {
public:
  /*! The different architectures BeaRopGadgetFinder handles */
  enum E_Arch { x86 = 0, x64 = 64 };

  explicit IntelBeaEngine(E_Arch arch);
  InstructionInformation disass(const uint8_t *data, uint64_t len,
                                uint64_t vaddr,
                                DisassEngineReturn &ret) override;

  bool
  is_valid_ending_instruction(InstructionInformation &instr) const override;

  bool is_valid_instruction(InstructionInformation &instr) const override;

  uint32_t get_size_biggest_instruction(void) const override;

  uint32_t get_alignement(void) const override;

private:
  uint32_t m_arch; /*!< architecture the BeaEngine will use to disassemble*/

  DISASM m_disasm;
};
