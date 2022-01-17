// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "disassenginewrapper.hpp"
#include <beaengine/BeaEngine.h>

class IntelBeaEngine : public DisassEngineWrapper {
public:
  /*! The different architectures BeaRopGadgetFinder handles */
  enum E_Arch { x86 = 0, x64 = 64 };

  explicit IntelBeaEngine(const E_Arch arch) : m_arch(uint32_t(arch)) {
    // those options are mostly display option for the disassembler engine
    m_disasm.Options = PrefixedNumeral + NasmSyntax;

    // this one is to precise what architecture we'll disassemble
    m_disasm.Archi = m_arch;
  }

  InstructionInformation disass(const uint8_t *data, uint64_t len,
                                const uint64_t vaddr,
                                DisassEngineReturn &ret) override {
    InstructionInformation instr;
    m_disasm.EIP = UIntPtr(data);
    m_disasm.VirtualAddr = vaddr;
    m_disasm.SecurityBlock = uint32_t(len);

    const int len_instr = Disasm(&m_disasm);
    if (len_instr == OUT_OF_BLOCK) {
      ret = OutOfBlock;
      return instr;
    }

    // OK this one is an unknow opcode, goto the next one
    if (len_instr == UNKNOWN_OPCODE) {
      ret = UnknownInstruction;
      return instr;
    }

    ret = AllRight;

    instr.address = m_disasm.EIP;
    instr.virtual_address_in_memory = uintptr_t(m_disasm.VirtualAddr);
    instr.disassembly = m_disasm.CompleteInstr;
    instr.mnemonic = m_disasm.Instruction.Mnemonic;
    instr.size = len_instr;
    instr.bytes.insert(instr.bytes.begin(), data, data + instr.size);
    instr.bea_branch_type = m_disasm.Instruction.BranchType;
    instr.bea_addr_value = m_disasm.Instruction.AddrValue;
    return instr;
  }

  bool is_valid_ending_instruction(
      const InstructionInformation &instr) const override {
    const uint32_t branch_type = instr.bea_branch_type;
    const uint64_t addr_value = instr.bea_addr_value;
    const char *mnemonic_s = instr.mnemonic.c_str();

    const std::string &disass = instr.disassembly;
    const char *disass_s = disass.c_str();

    const bool is_good_branch_type =
        // We accept all the ret type instructions (except retf/iret)
        (branch_type == RetType && (strncmp(mnemonic_s, "retf", 4) != 0) &&
         (strncmp(mnemonic_s, "iretd", 5) != 0)) ||

        // call reg32 / call [reg32]
        (branch_type == CallType && addr_value == 0) ||

        // jmp reg32 / jmp [reg32]
        (branch_type == JmpType && addr_value == 0) ||

        // int 0x80 & int 0x2e
        ((strncmp(disass_s, "int 0x80", 8) == 0) ||
         (strncmp(disass_s, "int 0x2e", 8) == 0) ||
         (strncmp(disass_s, "syscall", 7) == 0));

    return is_good_branch_type &&
           // Yeah, we don't accept jmp far/call far
           disass.find("far") == std::string::npos;
  }

  bool
  is_valid_instruction(const InstructionInformation &instr) const override {
    const Int32 branch_type = instr.bea_branch_type;
    const uint64_t addr_value = instr.bea_addr_value;
    return branch_type != RetType && branch_type != JmpType &&
           ((branch_type == CallType && addr_value == 0) ||
            branch_type != CallType) &&
           instr.disassembly.find("far") == std::string::npos;
  }

  uint32_t get_size_biggest_instruction() const override { return 15; }

  uint32_t get_alignement() const override { return 1; }

private:
  uint32_t m_arch = 0; /*!< architecture the BeaEngine will use to disassemble*/
  DISASM m_disasm = {};
};
