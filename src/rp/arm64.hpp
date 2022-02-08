// Axel '0vercl0k' Souchet - February 7 2022
#pragma once

#include "cpu.hpp"

#include "disassenginewrapper.hpp"
#include "ropsearch_algorithm.hpp"
#include "rpexception.hpp"
#include <capstone/capstone.h>
#include <vector>

class Arm64Capstone : public DisassEngineWrapper {
public:
  Arm64Capstone() {
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &m_handle) != CS_ERR_OK) {
      RAISE_EXCEPTION("Apparently no support for ARM64 in capstone.lib");
    }

    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
  }

  ~Arm64Capstone() override { cs_close(&m_handle); }
  InstructionInformation disass(const uint8_t *data, uint64_t len,
                                const uint64_t vaddr,
                                DisassEngineReturn &ret) override {
    cs_insn *insn = nullptr;
    const size_t count =
        cs_disasm(m_handle, data, size_t(len), vaddr, 1, &insn);
    if (count != 1) {
      ret = UnknownInstruction;
      return {};
    }

    InstructionInformation instr;
    instr.address = uintptr_t(data);
    instr.virtual_address_in_memory = uintptr_t(vaddr);
    instr.mnemonic = insn[0].mnemonic;
    instr.disassembly = instr.mnemonic + ' ' + std::string(insn[0].op_str);
    instr.size = insn[0].size;
    instr.bytes.insert(instr.bytes.begin(), data, data + instr.size);

    instr.u.capstone.is_branch = false;
    instr.u.capstone.is_valid_ending_instr = false;
    ret = AllRight;

    if (insn[0].detail == nullptr) {
      cs_free(insn, count);
      return instr;
    }

    if (cs_insn_group(m_handle, insn, ARM_GRP_JUMP)) {
      instr.u.capstone.is_branch = true;
      instr.u.capstone.is_valid_ending_instr =
          insn[0].detail->arm.op_count == 1 &&
          insn[0].detail->arm.operands[0].type != ARM_OP_IMM;
    } else if (instr.mnemonic == "ret") {
      instr.u.capstone.is_branch = true;
      instr.u.capstone.is_valid_ending_instr = true;
    } else if (instr.mnemonic == "b" || instr.mnemonic == "bl" ||
               instr.mnemonic == "cbz" || instr.mnemonic == "cbnz" ||
               instr.mnemonic == "tbnz" || instr.mnemonic == "tbz") {
      instr.u.capstone.is_branch = true;
    } else if (instr.mnemonic == "svc" || instr.mnemonic == "smc" ||
               instr.mnemonic == "hvc") {
      instr.u.capstone.is_branch = true;
      instr.u.capstone.is_valid_ending_instr = true;
    } else if (instr.mnemonic == "br" || instr.mnemonic == "blr") {
      instr.u.capstone.is_branch = true;
      instr.u.capstone.is_valid_ending_instr = true;
    }

    cs_free(insn, count);
    return instr;
  }

  bool is_valid_ending_instruction(
      const InstructionInformation &instr) const override {
    return instr.u.capstone.is_valid_ending_instr;
  }

  bool
  is_valid_instruction(const InstructionInformation &instr) const override {
    return instr.u.capstone.is_branch == false;
  }

  uint32_t get_size_biggest_instruction() const override { return 4; }

  uint32_t get_alignement() const override { return 4; }

private:
  csh m_handle = {};
};

class ARM64 : public CPU {
public:
  std::string get_class_name() const override { return "ARM64"; }

  void find_gadget_in_memory(const std::vector<uint8_t> &p_memory,
                             const uint64_t vaddr, const uint32_t depth,
                             GadgetMultiset &gadgets,
                             uint32_t disass_engine_options,
                             std::mutex &m) override {
    Arm64Capstone capstone_engine;
    find_rop_gadgets(p_memory, vaddr, depth, gadgets, capstone_engine, m);
  }
};
