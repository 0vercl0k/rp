// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "disassenginewrapper.hpp"

#include "rpexception.hpp"
#include <capstone/capstone.h>

class ArmCapstone : public DisassEngineWrapper {
public:
  explicit ArmCapstone(const uint32_t thumb_mode) : is_thumb(true) {
    cs_mode mode = CS_MODE_THUMB;
    if (thumb_mode == 0) {
      mode = CS_MODE_ARM;
      is_thumb = false;
    }

    if (cs_open(CS_ARCH_ARM, mode, &m_handle) != CS_ERR_OK) {
      RAISE_EXCEPTION("Apparently no support for ARM in capstone.lib");
    }

    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
  }

  ~ArmCapstone() override { cs_close(&m_handle); }
  InstructionInformation disass(const uint8_t *data, uint64_t len,
                                const uint64_t vaddr,
                                DisassEngineReturn &ret) override {
    if (len == 0) {
      len = 4;
    }

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

    instr.cap_is_branch = false;
    instr.cap_is_valid_ending_instr = false;
    ret = AllRight;

    if (insn[0].detail == nullptr) {
      cs_free(insn, count);
      return instr;
    }

    if (cs_insn_group(m_handle, insn, ARM_GRP_JUMP)) {
      instr.cap_is_branch = true;
      instr.cap_is_valid_ending_instr =
          insn[0].detail->arm.op_count == 1 &&
          insn[0].detail->arm.operands[0].type != ARM_OP_IMM;
    } else if (instr.mnemonic == "b" || instr.mnemonic == "bl" ||
               instr.mnemonic == "blx" || instr.mnemonic == "cb" ||
               instr.mnemonic == "cbz") {
      instr.cap_is_branch = true;
    } else if (instr.mnemonic == "swi" || instr.mnemonic == "svc") {
      instr.cap_is_branch = true;
      instr.cap_is_valid_ending_instr = true;
    } else if (instr.mnemonic == "mov" && insn[0].detail->arm.op_count >= 1 &&
               insn[0].detail->arm.operands[0].type == ARM_OP_REG &&
               insn[0].detail->arm.operands[0].reg == ARM_REG_PC) {
      instr.cap_is_branch = true;
      instr.cap_is_valid_ending_instr = true;
    } else if (instr.mnemonic == "bx") {
      instr.cap_is_branch = true;
      instr.cap_is_valid_ending_instr =
          insn[0].detail->arm.operands[0].type == ARM_OP_REG;
    } else if (instr.mnemonic == "blx") {
      instr.cap_is_branch = true;
      instr.cap_is_valid_ending_instr = true;
    } else if (instr.mnemonic == "pop") {
      bool has_pc = false;
      for (size_t i = 0; i < insn[0].detail->arm.op_count; ++i) {
        if (insn[0].detail->arm.operands[i].type == ARM_OP_REG &&
            insn[0].detail->arm.operands[i].reg == ARM_REG_PC) {
          has_pc = true;
          break;
        }
      }

      if (has_pc) {
        instr.cap_is_branch = true;
        instr.cap_is_valid_ending_instr = true;
      }
    }

    cs_free(insn, count);
    return instr;
  }

  bool is_valid_ending_instruction(
      const InstructionInformation &instr) const override {
    return instr.cap_is_valid_ending_instr;
  }

  bool
  is_valid_instruction(const InstructionInformation &instr) const override {
    return instr.cap_is_branch == false;
  }

  uint32_t get_size_biggest_instruction() const override { return 4; }

  uint32_t get_alignement() const override {
    if (is_thumb) {
      return 2;
    }

    return 4;
  }

private:
  csh m_handle;
  bool is_thumb;
};
