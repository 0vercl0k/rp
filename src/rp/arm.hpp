// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"

#include "disassenginewrapper.hpp"
#include "ropsearch_algorithm.hpp"
#include "rpexception.hpp"
#include <capstone/capstone.h>
#include <vector>

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
    cs_insn *insn = nullptr;
    const size_t count =
        cs_disasm(m_handle, data, size_t(len), vaddr, 1, &insn);
    if (count != 1) {
      ret = UnknownInstruction;
      return {};
    }

    std::string mnemonic(insn[0].mnemonic);
    InstructionInformation instr;
    instr.address = uintptr_t(data);
    instr.virtual_address_in_memory = uintptr_t(vaddr);
    instr.disassembly = mnemonic + ' ' + std::string(insn[0].op_str);
    instr.size = insn[0].size;
    ret = AllRight;

    if (insn[0].detail == nullptr) {
      cs_free(insn, count);
      std::abort();
    }

    bool has_pc_operand_after_first = false;
    bool has_pc_operand_first = false;
    for (size_t i = 0; i < insn[0].detail->arm.op_count; i++) {
      const bool pc_operand =
          insn[0].detail->arm.operands[i].type == ARM_OP_REG &&
          insn[0].detail->arm.operands[i].reg == ARM_REG_PC;
      if (!has_pc_operand_first) {
        has_pc_operand_first = pc_operand && i == 0;
      }
      if (!has_pc_operand_after_first) {
        has_pc_operand_after_first = pc_operand && i > 0;
      }

      if (has_pc_operand_after_first) {
        break;
      }
    }

    const bool has_pc_operand =
        has_pc_operand_after_first || has_pc_operand_first;

    const bool Jump = cs_insn_group(m_handle, insn, ARM_GRP_JUMP);
    const bool Call = cs_insn_group(m_handle, insn, ARM_GRP_CALL);
    const bool indirect_jmp_call =
        (Jump || Call) && insn[0].detail->arm.op_count == 1 &&
        insn[0].detail->arm.operands[0].type != ARM_OP_IMM;
    const bool pop_pc = insn[0].id == ARM_INS_POP && has_pc_operand;
    const bool ldm_pc =
        (insn[0].id == ARM_INS_LDM || insn[0].id == ARM_INS_LDMDA ||
         insn[0].id == ARM_INS_LDMDB || insn[0].id == ARM_INS_LDMIB) &&
        has_pc_operand_after_first;
    const bool mov_pc = insn[0].id == ARM_INS_MOV && has_pc_operand;
    const bool swi_svc = insn[0].id == ARM_INS_SVC;
    instr.is_valid_ending_instr =
        indirect_jmp_call || pop_pc || ldm_pc || mov_pc;

    const bool Int = cs_insn_group(m_handle, insn, ARM_GRP_INT);
    instr.is_branch = instr.is_valid_ending_instr || Jump || Call || Int;

    cs_free(insn, count);
    return instr;
  }

  uint32_t get_size_biggest_instruction() const override { return 4; }

  uint32_t get_alignement() const override {
    if (is_thumb) {
      return 2;
    }

    return 4;
  }

private:
  csh m_handle = {};
  bool is_thumb = false;
};

class ARM : public CPU {
public:
  std::string get_class_name() const override { return "ARM"; }

  void find_gadget_in_memory(const std::vector<uint8_t> &p_memory,
                             const uint64_t vaddr, const uint32_t depth,
                             GadgetMultiset &gadgets,
                             uint32_t disass_engine_options,
                             std::mutex &m) override {
    ArmCapstone capstone_engine(disass_engine_options);
    find_rop_gadgets(p_memory, vaddr, depth, gadgets, capstone_engine, m);
  }
};
