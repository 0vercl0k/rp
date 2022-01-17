// Axel '0vercl0k' Souchet - January 12 2022
#include "ropsearch_algorithm.hpp"
#include "safeint.hpp"
#include <cstring>

void find_all_gadget_from_ret(const std::vector<uint8_t> &memory,
                              uint64_t vaddr,
                              const InstructionInformation &ending_instr_disasm,
                              const uint32_t depth, GadgetMultiset &gadgets,
                              DisassEngineWrapper &disass_engine) {
  const uint8_t *data = memory.data();
  const uint8_t *end_data = memory.data() + memory.size();
  const uint32_t alignement = disass_engine.get_alignement();
  const uint32_t size_biggest_instruction =
      disass_engine.get_size_biggest_instruction();

  // We go back, trying to create the longuest gadget possible with the longuest
  // instructions
  uintptr_t EIP =
      ending_instr_disasm.address - (depth * size_biggest_instruction);
  uintptr_t VirtualAddr = ending_instr_disasm.virtual_address_in_memory -
                          (depth * size_biggest_instruction);

  // going back yeah, but not too much :))
  if (EIP < uintptr_t(data)) {
    EIP = uintptr_t(data);
    VirtualAddr = uintptr_t(vaddr);
  }

  while (EIP < ending_instr_disasm.address) {
    std::vector<Instruction> list_of_instr;

    uint64_t gadget_start_address = 0;

    // save where we were in memory
    uintptr_t saved_eip = EIP;
    uintptr_t saved_vaddr = VirtualAddr;

    bool is_a_valid_gadget = false;

    // now we'll try to find suitable sequence
    for (uint32_t nb_ins = 0; nb_ins < depth; nb_ins++) {
      DisassEngineReturn ret;
      const uint8_t *EIP_ = (uint8_t *)EIP;
      InstructionInformation instr =
          disass_engine.disass(EIP_, end_data - EIP_, VirtualAddr, ret);

      // if the instruction isn't valid, ends this function
      if (ret == UnknownInstruction || ret == OutOfBlock ||
          !disass_engine.is_valid_instruction(instr)) {
        break;
      }

      // Sets the begining address of the gadget as soon as we find the first
      // one
      if (list_of_instr.size() == 0) {
        gadget_start_address = EIP - uintptr_t(data);
      }

      list_of_instr.emplace_back(instr.disassembly, instr.bytes);

      EIP += instr.size;
      VirtualAddr += instr.size;

      // if the address of the latest instruction found points on the ending
      // one, we have a winner
      if (EIP == ending_instr_disasm.address) {
        is_a_valid_gadget = true;
        // I reach the ending instruction without depth instruction
        break;
      }

      // if we point after the ending one, it's not a valid sequence
      if (EIP > ending_instr_disasm.address) {
        break;
      }
    }

    if (is_a_valid_gadget) {
      // we have a valid gadget, time to build it ; add the instructions found &
      // finally add the ending instruction

      // Don't forget to include the ending instruction in the chain of
      // instruction
      list_of_instr.emplace_back(ending_instr_disasm.disassembly,
                                 ending_instr_disasm.bytes);

      Gadget gadget(gadget_start_address);

      // Now we populate our gadget with the instructions previously found..
      gadget.add_instructions(list_of_instr, vaddr);
      gadgets.insert(std::move(gadget));
    }

    // goto the next aligned-byte
    EIP = saved_eip + alignement;
    VirtualAddr = saved_vaddr + alignement;
  }
}

void find_rop_gadgets(const std::vector<uint8_t> &section, const uint64_t vaddr,
                      const uint32_t depth,
                      GadgetMultiset &merged_gadgets_final,
                      DisassEngineWrapper &disass_engine, std::mutex &m) {
  GadgetMultiset merged_gadgets;
  const uint8_t *data = section.data();
  const uint64_t size = section.size();
  const uint32_t alignement = disass_engine.get_alignement();
  for (uint64_t offset = 0; offset < size; offset += alignement) {
    DisassEngineReturn ret;
    InstructionInformation instr = disass_engine.disass(
        data + offset, size - offset, SafeIntAdd(vaddr, offset), ret);

    // OK either this is an unknow opcode & we goto the next one Or the
    // instruction encountered is too long & we also goto the next one in that
    // case
    if (ret == UnknownInstruction || ret == OutOfBlock) {
      continue;
    }

    if (!disass_engine.is_valid_ending_instruction(instr)) {
      continue;
    }

    // Okay I found a RET ; now I can build the gadget
    InstructionInformation ret_instr(instr);

    // Do not forget to add the ending instruction only -- we give to the user
    // all gadget with < depth instruction
    std::vector<Instruction> only_ending_instr;

    only_ending_instr.emplace_back(ret_instr.disassembly, ret_instr.bytes);

    Gadget gadget_with_one_instr(offset);

    // the gadget will only have 1 ending instruction
    gadget_with_one_instr.add_instructions(only_ending_instr, vaddr);
    merged_gadgets.insert(std::move(gadget_with_one_instr));

    // if we want to see gadget with more instructions
    if (depth > 0) {
      find_all_gadget_from_ret(section, vaddr, ret_instr, depth, merged_gadgets,
                               disass_engine);
    }
  }

  m.lock();
  merged_gadgets_final.merge(merged_gadgets);
  m.unlock();
}