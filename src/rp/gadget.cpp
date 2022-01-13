// Axel '0vercl0k' Souchet - January 12 2022
#include "gadget.hpp"
#include "coloshell.hpp"
#include "toolbox.hpp"

Gadget::Gadget(uint64_t offset_start)
    : m_start_offset(offset_start), m_size(0) {}

std::string Gadget::get_disassembly(void) const {
  // Computing the disassembly is cheaper than keeping it in memory
  // Otherwise with big binaries you end up with a *lot* of memory being used
  std::string disassembly;
  for (const auto &i : m_instructions)
    disassembly += i->get_disassembly() + " ; ";
  return disassembly;
}

uint32_t Gadget::get_size(void) const { return m_size; }

void Gadget::add_instructions(std::vector<Instruction> &instrs,
                              uint64_t va_section) {
  for (const auto &instr : instrs) {
    /*
     * If we haven't any offset yet, it means this instruction is the first one
     * added thus, the offset of the gadget
     *
     * XXX: Yeah I'm aware that passing the va_section is a bit weird
     */
    if (m_info_gadgets.size() == 0)
      m_info_gadgets.emplace_back(m_start_offset, va_section);

    std::shared_ptr<Instruction> instr_copy =
        std::make_shared<Instruction>(instr);

    /* We build our gadget instruction per instruction */
    m_instructions.push_back(instr_copy);

    /* Don't forget to increment the size */
    m_size += instr.get_size();
  }
}

uint64_t Gadget::get_first_offset(void) const {
  return m_info_gadgets.front().m_offset;
}

uint64_t Gadget::get_first_va_section(void) const {
  return m_info_gadgets.front().m_va_section;
}

uint64_t Gadget::get_first_absolute_address(void) const {
  return get_first_offset() + get_first_va_section();
}

size_t Gadget::get_nb(void) const { return m_info_gadgets.size(); }

void Gadget::add_new_one(uint64_t offset, uint64_t va_section) {
  m_info_gadgets.emplace_back(offset, va_section);
}

std::vector<std::shared_ptr<Instruction>> Gadget::get_instructions(void) {
  std::vector<std::shared_ptr<Instruction>> instrs(m_instructions);
  /* We don't want the ending instruction in the list */
  instrs.pop_back();

  return instrs;
}

std::shared_ptr<Instruction> Gadget::get_ending_instruction(void) {
  return m_instructions.back();
}

void Gadget::display_disassembly(void) const {
  for (const auto &i : m_instructions)
    std::cout << i->get_disassembly() << " ; ";
}

void Gadget::print_bytes() {
  for (const auto &i : m_instructions)
    i->print_bytes();
}