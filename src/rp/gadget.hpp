// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "instruction.hpp"
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

/*! \class Gadget
 *
 * A gadget is a sequence of instructions that ends by an ending instruction
 * (ret/call/jmp) In order, to keep in memory only *unique* gadgets, each gadget
 * holds a set of offset where you can find the same one.
 */
class Gadget {
public:
  struct Info {
    uint64_t m_offset;
    uint64_t m_va_section;

    Info(uint64_t offset, uint64_t va_section)
        : m_offset(offset), m_va_section(va_section) {}
  };

  explicit Gadget(uint64_t offset_start);

  /*!
   *  \brief Get the entire disassembly of your gadget
   *  \return the disassembly
   */
  std::string get_disassembly(void) const;

  void display_disassembly(void) const;

  /*!
   *  \brief Get the size of your gadget
   *  \return the size of the whole gadget
   */
  uint32_t get_size(void) const;

  /*!
   *  \brief Add a list of instructions to your gadget ; don't forget it's back
   * pushed in the instruction list It means the first instruction inserted will
   * be the address of the gadget
   *
   *  \param instrs: It is a list of Instruction to create our gadget (NB: the
   * method copy in its memory those instructions for futur usage) \param
   * va_section: It is the va section of the instructions ; a bit weird to pass
   * it here yeah
   */
  void add_instructions(std::vector<Instruction> &instrs, uint64_t va_section);

  /*!
   *  \brief Get the size of your gadget
   *  \return the size of the whole gadget
   */
  std::vector<std::shared_ptr<Instruction>> get_instructions(void);

  /*!
   *  \brief Get the first offset of this gadget (first offset because a gadget
   * instance stores other offset with the same disassembly in memory) \return
   * the offset (relative to m_va_section)
   */
  uint64_t get_first_offset(void) const;

  /*!
   *  \brief Get the first va section of this gadget (first offset because a
   * gadget instance stores other offset with the same disassembly in memory)
   *  \return the va section
   */
  uint64_t get_first_va_section(void) const;

  /*!
   *  \brief Get the first absolute address of this gadget
   *  \return the absolute address (computed like this: m_va_section + offset)
   */
  uint64_t get_first_absolute_address(void) const;

  /*!
   *  \brief Get the number of other equivalent gadget
   *  \return the number of the same gadget in memory
   */
  size_t get_nb(void) const;

  /*!
   *  \brief Add the offset where you can find the same gadget
   *
   *  \param offset: the offset where you can find the same gadget
   */
  void add_new_one(uint64_t offset, uint64_t va_section);

  /*!
   *  \brief Get the ending instruction of this gadget
   *  \return a pointer on the ending instruction
   */
  std::shared_ptr<Instruction> get_ending_instruction(void);

  /*!
   * \brief This structure can be used for sorting Gadgets instance
   * \return
   */
  struct Sort {
    bool operator()(const std::shared_ptr<Gadget> g,
                    const std::shared_ptr<Gadget> d) const {
      return g->get_disassembly() < d->get_disassembly();
    }
  };

  void print_bytes();

private:
  uint64_t m_start_offset; /*!< this is where the gadget is starting from in
                              memory */

  uint32_t m_size; /*!< the size in byte of the gadget*/

  std::vector<std::shared_ptr<Instruction>>
      m_instructions; /*!< the list of the different instructions composing the
                         gadget*/

  std::vector<Info>
      m_info_gadgets; /*!< the vector which stores where you can find the same
                         gadget ; those offsets are relative to m_va_section*/
};