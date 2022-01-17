// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "gadget.hpp"
#include <mutex>
#include <set>
#include <string>

/*! \class CPU
 *
 *  A CPU is an important class that compose a part of the Program class.
 */
class CPU {
public:
  virtual ~CPU() = default;

  /*!
   *  \brief Obtain the name of the class (useful when you use the polymorphism)
   *
   *  \return the name of the class
   */
  virtual std::string get_class_name() const = 0;

  /*!
   *  \brief Each CPU class is able to find all gadgets in [p_memory,
   * p_memory+size] NB: The vaddr field is actually used by the BeaEngine when
   * it disassembles something like jmp instruction, it needs the original
   * virtual address to give you disassemble correctly (indeed jmp instruction
   * are relative)
   *
   *  \param p_memory: It is a pointer on the memory where you want to find rop
   * gadget \param size: It is the size of the p_memory \param vaddr: It is the
   * real virtual address of the memory which will be disassembled (see the
   * previous remark) \param depth: It is the number of maximum instructions
   * contained by a gadget \param gadgets: A list of the Gadget instance \param
   * disass_engine_options: Options you want to pass to the disassembly engine
   *
   */
  virtual void find_gadget_in_memory(const std::vector<uint8_t> &p_memory,
                                     const uint64_t vaddr, const uint32_t depth,
                                     GadgetMultiset &gadgets,
                                     uint32_t disass_engine_options,
                                     std::mutex &m) = 0;

  /*! The different architectures RP++ handles */
  enum E_CPU {
    CPU_x86,    /*!< x86 */
    CPU_x64,    /*!< x64 */
    CPU_ARM,    /*!< ARM */
    CPU_UNKNOWN /*!< unknown cpu */
  };
};
