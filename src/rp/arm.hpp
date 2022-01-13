// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "armcapstone.hpp"
#include "cpu.hpp"
#include "ropsearch_algorithm.hpp"
#include <vector>

class ARM : public CPU {
public:
  std::string get_class_name() const { return "ARM"; }

  void find_gadget_in_memory(const uint8_t *p_memory, const uint64_t size,
                             const uint64_t vaddr, const uint32_t depth,
                             std::multiset<std::shared_ptr<Gadget>> &gadgets,
                             uint32_t disass_engine_options, std::mutex &m) {
    ArmCapstone capstone_engine(disass_engine_options);
    DisassEngineWrapper &engine = capstone_engine;
    find_rop_gadgets(p_memory, size, vaddr, depth, gadgets, engine, m);
  }

  static constexpr uint32_t get_size_biggest_instruction() { return 4; }
  static constexpr uint32_t get_alignement() { return 4; }
};
