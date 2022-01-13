// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"
#include <vector>

class x86 : public CPU {
public:
  std::string get_class_name() { return "x86"; }

  void find_gadget_in_memory(const uint8_t *p_memory, const uint64_t size,
                             const uint64_t vaddr, const uint32_t depth,
                             std::multiset<std::shared_ptr<Gadget>> &gadgets,
                             uint32_t disass_engine_options, std::mutex &m) {
    // BeaRopGadgetFinder bea(BeaRopGadgetFinder::x86, depth);
    // bea.find_rop_gadgets(p_memory, size, vaddr, gadgets);
    IntelBeaEngine bea_engine(IntelBeaEngine::x86);
    DisassEngineWrapper &engine = bea_engine;
    find_rop_gadgets(p_memory, size, vaddr, depth, gadgets, engine, m);
  }

  static constexpr uint32_t get_size_biggest_instruction() { return 15; }
  static constexpr uint32_t get_alignement() { return 1; }
};
