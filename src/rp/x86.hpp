// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"
#include <vector>

#include "intelbeaengine.hpp"

class x86 : public CPU {
public:
  std::string get_class_name() const override { return "x86"; }

  void find_gadget_in_memory(const std::vector<uint8_t> &p_memory,
                             const uint64_t vaddr, const uint32_t depth,
                             GadgetMultiset &gadgets,
                             uint32_t disass_engine_options,
                             std::mutex &m) override {
    // BeaRopGadgetFinder bea(BeaRopGadgetFinder::x86, depth);
    // bea.find_rop_gadgets(p_memory, size, vaddr, gadgets);
    IntelBeaEngine bea_engine(IntelBeaEngine::x86);
    DisassEngineWrapper &engine = bea_engine;
    find_rop_gadgets(p_memory, vaddr, depth, gadgets, engine, m);
  }
};
