// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"
#include "intelbeaengine.hpp"
#include "ropsearch_algorithm.hpp"

class x64 : public CPU {
public:
  std::string get_class_name() const override { return "x64"; }

  void find_gadget_in_memory(const std::vector<uint8_t> &p_memory,
                             const uint64_t vaddr, const uint32_t depth,
                             GadgetMultiset &gadgets,
                             uint32_t disass_engine_options,
                             std::mutex &m) override {
    IntelBeaEngine bea_engine(IntelBeaEngine::x64);
    DisassEngineWrapper &engine = bea_engine;
    find_rop_gadgets(p_memory, vaddr, depth, gadgets, engine, m);
  }
};
