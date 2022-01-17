// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "cpu.hpp"

#include "armcapstone.hpp"
#include "ropsearch_algorithm.hpp"
#include <vector>

class ARM : public CPU {
public:
  std::string get_class_name() const override { return "ARM"; }

  void find_gadget_in_memory(const std::vector<uint8_t> &p_memory,
                             const uint64_t vaddr, const uint32_t depth,
                             GadgetMultiset &gadgets,
                             uint32_t disass_engine_options,
                             std::mutex &m) override {
    ArmCapstone capstone_engine(disass_engine_options);
    DisassEngineWrapper &engine = capstone_engine;
    find_rop_gadgets(p_memory, vaddr, depth, gadgets, engine, m);
  }
};
