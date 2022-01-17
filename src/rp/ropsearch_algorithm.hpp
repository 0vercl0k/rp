// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "disassenginewrapper.hpp"
#include "gadget.hpp"
#include <memory>
#include <mutex>
#include <set>

void find_rop_gadgets(const std::vector<uint8_t> &section, const uint64_t vaddr,
                      const uint32_t depth, GadgetMultiset &merged_gadgets,
                      DisassEngineWrapper &disass_engine, std::mutex &m);
