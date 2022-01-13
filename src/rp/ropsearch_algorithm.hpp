// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "disassenginewrapper.hpp"
#include "gadget.hpp"
#include <memory>
#include <mutex>
#include <set>

void find_rop_gadgets(const uint8_t *data, uint64_t size, uint64_t vaddr,
                      uint32_t depth,
                      std::multiset<std::shared_ptr<Gadget>> &merged_gadgets,
                      DisassEngineWrapper &disass_engine, std::mutex &m);
