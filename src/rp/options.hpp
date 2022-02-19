// Axel '0vercl0k' Souchet - February 19 2022
#pragma once
#include "cpu.hpp"
#include <cstdint>
#include <string>

struct Options_t {
  std::string file;
  uint8_t display = 0;
  uint32_t rop = 0;
  CPU::E_CPU raw = CPU::E_CPU::CPU_UNKNOWN;
  std::string shexa;
  uint32_t maxth = 2;
  std::string badbytes;
  std::string sint;
  std::string va;
  bool allow_branches = false;
  bool unique = false;
  bool version = false;
  bool thumb = false;
};

static Options_t g_opts;
