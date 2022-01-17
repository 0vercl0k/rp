// Axel '0vercl0k' Souchet - January 12 2022
#include "program.hpp"
#include "arm.hpp"
#include "coloshell.hpp"
#include "executable_format.hpp"
#include "raw.hpp"
#include "rpexception.hpp"
#include "section.hpp"
#include "toolbox.hpp"
#include "x64.hpp"
#include "x86.hpp"
#include <fmt/printf.h>
#include <future>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>

Program::Program(const std::string &program_path, const CPU::E_CPU arch) {
  uint32_t magic_dword = 0;

  fmt::print("Trying to open '{}'..\n", program_path);
  m_file.open(program_path.c_str(), std::ios::binary);
  if (!m_file.is_open()) {
    RAISE_EXCEPTION("Cannot open the file");
  }

  if (arch != CPU::CPU_UNKNOWN) {
    // If we know the CPU in the constructor, it is a raw file
    m_exformat = std::make_unique<Raw>();

    switch (arch) {
    case CPU::CPU_x86: {
      m_cpu = std::make_unique<x86>();
      break;
    }

    case CPU::CPU_x64: {
      m_cpu = std::make_unique<x64>();
      break;
    }

    case CPU::CPU_ARM: {
      m_cpu = std::make_unique<ARM>();
      break;
    }

    default: {
      RAISE_EXCEPTION("Don't know your architecture");
    }
    }
  } else {
    // This isn't a raw file, we have to determine the executable format and the
    // cpu
    m_file.read((char *)&magic_dword, sizeof(magic_dword));

    m_exformat = get_executable_format(magic_dword);
    if (m_exformat == nullptr) {
      RAISE_EXCEPTION("get_executable_format fails");
    }

    m_cpu = m_exformat->get_cpu(m_file);
    if (m_cpu == nullptr) {
      RAISE_EXCEPTION("get_cpu failed");
    }
  }

  fmt::print("FileFormat: {}, Arch: {}\n", m_exformat->get_class_name(),
             m_cpu->get_class_name());
}

void Program::display_information(const VerbosityLevel lvl) {
  m_exformat->display_information(lvl);
}

GadgetMultiset Program::find_gadgets(const uint32_t depth,
                                     const uint32_t disass_engine_options,
                                     const size_t n_max_thread,
                                     const uint64_t base) {
  // To do a ROP gadget research, we need to know the executable section
  auto executable_sections = m_exformat->get_executables_section(m_file, base);
  if (executable_sections.size() == 0) {
    fmt::print("It seems your binary haven't executable sections.\n");
  }

  std::queue<Section> jobs_queue;
  for (auto &executable_section : executable_sections) {
    jobs_queue.push(executable_section);
  }

  GadgetMultiset gadgets_found;
  std::vector<std::future<void>> thread_pool;
  std::mutex m;
  while (jobs_queue.size() != 0) {
    if (thread_pool.size() < n_max_thread) {
      auto section = std::move(jobs_queue.front());
      jobs_queue.pop();
      auto Lambda = [&](Section section) {
        const auto section_buffer = section.get_section_buffer();
        const auto vaddr = section.get_vaddr();
        m_cpu->find_gadget_in_memory(section_buffer, vaddr, depth,
                                     gadgets_found, disass_engine_options, m);
      };
      thread_pool.emplace_back(
          std::async(std::launch::async, Lambda, std::move(section)));
    } else {
      // Wait for a thread to finish
      for (auto it = thread_pool.begin(); it != thread_pool.end();) {
        if (it->wait_for(std::chrono::milliseconds(1)) ==
            std::future_status::ready) {
          it->get();
          it = thread_pool.erase(it);
        } else {
          it++;
        }
      }
    }
  }

  // Wait for potentially unfinished threads
  for (auto &f : thread_pool) {
    f.get();
  }

  return gadgets_found;
}

void Program::search_and_display(const uint8_t *hex_values, const size_t size,
                                 const uint64_t base) {
  const auto &executable_sections =
      m_exformat->get_executables_section(m_file, base);
  if (executable_sections.size() == 0) {
    fmt::print("It seems your binary haven't executable sections.\n");
  }

  for (const auto &executable_section : executable_sections) {
    const auto &offsets = executable_section.search_in_memory(hex_values, size);
    for (const auto &offset : offsets) {
      const uint64_t va_section = executable_section.get_vaddr();
      const uint64_t va = va_section + offset;
      display_offset_lf(va, hex_values, size);
    }
  }
}

uint64_t Program::get_image_base_address() const {
  return m_exformat->get_image_base_address();
}