// Axel '0vercl0k' Souchet - January 12 2022
#include "rpexception.hpp"
#include <sstream>

RpException::RpException(const char *filename, uint32_t line, const char *funct,
                         const char *msg)
    : m_filename(filename), m_msg(msg), m_function_name(funct), m_line(line) {
  std::ostringstream oss;
  oss << "[EXCEPTION REPORT]:" << std::endl;
  oss << "\t Raised in " << m_filename << ":" << m_line << std::endl;
  oss << "\t More precisely in " << m_function_name << std::endl;
  oss << "\t Further infos: " << m_msg;

  m_report = oss.str();
}

RpException::~RpException(void) throw() {}

const char *RpException::what(void) const throw() { return m_report.c_str(); }
