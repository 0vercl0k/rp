// Axel '0vercl0k' Souchet - January 12 2022
#pragma once

#include "safeint.hpp"
#include "toolbox.hpp"
#include <fstream>
#include <string>
#include <vector>

/*! \class Section
 *
 *   Each binary is divided in section, actually it is a chunk of the binary of
 * a specific size which contains code or data
 */
class Section {
public:
  /*! The different rights a section can have ; those rights are usually
   * combined by an OR operation */
  enum Properties {
    Readable,  /*!< the section is readable*/
    Writeable, /*!< the section is writeable*/
    Executable /*!< the section is executable*/
  };

  /*!
   *  \brief The constructor will make a copy of the memory in its own buffer
   *
   *  \param name: The name of the section
   *  \param offset: It is the offset in file where you can find the section
   *  \param vaddr: Virtual address of the section
   *  \param size: It is the size of the section
   */
  Section(const char *name, const uint64_t offset, const uint64_t vaddr,
          const uint64_t size)
      : m_name(name), m_offset(offset), m_size(size), m_vaddr(vaddr) {}

  /*!
   *  \brief Get the name of the section
   *
   *  \return the name of the section
   */
  std::string get_name() const { return m_name; }

  /*!
   *  \brief Get the size of the section
   *
   *  \return the size of the section
   */
  uint64_t get_size() const { return m_size; }

  /*!
   *  \brief Get the content of the section (it's the internal copy)
   *
   *  \return a pointer on the buffer
   */
  const std::vector<uint8_t> &get_section_buffer() const { return m_section; }

  /*!
   *  \brief Get the (raw) offset of the section ; in other word, where it was
   * found in the binary
   *
   *  \return the offset where the section was found in the binary
   */
  const uint64_t get_offset() const { return m_offset; }

  /*!
   *  \brief Search in memory a sequence of bytes
   *
   *  \param val: A pointer on the bytes you want to search
   *  \param size: The size of the buffer
   *
   *  \return a list of offset (relative to the section) where it found the
   * sequence of bytes
   */
  std::vector<uint64_t> search_in_memory(const uint8_t *val,
                                         const size_t size) const {
    std::vector<uint64_t> val_found;
    for (uint64_t offset = 0; (offset + size) < m_size; ++offset) {
      if (std::memcmp(m_section.data() + offset, val, size) == 0) {
        val_found.push_back(offset);
      }
    }

    return val_found;
  }

  /*!
   *  \brief Dump the raw section of your file
   *
   *  \param file: The file
   */
  void dump(std::ifstream &file) {
    // NB: std::streampos performs unsigned check
    uint64_t fsize = get_file_size(file);
    if (SafeIntAdd(m_offset, m_size) > fsize) {
      RAISE_EXCEPTION("Your file seems to be screwed up");
    }

    std::streampos backup = file.tellg();

    file.seekg((uint32_t)m_offset, std::ios::beg);
    m_section.resize((uint32_t)m_size);

    file.read((char *)m_section.data(), (uint32_t)m_size);

    file.seekg(backup);
  }

  /*!
   *  \brief Set the properties of the section
   *
   *  \param props: The properties of the section
   */
  void set_props(const Properties props) { m_props = props; }

  uint64_t get_vaddr() const { return m_vaddr; }

private:
  std::string m_name; /*!< the name of the section*/

  const uint64_t m_offset; /*!< the raw offset of the section*/

  const uint64_t m_size; /*!< the size of the section of the section*/

  Properties m_props; /*!< the properties of the section*/

  std::vector<uint8_t> m_section; /*!< the section content*/

  uint64_t m_vaddr; /* !< the virtual address of the section*/
};
