#ifndef SECTION_HPP
#define SECTION_HPP

#include <string>
#include <list>
#include <fstream>

/*
    Each binary is divided in section, actually it is a chunk of the binary of a specific size which contains code
*/
class Section
{
    public:
        enum Properties
        {
            Readable,
            Writeable,
            Executable
        };

        /* The constructor will make a copy of the memory in its own buffer */
        explicit Section(std::ifstream &file, const char *name, const unsigned long long offset, const unsigned long long size, const Properties props);
        ~Section(void);
        
        /* Get the name of the section */
        std::string get_name(void) const;

        /* Get the size of the section */
        unsigned long long get_size(void) const;

        /* Get the section code ; it's the copy the constructor have made */
        unsigned char *get_section_buffer(void) const;

        /* Get the offset of the section */
        const unsigned long long get_offset(void) const;

        std::list<unsigned long long> search_in_memory(const unsigned char *val, const unsigned int size);

    private:
        std::string m_name;
        const unsigned long long m_offset;
        const unsigned long long m_size;
        const Properties m_props;
        unsigned char *m_section;
};

#endif