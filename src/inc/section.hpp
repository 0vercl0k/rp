#ifndef SECTION_HPP
#define SECTION_HPP

#include <string>

class Section
{
    public:
        enum Properties
        {
            Readable,
            Writeable,
            Executable
        };

        explicit Section(const char *name, const unsigned int offset, const unsigned int size, const Properties props);
        ~Section(void);

        std::string get_name(void) const;
        unsigned int get_size(void) const;
        unsigned char *get_section_buffer(void) const;

    private:
        std::string m_name;
        const unsigned int m_size;
        const Properties m_props;
        unsigned char *m_section;
};

#endif