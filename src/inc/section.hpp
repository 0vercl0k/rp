#ifndef SECTION_HPP
#define SECTION_HPP

class Section
{
    public:
        enum Properties
        {
            Readable,
            Writeable,
            Executable
        };

        explicit Section(const unsigned int offset, const unsigned int size, const Properties props);
        ~Section(void);

    private:
        const unsigned int m_offset;
        const unsigned int m_size;
        const Properties m_props;
};

#endif