#ifndef GADGET_HPP
#define GADGET_HPP

class Gadget
{
    public:
        explicit Gadget(const char* ins, const char* ops, unsigned int size, unsigned int offset = 0);
        ~Gadget(void);

        const char* get_disassembly(void) const;

        unsigned int get_offset(void) const;

    private:
        const char *m_disassembly;
        const char *m_opcodes;

        unsigned int m_size;
        unsigned int m_offset;
};

#endif