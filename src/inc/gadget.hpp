#ifndef GADGET_HPP
#define GADGET_HPP

class Gadget
{
    public:
        explicit Gadget(const char* ins, const char* ops, unsigned int size, unsigned long long offset = 0);
        ~Gadget(void);

        const char* get_disassembly(void) const;

        unsigned long long get_offset(void) const;
        unsigned int get_size(void) const;
        const char* get_opcodes(void) const;

    private:
        const char *m_disassembly;
        const char *m_opcodes;

        unsigned int m_size;
        unsigned long long m_offset;
};

#endif