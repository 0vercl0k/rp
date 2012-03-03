#ifndef GADGET_HPP
#define GADGET_HPP

class Gadget
{
    public:
        explicit Gadget(const char* ins, const char* ops, unsigned int size);
        ~Gadget(void);

    private:
        const char *m_disassembly;
        const char *m_opcodes;

        unsigned int m_size;
};

#endif