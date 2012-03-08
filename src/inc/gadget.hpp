#ifndef GADGET_HPP
#define GADGET_HPP

#include <vector>

class Gadget
{
    public:
        explicit Gadget(const char* ins, const char* ops, unsigned int size, unsigned long long offset = 0);
        ~Gadget(void);

        const char* get_disassembly(void) const;

        std::vector<unsigned long long> get_offsets(void) const;

        unsigned int get_size(void) const;
        
        const char* get_opcodes(void) const;
        
        void add_offset(unsigned long long offset);

        unsigned long long get_first_offset(void) const;

        unsigned int get_nb(void) const;

    private:
        const char *m_disassembly;
        const char *m_opcodes;

        unsigned int m_size;
        std::vector<unsigned long long> m_offsets;
};

#endif