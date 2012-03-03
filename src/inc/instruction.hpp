#ifndef INSTRUCTION_HPP
#define INSTRUCTION_HPP

class Instruction
{
    public:
        explicit Instruction(const char* ins, const char* ops, unsigned int size);
        ~Instruction(void);

    private:
        const char *m_instructions_name;
        const char *m_opcodes;

        unsigned int m_size;
};

#endif