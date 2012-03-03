#include "ia32.hpp"

Ia32::Ia32(void)
{
    m_instructions.push_back(Instruction("int 0x80", "\xcd\x80", 2));
    m_instructions.push_back(Instruction("sysenter", "\x0f\x34", 2));
    
    m_instructions.push_back(Instruction("call eax", "\xff\xd0", 2));
    m_instructions.push_back(Instruction("call ebx", "\xff\xd3", 2));
    m_instructions.push_back(Instruction("call ecx", "\xff\xd1", 2));
    m_instructions.push_back(Instruction("call edx", "\xff\xd2", 2));
    m_instructions.push_back(Instruction("call esi", "\xff\xd6", 2));
    m_instructions.push_back(Instruction("call edi", "\xff\xd7", 2));
   
    m_instructions.push_back(Instruction("call [eax]", "\xff\x10", 2));
    m_instructions.push_back(Instruction("call [ebx]", "\xff\x13", 2));
    m_instructions.push_back(Instruction("call [ecx]", "\xff\x11", 2));
    m_instructions.push_back(Instruction("call [edx]", "\xff\x12", 2));
    m_instructions.push_back(Instruction("call [esi]", "\xff\x16", 2));
    m_instructions.push_back(Instruction("call [edi]", "\xff\x17", 2));
    
    m_instructions.push_back(Instruction("call label ; label: pop eax ; ret", "\xe8\x00\x00\x00\x00\x58\xc3", 7));
    m_instructions.push_back(Instruction("call label ; label: pop ebx ; ret", "\xe8\x00\x00\x00\x00\x5b\xc3", 7));
    m_instructions.push_back(Instruction("call label ; label: pop ecx ; ret", "\xe8\x00\x00\x00\x00\x59\xc3", 7));
    m_instructions.push_back(Instruction("call label ; label: pop edx ; ret", "\xe8\x00\x00\x00\x00\x5a\xc3", 7));
    m_instructions.push_back(Instruction("call label ; label: pop esi ; ret", "\xe8\x00\x00\x00\x00\x5e\xc3", 7));
    m_instructions.push_back(Instruction("call label ; label: pop edi ; ret", "\xe8\x00\x00\x00\x00\x5f\xc3", 7));
    m_instructions.push_back(Instruction("call label ; label: pop ebp ; ret", "\xe8\x00\x00\x00\x00\x5d\xc3", 7));
    
    m_instructions.push_back(Instruction("call gs:[0x10]", "\x65\xff\x15\x10\x00\x00\x00", 7));

    m_instructions.push_back(Instruction("jmp eax", "\xff\xe0", 2));
    m_instructions.push_back(Instruction("jmp ebx", "\xff\xe3", 2));
    m_instructions.push_back(Instruction("jmp ecx", "\xff\xe1", 2));
    m_instructions.push_back(Instruction("jmp edx", "\xff\xe2", 2));
    m_instructions.push_back(Instruction("jmp esi", "\xff\xe6", 2));
    m_instructions.push_back(Instruction("jmp edi", "\xff\xe7", 2));

    m_instructions.push_back(Instruction("jmp [eax]", "\xff\x20", 2));
    m_instructions.push_back(Instruction("jmp [ebx]", "\xff\x23", 2));
    m_instructions.push_back(Instruction("jmp [ecx]", "\xff\x21", 2));
    m_instructions.push_back(Instruction("jmp [edx]", "\xff\x22", 2));
    m_instructions.push_back(Instruction("jmp [esi]", "\xff\x26", 2));
    m_instructions.push_back(Instruction("jmp [edi]", "\xff\x27", 2));

    m_instructions.push_back(Instruction("pushad ; ret", "\x60\xc3", 2));
    m_instructions.push_back(Instruction("popad ; ret", "\x61\xc3", 2));

    m_instructions.push_back(Instruction("push eax ; ret", "\x50\xc3", 2));
    m_instructions.push_back(Instruction("push ebx ; ret", "\x53\xc3", 2));
    m_instructions.push_back(Instruction("push ecx ; ret", "\x51\xc3", 2));
    m_instructions.push_back(Instruction("push edx ; ret", "\x52\xc3", 2));
    m_instructions.push_back(Instruction("push esi ; ret", "\x56\xc3", 2));
    m_instructions.push_back(Instruction("push edi ; ret", "\x57\xc3", 2));
    m_instructions.push_back(Instruction("push ebp ; ret", "\x55\xc3", 2));
    m_instructions.push_back(Instruction("push esp ; ret", "\x54\xc3", 2));

    m_instructions.push_back(Instruction("pop esp ; ret", "\x5c\xc3", 2));
    m_instructions.push_back(Instruction("pop ebp ; ret", "\x5d\xc3", 2));
    m_instructions.push_back(Instruction("pop eax ; ret", "\x58\xc3", 2));
    m_instructions.push_back(Instruction("pop ebx ; ret", "\x5b\xc3", 2));
    m_instructions.push_back(Instruction("pop ecx ; ret", "\x59\xc3", 2));
    m_instructions.push_back(Instruction("pop edx ; ret", "\x5a\xc3", 2));
    m_instructions.push_back(Instruction("pop esi ; ret", "\x5e\xc3", 2));
    m_instructions.push_back(Instruction("pop edi ; ret", "\x5f\xc3", 2));

    m_instructions.push_back(Instruction("pop ebx ; pop ebp ; ret", "\x5b\x5d\xc3", 3));
    m_instructions.push_back(Instruction("pop eax ; pop ebx ; pop esi ; pop edi ; ret", "\x58\x5b\x5e\x5f\xc3", 5));
    m_instructions.push_back(Instruction("pop ebx ; pop esi ; pop ebp ; ret", "\x5b\x5e\x5d\xc3", 4));
    m_instructions.push_back(Instruction("pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x5b\x5e\x5f\x5d\xc3", 5));
    m_instructions.push_back(Instruction("pop esi ; pop ebx ; pop edx ; ret", "\x5e\x5b\x5a\xc3", 4));
    m_instructions.push_back(Instruction("pop edx ; pop ecx ; pop ebx ; ret", "\x5a\x59\x5b\xc3", 4));

    m_instructions.push_back(Instruction("xor eax, eax ; ret", "\x31\xc0\xc3", 3));
    m_instructions.push_back(Instruction("xor ebx, ebx ; ret", "\x31\xdb\xc3", 3));
    m_instructions.push_back(Instruction("xor ecx, ecx ; ret", "\x31\xc9\xc3", 3));
    m_instructions.push_back(Instruction("xor edx, edx ; ret", "\x31\xd2\xc3", 3));
    m_instructions.push_back(Instruction("xor esi, esi ; ret", "\x31\xf6\xc3", 3));
    m_instructions.push_back(Instruction("xor edi, edi ; ret", "\x31\xf7\xc3", 3));

    m_instructions.push_back(Instruction("xor eax, eax ; pop ebx ; pop ebp ; ret", "\x31\xc0\x5b\x5d\xc3", 5));
    m_instructions.push_back(Instruction("xor eax, eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x31\xc0\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("xor eax, eax ; pop edi ; ret", "\x31\xc0\x5f\xc3", 4));
    m_instructions.push_back(Instruction("xor eax, eax ; pop ebx ; ret", "\x31\xc0\x5b\xc3", 4));
    m_instructions.push_back(Instruction("xor eax, eax ; mov ebp, esp ; pop ebp ; ret", "\x31\xc0\x89\xe5\x5d\xc3", 6));

    m_instructions.push_back(Instruction("inc eax ; ret", "\x40\xc3", 2));
    m_instructions.push_back(Instruction("inc ebx ; ret", "\x43\xc3", 2));
    m_instructions.push_back(Instruction("inc ecx ; ret", "\x41\xc3", 2));
    m_instructions.push_back(Instruction("inc edx ; ret", "\x42\xc3", 2));
    m_instructions.push_back(Instruction("inc esi ; ret", "\x46\xc3", 2));
    m_instructions.push_back(Instruction("inc edi ; ret", "\x47\xc3", 2));

    m_instructions.push_back(Instruction("dec eax ; ret", "\x48\xc3", 2));
    m_instructions.push_back(Instruction("dec ebx ; ret", "\x4b\xc3", 2));
    m_instructions.push_back(Instruction("dec ecx ; ret", "\x49\xc3", 2));
    m_instructions.push_back(Instruction("dec edx ; ret", "\x4a\xc3", 2));
    m_instructions.push_back(Instruction("dec esi ; ret", "\x4e\xc3", 2));
    m_instructions.push_back(Instruction("dec edi ; ret", "\x4f\xc3", 2));

    m_instructions.push_back(Instruction("inc eax ; pop edi ; pop esi ; ret", "\x40\x5f\x5e\xc3", 4));
    m_instructions.push_back(Instruction("inc eax ; pop edi ; ret", "\x40\x5f\xc3", 3));
    m_instructions.push_back(Instruction("inc eax ; inc eax ; inc eax ; ret", "\x40\x40\x40\xc3", 4));
    m_instructions.push_back(Instruction("inc eax ; inc eax ; ret", "\x40\x40\xc3", 3));

    m_instructions.push_back(Instruction("sub eax, 1 ; pop ebx ; pop esi ; pop ebp ; ret", "\x83\xe8\x01\x5b\x5e\x5d\xc3", 7));
    m_instructions.push_back(Instruction("sub eax, ebx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x29\xd8\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("sub eax, 1 ; pop ebp ; ret", "\x83\xe8\x01\x5d\xc3", 5));
    m_instructions.push_back(Instruction("add eax, ebx ; pop ebx ; pop ebp ; ret", "\x01\xd8\x5b\x5d\xc3", 5));

    m_instructions.push_back(Instruction("mul eax ; ret", "\xf7\xe0\xc3", 3));
    m_instructions.push_back(Instruction("mul ebx ; ret", "\xf7\xe3\xc3", 3));
    m_instructions.push_back(Instruction("mul ecx ; ret", "\xf7\xe1\xc3", 3));
    m_instructions.push_back(Instruction("mul edx ; ret", "\xf7\xe2\xc3", 3));
    m_instructions.push_back(Instruction("mul esi ; ret", "\xf7\xe6\xc3", 3));
    m_instructions.push_back(Instruction("mul edi ; ret", "\xf7\xe7\xc3", 3));

    m_instructions.push_back(Instruction("mul eax ; pop ebp ; ret", "\xf7\xe0\x5d\xc3", 3));
    m_instructions.push_back(Instruction("mul ebx ; pop ebp ; ret", "\xf7\xe3\x5d\xc3", 3));
    m_instructions.push_back(Instruction("mul ecx ; pop ebp ; ret", "\xf7\xe1\x5d\xc3", 3));
    m_instructions.push_back(Instruction("mul edx ; pop ebp ; ret", "\xf7\xe2\x5d\xc3", 3));
    m_instructions.push_back(Instruction("mul esi ; pop ebp ; ret", "\xf7\xe6\x5d\xc3", 3));
    m_instructions.push_back(Instruction("mul edi ; pop ebp ; ret", "\xf7\xe7\x5d\xc3", 3));

    m_instructions.push_back(Instruction("div eax ; ret", "\xf7\xf0\xc3", 3));
    m_instructions.push_back(Instruction("div ebx ; ret", "\xf7\xf3\xc3", 3));
    m_instructions.push_back(Instruction("div ecx ; ret", "\xf7\xf1\xc3", 3));
    m_instructions.push_back(Instruction("div edx ; ret", "\xf7\xf2\xc3", 3));
    m_instructions.push_back(Instruction("div esi ; ret", "\xf7\xf6\xc3", 3));
    m_instructions.push_back(Instruction("div edi ; ret", "\xf7\xf7\xc3", 3));

    m_instructions.push_back(Instruction("div eax ; pop ebp ; ret", "\xf7\xf0\x5d\xc3", 3));
    m_instructions.push_back(Instruction("div ebx ; pop ebp ; ret", "\xf7\xf3\x5d\xc3", 3));
    m_instructions.push_back(Instruction("div ecx ; pop ebp ; ret", "\xf7\xf1\x5d\xc3", 3));
    m_instructions.push_back(Instruction("div edx ; pop ebp ; ret", "\xf7\xf2\x5d\xc3", 3));
    m_instructions.push_back(Instruction("div esi ; pop ebp ; ret", "\xf7\xf6\x5d\xc3", 3));
    m_instructions.push_back(Instruction("div edi ; pop ebp ; ret", "\xf7\xf7\x5d\xc3", 3));

    m_instructions.push_back(Instruction("neg eax ; ret", "\xf7\xd8\xc3", 3));
    m_instructions.push_back(Instruction("neg ebx ; ret", "\xf7\xdb\xc3", 3));
    m_instructions.push_back(Instruction("neg ecx ; ret", "\xf7\xd9\xc3", 3));
    m_instructions.push_back(Instruction("neg edx ; ret", "\xf7\xda\xc3", 3));
    m_instructions.push_back(Instruction("neg esi ; ret", "\xf7\xde\xc3", 3));
    m_instructions.push_back(Instruction("neg edi ; ret", "\xf7\xdf\xc3", 3));

    m_instructions.push_back(Instruction("neg eax ; pop ebp ; ret", "\xf7\xd8\x5d\xc3", 3));
    m_instructions.push_back(Instruction("neg ebx ; pop ebp ; ret", "\xf7\xdb\x5d\xc3", 3));
    m_instructions.push_back(Instruction("neg ecx ; pop ebp ; ret", "\xf7\xd9\x5d\xc3", 3));
    m_instructions.push_back(Instruction("neg edx ; pop ebp ; ret", "\xf7\xda\x5d\xc3", 3));
    m_instructions.push_back(Instruction("neg esi ; pop ebp ; ret", "\xf7\xde\x5d\xc3", 3));
    m_instructions.push_back(Instruction("neg edi ; pop ebp ; ret", "\xf7\xdf\x5d\xc3", 3));

    m_instructions.push_back(Instruction("not eax ; ret", "\xf7\xd0\xc3", 3));
    m_instructions.push_back(Instruction("not ebx ; ret", "\xf7\xd3\xc3", 3));
    m_instructions.push_back(Instruction("not ecx ; ret", "\xf7\xd1\xc3", 3));
    m_instructions.push_back(Instruction("not edx ; ret", "\xf7\xd2\xc3", 3));
    m_instructions.push_back(Instruction("not esi ; ret", "\xf7\xd6\xc3", 3));
    m_instructions.push_back(Instruction("not edi ; ret", "\xf7\xd7\xc3", 3));

    m_instructions.push_back(Instruction("not eax ; pop ebp ; ret", "\xf7\xd0\x5d\xc3", 3));
    m_instructions.push_back(Instruction("not ebx ; pop ebp ; ret", "\xf7\xd3\x5d\xc3", 3));
    m_instructions.push_back(Instruction("not ecx ; pop ebp ; ret", "\xf7\xd1\x5d\xc3", 3));
    m_instructions.push_back(Instruction("not edx ; pop ebp ; ret", "\xf7\xd2\x5d\xc3", 3));
    m_instructions.push_back(Instruction("not esi ; pop ebp ; ret", "\xf7\xd6\x5d\xc3", 3));
    m_instructions.push_back(Instruction("not edi ; pop ebp ; ret", "\xf7\xd7\x5d\xc3", 3));

    m_instructions.push_back(Instruction("shr eax, 1 ; ret", "\xd1\xe8\xc3", 3));
    m_instructions.push_back(Instruction("shr ebx, 1 ; ret", "\xd1\xeb\xc3", 3));
    m_instructions.push_back(Instruction("shr ecx, 1 ; ret", "\xd1\xe9\xc3", 3));
    m_instructions.push_back(Instruction("shr edx, 1 ; ret", "\xd1\xea\xc3", 3));
    m_instructions.push_back(Instruction("shr esi, 1 ; ret", "\xd1\xee\xc3", 3));
    m_instructions.push_back(Instruction("shr edi, 1 ; ret", "\xd1\xef\xc3", 3));

    m_instructions.push_back(Instruction("shl eax, 1 ; ret", "\xd1\xe0\xc3", 3));
    m_instructions.push_back(Instruction("shl ebx, 1 ; ret", "\xd1\xe3\xc3", 3));
    m_instructions.push_back(Instruction("shl ecx, 1 ; ret", "\xd1\xe1\xc3", 3));
    m_instructions.push_back(Instruction("shl edx, 1 ; ret", "\xd1\xe2\xc3", 3));
    m_instructions.push_back(Instruction("shl esi, 1 ; ret", "\xd1\xe6\xc3", 3));
    m_instructions.push_back(Instruction("shl edi, 1 ; ret", "\xd1\xe7\xc3", 3));

    m_instructions.push_back(Instruction("ror eax, 1 ; ret", "\xd1\xc8\xc3", 3));
    m_instructions.push_back(Instruction("ror ebx, 1 ; ret", "\xd1\xcb\xc3", 3));
    m_instructions.push_back(Instruction("ror ecx, 1 ; ret", "\xd1\xc9\xc3", 3));
    m_instructions.push_back(Instruction("ror edx, 1 ; ret", "\xd1\xca\xc3", 3));
    m_instructions.push_back(Instruction("ror esi, 1 ; ret", "\xd1\xce\xc3", 3));
    m_instructions.push_back(Instruction("ror edi, 1 ; ret", "\xd1\xcf\xc3", 3));
    m_instructions.push_back(Instruction("rol eax, 1 ; ret", "\xd1\xc0\xc3", 3));
    m_instructions.push_back(Instruction("rol ebx, 1 ; ret", "\xd1\xc3\xc3", 3));
    m_instructions.push_back(Instruction("rol ecx, 1 ; ret", "\xd1\xc1\xc3", 3));
    m_instructions.push_back(Instruction("rol edx, 1 ; ret", "\xd1\xc2\xc3", 3));
    m_instructions.push_back(Instruction("rol esi, 1 ; ret", "\xd1\xc6\xc3", 3));
    m_instructions.push_back(Instruction("rol edi, 1 ; ret", "\xd1\xc7\xc3", 3));

    m_instructions.push_back(Instruction("xchg eax, esp ; ret", "\x94\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, ebx ; ret", "\x93\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, ecx ; ret", "\x91\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, edx ; ret", "\x92\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, esi ; ret", "\x96\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, edi ; ret", "\x97\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, ebp ; ret", "\x95\xc3", 2));

    m_instructions.push_back(Instruction("xchg eax, esp ; pop ebp ; ret", "\x94\x5d\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, ebx ; pop ebp ; ret", "\x93\x5d\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, ecx ; pop ebp ; ret", "\x91\x5d\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, edx ; pop ebp ; ret", "\x92\x5d\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, esi ; pop ebp ; ret", "\x96\x5d\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, edi ; pop ebp ; ret", "\x97\x5d\xc3", 2));
    m_instructions.push_back(Instruction("xchg eax, ebp ; pop ebp ; ret", "\x95\x5d\xc3", 2));

    m_instructions.push_back(Instruction("bswap eax ; ret", "\x0f\xc8\xc3", 3));
    m_instructions.push_back(Instruction("bswap ebx ; ret", "\x0f\xcb\xc3", 3));
    m_instructions.push_back(Instruction("bswap ecx ; ret", "\x0f\xc9\xc3", 3));
    m_instructions.push_back(Instruction("bswap edx ; ret", "\x0f\xca\xc3", 3));
    m_instructions.push_back(Instruction("bswap esi ; ret", "\x0f\xce\xc3", 3));
    m_instructions.push_back(Instruction("bswap edi ; ret", "\x0f\xcf\xc3", 3));

    m_instructions.push_back(Instruction("bswap eax ; pop ebp ; ret", "\x0f\xc8\x5d\xc3", 3));
    m_instructions.push_back(Instruction("bswap ebx ; pop ebp ; ret", "\x0f\xcb\x5d\xc3", 3));
    m_instructions.push_back(Instruction("bswap ecx ; pop ebp ; ret", "\x0f\xc9\x5d\xc3", 3));
    m_instructions.push_back(Instruction("bswap edx ; pop ebp ; ret", "\x0f\xca\x5d\xc3", 3));
    m_instructions.push_back(Instruction("bswap esi ; pop ebp ; ret", "\x0f\xce\x5d\xc3", 3));
    m_instructions.push_back(Instruction("bswap edi ; pop ebp ; ret", "\x0f\xcf\x5d\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, ebx ; pop ebx ; pop ebp ; ret", "\x89\xd8\x5b\x5d\xc3", 5));
    m_instructions.push_back(Instruction("mov eax, edx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xd0\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov eax, edi ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xf8\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov eax, ebx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xd8\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov eax, esi ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xf0\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov eax, ecx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xc8\x5b\x5e\x5f\x5d\xc3", 7));

    m_instructions.push_back(Instruction("mov eax, ebx ; pop ebx ; pop esi ; pop ebp ; ret", "\x89\xd8\x5b\x5e\x5d\xc3", 6));
    m_instructions.push_back(Instruction("mov esp, ebp ; pop ebp ; ret", "\x89\xec\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, esp ; ret", "\x89\xe0\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, esp ; ret", "\x89\xe3\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, esp ; ret", "\x89\xe1\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, esp ; ret", "\x89\xe2\xc3", 3));
    m_instructions.push_back(Instruction("mov ebp, esp ; ret", "\x89\xe5\xc3", 3));

    m_instructions.push_back(Instruction("mov ebx, eax ; ret", "\x89\xc3\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, eax ; ret", "\x89\xc1\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, eax ; ret", "\x89\xc2\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, eax ; ret", "\x89\xc6\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, eax ; ret", "\x89\xc7\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, ebx ; ret", "\x89\xd8\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, ebx ; ret", "\x89\xd9\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, ebx ; ret", "\x89\xda\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, ebx ; ret", "\x89\xde\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, ebx ; ret", "\x89\xdf\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, ecx ; ret", "\x89\xc8\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, ecx ; ret", "\x89\xcb\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, ecx ; ret", "\x89\xca\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, ecx ; ret", "\x89\xce\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, ecx ; ret", "\x89\xcf\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, edx ; ret", "\x89\xd0\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, edx ; ret", "\x89\xd3\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, edx ; ret", "\x89\xd1\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, edx ; ret", "\x89\xd6\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, edx ; ret", "\x89\xd7\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, esi ; ret", "\x89\xf0\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, esi ; ret", "\x89\xf3\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, esi ; ret", "\x89\xf1\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, esi ; ret", "\x89\xf2\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, esi ; ret", "\x89\xf7\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, edi ; ret", "\x89\xf8\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, edi ; ret", "\x89\xfb\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, edi ; ret", "\x89\xf9\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, edi ; ret", "\x89\xfa\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, edi ; ret", "\x89\xfe\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, esp ; pop ebp ; ret", "\x89\xe0\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, esp ; pop ebp ; ret", "\x89\xe3\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, esp ; pop ebp ; ret", "\x89\xe1\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, esp ; pop ebp ; ret", "\x89\xe2\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov ebx, eax ; pop ebp ; ret", "\x89\xc3\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, eax ; pop ebp ; ret", "\x89\xc1\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, eax ; pop ebp ; ret", "\x89\xc2\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, eax ; pop ebp ; ret", "\x89\xc6\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, eax ; pop ebp ; ret", "\x89\xc7\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, ebx ; pop ebp ; ret", "\x89\xd8\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, ebx ; pop ebp ; ret", "\x89\xd9\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, ebx ; pop ebp ; ret", "\x89\xda\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, ebx ; pop ebp ; ret", "\x89\xde\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, ebx ; pop ebp ; ret", "\x89\xdf\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, ecx ; pop ebp ; ret", "\x89\xc8\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, ecx ; pop ebp ; ret", "\x89\xcb\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, ecx ; pop ebp ; ret", "\x89\xca\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, ecx ; pop ebp ; ret", "\x89\xce\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, ecx ; pop ebp ; ret", "\x89\xcf\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, edx ; pop ebp ; ret", "\x89\xd0\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, edx ; pop ebp ; ret", "\x89\xd3\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, edx ; pop ebp ; ret", "\x89\xd1\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, edx ; pop ebp ; ret", "\x89\xd6\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, edx ; pop ebp ; ret", "\x89\xd7\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, esi ; pop ebp ; ret", "\x89\xf0\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, esi ; pop ebp ; ret", "\x89\xf3\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, esi ; pop ebp ; ret", "\x89\xf1\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, esi ; pop ebp ; ret", "\x89\xf2\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, esi ; pop ebp ; ret", "\x89\xf7\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, edi ; pop ebp ; ret", "\x89\xf8\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, edi ; pop ebp ; ret", "\x89\xfb\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, edi ; pop ebp ; ret", "\x89\xf9\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, edi ; pop ebp ; ret", "\x89\xfa\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, edi ; pop ebp ; ret", "\x89\xfe\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov ebx, [eax] ; ret", "\x8b\x18\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, [eax] ; ret", "\x8b\x08\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, [eax] ; ret", "\x8b\x10\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, [eax] ; ret", "\x8b\x30\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, [eax] ; ret", "\x8b\x38\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, [ebx] ; ret", "\x8b\x03\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, [ebx] ; ret", "\x8b\x1b\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, [ebx] ; ret", "\x8b\x0b\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, [ebx] ; ret", "\x8b\x13\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, [ebx] ; ret", "\x8b\x33\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, [ebx] ; ret", "\x8b\x3b\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, [ecx] ; ret", "\x8b\x01\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, [ecx] ; ret", "\x8b\x19\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, [ecx] ; ret", "\x8b\x09\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, [ecx] ; ret", "\x8b\x11\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, [ecx] ; ret", "\x8b\x31\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, [ecx] ; ret", "\x8b\x39\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, [edx] ; ret", "\x8b\x02\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, [edx] ; ret", "\x8b\x1a\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, [edx] ; ret", "\x8b\x0a\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, [edx] ; ret", "\x8b\x12\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, [edx] ; ret", "\x8b\x32\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, [edx] ; ret", "\x8b\x3a\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, [esi] ; ret", "\x8b\x06\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, [esi] ; ret", "\x8b\x1e\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, [esi] ; ret", "\x8b\x0e\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, [esi] ; ret", "\x8b\x16\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, [esi] ; ret", "\x8b\x36\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, [esi] ; ret", "\x8b\x3e\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, [edi] ; ret", "\x8b\x07\xc3", 3));
    m_instructions.push_back(Instruction("mov ebx, [edi] ; ret", "\x8b\x1f\xc3", 3));
    m_instructions.push_back(Instruction("mov ecx, [edi] ; ret", "\x8b\x0f\xc3", 3));
    m_instructions.push_back(Instruction("mov edx, [edi] ; ret", "\x8b\x17\xc3", 3));
    m_instructions.push_back(Instruction("mov esi, [edi] ; ret", "\x8b\x37\xc3", 3));
    m_instructions.push_back(Instruction("mov edi, [edi] ; ret", "\x8b\x3f\xc3", 3));

    m_instructions.push_back(Instruction("mov ebx, [eax] ; pop ebp ; ret", "\x8b\x18\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [eax] ; pop ebp ; ret", "\x8b\x08\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [eax] ; pop ebp ; ret", "\x8b\x10\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [eax] ; pop ebp ; ret", "\x8b\x30\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [eax] ; pop ebp ; ret", "\x8b\x38\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, [ebx] ; pop ebp ; ret", "\x8b\x03\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, [ebx] ; pop ebp ; ret", "\x8b\x1b\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [ebx] ; pop ebp ; ret", "\x8b\x0b\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [ebx] ; pop ebp ; ret", "\x8b\x13\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [ebx] ; pop ebp ; ret", "\x8b\x33\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [ebx] ; pop ebp ; ret", "\x8b\x3b\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, [ecx] ; pop ebp ; ret", "\x8b\x01\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, [ecx] ; pop ebp ; ret", "\x8b\x19\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [ecx] ; pop ebp ; ret", "\x8b\x09\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [ecx] ; pop ebp ; ret", "\x8b\x11\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [ecx] ; pop ebp ; ret", "\x8b\x31\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [ecx] ; pop ebp ; ret", "\x8b\x39\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, [edx] ; pop ebp ; ret", "\x8b\x02\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, [edx] ; pop ebp ; ret", "\x8b\x1a\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [edx] ; pop ebp ; ret", "\x8b\x0a\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [edx] ; pop ebp ; ret", "\x8b\x12\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [edx] ; pop ebp ; ret", "\x8b\x32\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [edx] ; pop ebp ; ret", "\x8b\x3a\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, [esi] ; pop ebp ; ret", "\x8b\x06\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, [esi] ; pop ebp ; ret", "\x8b\x1e\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [esi] ; pop ebp ; ret", "\x8b\x0e\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [esi] ; pop ebp ; ret", "\x8b\x16\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [esi] ; pop ebp ; ret", "\x8b\x36\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [esi] ; pop ebp ; ret", "\x8b\x3e\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, [edi] ; pop ebp ; ret", "\x8b\x07\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, [edi] ; pop ebp ; ret", "\x8b\x1f\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [edi] ; pop ebp ; ret", "\x8b\x0f\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [edi] ; pop ebp ; ret", "\x8b\x17\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [edi] ; pop ebp ; ret", "\x8b\x37\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [edi] ; pop ebp ; ret", "\x8b\x3f\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov [edx], eax ; ret", "\x89\x02\xc3", 3));
    m_instructions.push_back(Instruction("mov [ebx], eax ; ret", "\x89\x03\xc3", 3));
    m_instructions.push_back(Instruction("mov [ecx], eax ; ret", "\x89\x01\xc3", 3));
    m_instructions.push_back(Instruction("mov [esi], eax ; ret", "\x89\x06\xc3", 3));
    m_instructions.push_back(Instruction("mov [edi], eax ; ret", "\x89\x07\xc3", 3));

    m_instructions.push_back(Instruction("mov [eax], ebx ; ret", "\x89\x18\xc3", 3));
    m_instructions.push_back(Instruction("mov [ecx], ebx ; ret", "\x89\x19\xc3", 3));
    m_instructions.push_back(Instruction("mov [edx], ebx ; ret", "\x89\x1a\xc3", 3));
    m_instructions.push_back(Instruction("mov [esi], ebx ; ret", "\x89\x1e\xc3", 3));
    m_instructions.push_back(Instruction("mov [edi], ebx ; ret", "\x89\x1f\xc3", 3));

    m_instructions.push_back(Instruction("mov [eax], ecx ; ret", "\x89\x08\xc3", 3));
    m_instructions.push_back(Instruction("mov [ebx], ecx ; ret", "\x89\x0b\xc3", 3));
    m_instructions.push_back(Instruction("mov [edx], ecx ; ret", "\x89\x0a\xc3", 3));
    m_instructions.push_back(Instruction("mov [esi], ecx ; ret", "\x89\x0e\xc3", 3));
    m_instructions.push_back(Instruction("mov [edi], ecx ; ret", "\x89\x0f\xc3", 3));

    m_instructions.push_back(Instruction("mov [eax], edx ; ret", "\x89\x10\xc3", 3));
    m_instructions.push_back(Instruction("mov [ebx], edx ; ret", "\x89\x13\xc3", 3));
    m_instructions.push_back(Instruction("mov [ecx], edx ; ret", "\x89\x11\xc3", 3));
    m_instructions.push_back(Instruction("mov [esi], edx ; ret", "\x89\x16\xc3", 3));
    m_instructions.push_back(Instruction("mov [edi], edx ; ret", "\x89\x17\xc3", 3));

    m_instructions.push_back(Instruction("mov eax, [esp] ; ret", "\x8b\x04\x24\xc3", 4));
    m_instructions.push_back(Instruction("mov ebx, [esp] ; ret", "\x8b\x1c\x24\xc3", 4));
    m_instructions.push_back(Instruction("mov ecx, [esp] ; ret", "\x8b\x0c\x24\xc3", 4));
    m_instructions.push_back(Instruction("mov edx, [esp] ; ret", "\x8b\x14\x24\xc3", 4));
    m_instructions.push_back(Instruction("mov esi, [esp] ; ret", "\x8b\x34\x24\xc3", 4));
    m_instructions.push_back(Instruction("mov edi, [esp] ; ret", "\x8b\x3c\x24\xc3", 4));
    m_instructions.push_back(Instruction("mov ebp, [esp] ; ret", "\x8b\x2c\x24\xc3", 4));

    m_instructions.push_back(Instruction("mov [edx], eax ; pop ebp ; ret", "\x89\x02\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [ebx], eax ; pop ebp ; ret", "\x89\x03\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [ecx], eax ; pop ebp ; ret", "\x89\x01\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [esi], eax ; pop ebp ; ret", "\x89\x06\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [edi], eax ; pop ebp ; ret", "\x89\x07\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov [eax], ebx ; pop ebp ; ret", "\x89\x18\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [ecx], ebx ; pop ebp ; ret", "\x89\x19\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [edx], ebx ; pop ebp ; ret", "\x89\x1a\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [esi], ebx ; pop ebp ; ret", "\x89\x1e\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [edi], ebx ; pop ebp ; ret", "\x89\x1f\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov [eax], ecx ; pop ebp ; ret", "\x89\x08\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [ebx], ecx ; pop ebp ; ret", "\x89\x0b\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [edx], ecx ; pop ebp ; ret", "\x89\x0a\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [esi], ecx ; pop ebp ; ret", "\x89\x0e\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [edi], ecx ; pop ebp ; ret", "\x89\x0f\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov [eax], edx ; pop ebp ; ret", "\x89\x10\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [ebx], edx ; pop ebp ; ret", "\x89\x13\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [ecx], edx ; pop ebp ; ret", "\x89\x11\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [esi], edx ; pop ebp ; ret", "\x89\x16\x5d\xc3", 4));
    m_instructions.push_back(Instruction("mov [edi], edx ; pop ebp ; ret", "\x89\x17\x5d\xc3", 4));

    m_instructions.push_back(Instruction("mov eax, edx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xd0\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov edi, eax ; mov eax, edi ; pop edi ; pop ebp ; ret", "\x89\xc7\x89\xf8\x5f\x5d\xc3", 7));
    
    m_instructions.push_back(Instruction("add eax, [edx] ; mov ebx, [esp] ; mov esp, ebp ; pop ebp ; ret", "\x03\x02\x8b\x1c\x24\x89\xec\x5d\xc3", 9));
    m_instructions.push_back(Instruction("mov [edi], eax ; pop eax ; pop ebx ; pop esi ; pop edi ; ret", "\x89\x07\x58\x5b\x5e\x5f\xc3", 7));
    m_instructions.push_back(Instruction("mov [edi], ebx ; pop ebx ; pop esi ; pop edi ; ret", "\x89\x1f\x5b\x5e\x5f\xc3", 6));
    m_instructions.push_back(Instruction("mov [ecx], eax ; mov eax, ebx ; pop ebx ; pop ebp ; ret", "\x89\x01\x89\xd8\x5b\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov eax, ebp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret", "\x89\xe8\x5b\x5e\x5f\x5d\xc3", 7));
    m_instructions.push_back(Instruction("mov eax, ebx ; pop ebx ; pop esi ; pop edi ; ret", "\x89\xd8\x5b\x5e\x5f\xc3", 6));
    m_instructions.push_back(Instruction("mov eax, edi ; pop ebx ; pop esi ; pop edi ; ret", "\x89\xf8\x5b\x5e\x5f\xc3", 6));
    m_instructions.push_back(Instruction("mov eax, ebx ; pop ebx ; ret", "\x89\xd8\x5b\xc3", 4));
}

Ia32::~Ia32(void)
{
}

std::string Ia32::get_class_name(void) const
{
    return std::string("Ia32");
}