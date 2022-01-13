/* Copyright 2006-2020, BeatriX
 * File coded by BeatriX
 *
 * This file is part of BeaEngine.
 *
 *    BeaEngine is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU Lesser General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    BeaEngine is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public License
 *    along with BeaEngine.  If not, see <http://www.gnu.org/licenses/>. */

/* ====================================================================
 *      0ffh
 * ==================================================================== */
void __bea_callspec__ G5_Ev(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    switch (GV.REGOPCODE) {
    case 0:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "inc");
        #endif
        Ev(pMyDisasm);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        if ((pMyDisasm->Prefix.LockPrefix == InUsePrefix) && (GV.MOD_ == 0x3)) {
            GV.ERROR_OPCODE = UD_;
        }
        FillFlags(pMyDisasm, 40);
    break;
    case 1:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "dec");
        #endif
        Ev(pMyDisasm);
        if ((pMyDisasm->Prefix.LockPrefix == InUsePrefix) && (GV.MOD_ == 0x3)) {
            GV.ERROR_OPCODE = UD_;
        }
        FillFlags(pMyDisasm, 30);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+CONTROL_TRANSFER;
        pMyDisasm->Instruction.BranchType = CallType;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "call");
        #endif
        if (GV.Architecture == 64) {
            GV.OperandSize = 64;
        }
        if (GV.OperandSize == 64) {
            GV.MemDecoration = Arg1qword;
        }
        else if (GV.OperandSize == 32) {
            GV.MemDecoration = Arg1dword;
        }
        else {
            GV.MemDecoration = Arg1word;
        }
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        GV.EIP_ += GV.DECALAGE_EIP+2;
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.gpr = REG4;
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+CONTROL_TRANSFER;
        pMyDisasm->Instruction.BranchType = CallType;
        if (GV.SYNTAX_ == ATSyntax) {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy (pMyDisasm->Instruction.Mnemonic, "lcall");
            #endif
        }
        else {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy (pMyDisasm->Instruction.Mnemonic, "call far");
            #endif
        }
        GV.MemDecoration = Arg1fword;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        GV.EIP_ += GV.DECALAGE_EIP+2;
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.gpr = REG4;
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+CONTROL_TRANSFER;
        pMyDisasm->Instruction.BranchType = JmpType;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "jmp");
        #endif
        if (GV.Architecture == 64) {
            GV.OperandSize = 64;
        }
        if (GV.OperandSize == 64) {
            GV.MemDecoration = Arg1qword;
        }
        else if (GV.OperandSize == 32) {
            GV.MemDecoration = Arg1dword;
        }
        else {
            GV.MemDecoration = Arg1word;
        }
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        GV.EIP_ += GV.DECALAGE_EIP+2;
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+CONTROL_TRANSFER;
        pMyDisasm->Instruction.BranchType = JmpType;
        if (GV.SYNTAX_ == ATSyntax) {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ljmp");
            #endif
        }
        else {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy (pMyDisasm->Instruction.Mnemonic, "jmp far");
            #endif
        }
        GV.MemDecoration = Arg1fword;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        GV.EIP_ += GV.DECALAGE_EIP+2;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+DATA_TRANSFER;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "push");
        #endif
        if (GV.Architecture == 64) {
            GV.OperandSize = 64;
        }
        if (GV.OperandSize == 64) {
            GV.MemDecoration = Arg2qword;
        }
        else if (GV.OperandSize == 32) {
            GV.MemDecoration = Arg2dword;
        }
        else {
            GV.MemDecoration = Arg2word;
        }
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        GV.EIP_ += GV.DECALAGE_EIP+2;
        pMyDisasm->Operand1.OpType = MEMORY_TYPE;
        pMyDisasm->Operand1.OpSize = GV.OperandSize;
        pMyDisasm->Operand1.Memory.BaseRegister = REG4;
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.gpr = REG4;
    break;
    default:
        failDecode(pMyDisasm);
    }
}
