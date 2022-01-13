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
 *      0f00h
 * ==================================================================== */
void __bea_callspec__ G6_(PDISASM pMyDisasm)
{
    Int32 OperandSizeOld = 0;

    if (GV.VEX.state == InUsePrefix) {
      failDecode(pMyDisasm);
      return;
    }

    pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
    OperandSizeOld = GV.OperandSize;
    GV.OperandSize = 16;
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;

    if (GV.REGOPCODE == 0) {
        if ((OperandSizeOld == 64) && (GV.MOD_== 0x3)) {
            GV.OperandSize = OperandSizeOld;
        }
        else {
            GV.MemDecoration = Arg1word;
        }
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sldt");
        #endif
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = MEMORY_MANAGEMENT_REG;
        pMyDisasm->Operand2.Registers.mem_management = REG1;
        pMyDisasm->Operand2.OpSize = 32;
        GV.OperandSize = OperandSizeOld;
        GV.EIP_+= GV.DECALAGE_EIP+2;
    }
    else if (GV.REGOPCODE == 1) {
        if ((OperandSizeOld == 64) && (GV.MOD_== 0x3)) {
            GV.OperandSize = OperandSizeOld;
        }
        else {
            GV.MemDecoration = Arg1word;
        }
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "str");
        #endif
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = MEMORY_MANAGEMENT_REG;
        pMyDisasm->Operand2.Registers.mem_management = REG3;
        pMyDisasm->Operand2.OpSize = 16;
        GV.OperandSize = OperandSizeOld;
        GV.EIP_+= GV.DECALAGE_EIP+2;
    }
    else if (GV.REGOPCODE == 2) {
        GV.MemDecoration = Arg2word;
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "lldt");
        #endif
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = MEMORY_MANAGEMENT_REG;
        pMyDisasm->Operand1.Registers.mem_management = REG1;
        pMyDisasm->Operand1.OpSize = 16;
        GV.OperandSize = OperandSizeOld;
        GV.EIP_+= GV.DECALAGE_EIP+2;
    }
    else if (GV.REGOPCODE == 3) {
        GV.MemDecoration = Arg2word;
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ltr");
        #endif
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = MEMORY_MANAGEMENT_REG;
        pMyDisasm->Operand1.Registers.mem_management = REG3;
        pMyDisasm->Operand1.OpSize = 16;
        GV.OperandSize = OperandSizeOld;
        GV.EIP_+= GV.DECALAGE_EIP+2;
    }
    else if (GV.REGOPCODE == 4) {
        GV.MemDecoration = Arg1word;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "verr");
        #endif
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand2.Registers.special = REG0;
        pMyDisasm->Operand2.OpSize = 16;
        GV.OperandSize = OperandSizeOld;
        GV.EIP_+= GV.DECALAGE_EIP+2;
    }
    else if (GV.REGOPCODE == 5) {
        GV.MemDecoration = Arg1word;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "verw");
        #endif
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand2.Registers.special = REG0;
        pMyDisasm->Operand2.OpSize = 16;
        GV.OperandSize = OperandSizeOld;
        GV.EIP_+= GV.DECALAGE_EIP+2;
    }
    else if (GV.REGOPCODE == 6) {
        failDecode(pMyDisasm);
        GV.OperandSize = OperandSizeOld;
    }
    else {
        failDecode(pMyDisasm);
        GV.OperandSize = OperandSizeOld;
    }
}
