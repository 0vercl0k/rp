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
 *      0c0h
 * ==================================================================== */
void __bea_callspec__ G2_EbIb(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    EbIb(pMyDisasm);
    switch(GV.REGOPCODE) {
    case 0:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rol");
        #endif
        FillFlags(pMyDisasm, 88);
        break;
    case 1:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ror");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcl");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcr");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shl");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shr");
        #endif
        FillFlags(pMyDisasm, 92);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sal");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sar");
        #endif
        FillFlags(pMyDisasm, 92);
      }
}


/* ====================================================================
 *      0c1h
 * ==================================================================== */
void __bea_callspec__ G2_EvIb(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    EvIb(pMyDisasm);
    switch(GV.REGOPCODE) {
    case 0:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rol");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 1:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ror");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcl");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcr");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shl");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shr");
        #endif
        FillFlags(pMyDisasm, 92);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sal");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sar");
        #endif
        FillFlags(pMyDisasm, 92);
      }
}

/* ====================================================================
 *      0d0h
 * ==================================================================== */
void __bea_callspec__ G2_Eb1(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    GV.MemDecoration = Arg1byte;
    GV.OperandSize = 8;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.OperandSize = 32;
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy (pMyDisasm->Operand2.OpMnemonic, "1");
    #endif
    pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
    pMyDisasm->Operand2.OpSize = 8;
    pMyDisasm->Instruction.Immediat = 1;
    switch(GV.REGOPCODE) {
    case 0:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rol");
        #endif
        FillFlags(pMyDisasm, 87);
    break;
    case 1:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ror");
        #endif
        FillFlags(pMyDisasm, 87);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcl");
        #endif
        FillFlags(pMyDisasm, 80);
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcr");
        #endif
        FillFlags(pMyDisasm, 80);
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shl");
        #endif
        FillFlags(pMyDisasm, 91);
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shr");
        #endif
        FillFlags(pMyDisasm, 91);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sal");
        #endif
        FillFlags(pMyDisasm, 91);
    break;
    case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sar");
        #endif
        FillFlags(pMyDisasm, 91);
    }
    GV.EIP_ += GV.DECALAGE_EIP+2;
}


/* ====================================================================
 *      0d1h
 * ==================================================================== */
void __bea_callspec__ G2_Ev1(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
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
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy (pMyDisasm->Operand2.OpMnemonic, "1");
    #endif
    pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
    pMyDisasm->Operand2.OpSize = 8;
    pMyDisasm->Instruction.Immediat = 1;
    switch(GV.REGOPCODE) {
    case 0:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rol");
        #endif
        FillFlags(pMyDisasm, 87);
    break;
    case 1:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ror");
        #endif
        FillFlags(pMyDisasm, 87);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcl");
        #endif
        FillFlags(pMyDisasm, 80);
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcr");
        #endif
        FillFlags(pMyDisasm, 80);
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shl");
        #endif
        FillFlags(pMyDisasm, 91);
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shr");
        #endif
        FillFlags(pMyDisasm, 91);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sal");
        #endif
        FillFlags(pMyDisasm, 91);
    break;
    case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sar");
        #endif
        FillFlags(pMyDisasm, 91);
    }
    GV.EIP_ += GV.DECALAGE_EIP+2;
}


/* ====================================================================
 *      0d2h
 * ==================================================================== */
void __bea_callspec__ G2_EbCL(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    GV.MemDecoration = Arg1byte;
    GV.OperandSize = 8;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.OperandSize = 32;
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy (pMyDisasm->Operand2.OpMnemonic, Registers8Bits[1]);
    #endif
    pMyDisasm->Operand2.OpType = REGISTER_TYPE;
    pMyDisasm->Operand2.Registers.type = GENERAL_REG;
    pMyDisasm->Operand2.Registers.gpr = REG1;
    pMyDisasm->Operand2.OpSize = 8;
    switch(GV.REGOPCODE) {
    case 0:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rol");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 1:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ror");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcl");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcr");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shl");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shr");
        #endif
        FillFlags(pMyDisasm, 92);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sal");
        #endif
      FillFlags(pMyDisasm, 92);
    break;
    case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sar");
        #endif
        FillFlags(pMyDisasm, 92);
    }
    GV.EIP_ += GV.DECALAGE_EIP+2;
}


/* ====================================================================
 *      0d3h
 * ==================================================================== */
void __bea_callspec__ G2_EvCL(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
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
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy (pMyDisasm->Operand2.OpMnemonic, Registers8Bits[1]);
    #endif
    pMyDisasm->Operand2.OpType = REGISTER_TYPE;
    pMyDisasm->Operand2.Registers.type = GENERAL_REG;
    pMyDisasm->Operand2.Registers.gpr = REG1;
    pMyDisasm->Operand2.OpSize = 8;
    switch(GV.REGOPCODE) {
    case 0:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rol");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 1:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ror");
        #endif
        FillFlags(pMyDisasm, 88);
    break;
    case 2:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcl");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 3:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rcr");
        #endif
        FillFlags(pMyDisasm, 81);
    break;
    case 4:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shl");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 5:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "shr");
        #endif
        FillFlags(pMyDisasm, 92);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
    break;
    case 6:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sal");
        #endif
        FillFlags(pMyDisasm, 92);
    break;
    case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+SHIFT_ROTATE;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sar");
        #endif
        FillFlags(pMyDisasm, 92);
    }
    GV.EIP_ += GV.DECALAGE_EIP+2;
}
