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
 *      0fc7h
 * ==================================================================== */
void __bea_callspec__ G9_(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
    GV.RM_  = (*((UInt8*) (GV.EIP_+1))) & 0x7;
    if (GV.REGOPCODE == 1) {
        if (GV.MOD_ == 0x3) { failDecode(pMyDisasm); return; }
        GV.MemDecoration = Arg2qword;
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        if (GV.REX.W_ == 1) {
            GV.MemDecoration = Arg2dqword;
            pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+DATA_TRANSFER;
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy (pMyDisasm->Instruction.Mnemonic, "cmpxchg16b");
            #endif
            pMyDisasm->Operand1.OpType = REGISTER_TYPE;
            pMyDisasm->Operand1.Registers.type = GENERAL_REG;
            pMyDisasm->Operand1.Registers.gpr = REG0+REG2;
            pMyDisasm->Operand1.OpSize = 128;
            pMyDisasm->Operand1.AccessMode = READ + WRITE;

            FillFlags(pMyDisasm, 23);
            GV.EIP_ += GV.DECALAGE_EIP+2;
        }
        else {
            pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+DATA_TRANSFER;
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy (pMyDisasm->Instruction.Mnemonic, "cmpxchg8b");
            #endif
            pMyDisasm->Operand1.OpType = REGISTER_TYPE;
            pMyDisasm->Operand1.Registers.type = GENERAL_REG;
            pMyDisasm->Operand1.Registers.gpr = REG0+REG2;
            pMyDisasm->Operand1.OpSize = 64;
            pMyDisasm->Operand1.AccessMode = READ + WRITE;

            FillFlags(pMyDisasm, 23);
            GV.EIP_ += GV.DECALAGE_EIP+2;
        }
    }
    else if (GV.REGOPCODE == 6) {
        if (GV.MOD_ == 0x3) {
          if (GV.PrefRepe == 1) {
              pMyDisasm->Instruction.Category = UINTR_INSTRUCTION;
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy (pMyDisasm->Instruction.Mnemonic, "senduipi");
              #endif
              GV.Register_ = 0;
              GV.OperandSize = 64;
              decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
              GV.EIP_ += GV.DECALAGE_EIP+2;
          }
          else {
            failDecode(pMyDisasm);
          }
        }
        else {
          GV.MemDecoration = Arg2qword;
          decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
          pMyDisasm->Instruction.Category = VM_INSTRUCTION;
          if (GV.OperandSize == 16) {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmclear");
              #endif
          }
          else if (GV.PrefRepe == 1) {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmxon");
              #endif
          }
          else {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmptrld");
              #endif
          }
          GV.EIP_ += GV.DECALAGE_EIP+2;
        }
    }
    else if (GV.REGOPCODE == 7) {
        GV.MemDecoration = Arg2qword;
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        pMyDisasm->Instruction.Category = VM_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmptrst");
        #endif
        GV.EIP_ += GV.DECALAGE_EIP+2;
    }
    else {
        failDecode(pMyDisasm);
    }

}
