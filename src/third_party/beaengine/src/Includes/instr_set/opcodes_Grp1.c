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
 *      80h
 * ==================================================================== */
void __bea_callspec__ G1_EbIb(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    EbIb(pMyDisasm);
    switch (GV.REGOPCODE) {
      case 0:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "add");
        #endif
        FillFlags(pMyDisasm, 5);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 1:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "or");
        #endif
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        FillFlags(pMyDisasm, 74);
        break;
      case 2:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "adc");
        #endif
        FillFlags(pMyDisasm, 4);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 3:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sbb");
        #endif
        FillFlags(pMyDisasm, 93);
        break;
      case 4:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "and");
        #endif
        FillFlags(pMyDisasm, 6);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 5:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sub");
        #endif
        FillFlags(pMyDisasm, 103);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 6:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xor");
        #endif
        FillFlags(pMyDisasm, 113);
        break;
      case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "cmp");
        #endif
        FillFlags(pMyDisasm, 20);
        pMyDisasm->Operand1.AccessMode = READ;
    }
}

/* ====================================================================
 *      82h
 * ==================================================================== */
void __bea_callspec__ G1_EbIb2(PDISASM pMyDisasm)
{
    if (GV.Architecture == 64) {
        failDecode(pMyDisasm);
    }
    else {
        G1_EbIb(pMyDisasm);
    }
}

/* ====================================================================
 *      81h
 * ==================================================================== */
void __bea_callspec__ G1_EvIv(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    EvIv(pMyDisasm);
    switch (GV.REGOPCODE) {
      case 0:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "add");
        #endif
        FillFlags(pMyDisasm, 5);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 1:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "or");
        #endif
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        FillFlags(pMyDisasm, 74);
        break;

      case 2:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "adc");
        #endif
        FillFlags(pMyDisasm, 4);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 3:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sbb");
        #endif
        FillFlags(pMyDisasm, 93);
        break;
      case 4:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "and");
        #endif
        FillFlags(pMyDisasm, 6);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 5:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sub");
        #endif
        FillFlags(pMyDisasm, 103);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 6:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xor");
        #endif
        FillFlags(pMyDisasm, 113);
        break;
      case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "cmp");
        #endif
        FillFlags(pMyDisasm, 20);
        pMyDisasm->Operand1.AccessMode = READ;
    }
}

/* ====================================================================
 *      83h
 * ==================================================================== */
void __bea_callspec__ G1_EvIb(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    EvIb(pMyDisasm);
    switch (GV.REGOPCODE) {
      case 0:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "add");
        #endif
        FillFlags(pMyDisasm, 5);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 1:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "or");
        #endif
        FillFlags(pMyDisasm, 74);
        break;
      case 2:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "adc");
        #endif
        FillFlags(pMyDisasm, 4);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 3:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sbb");
        #endif
        FillFlags(pMyDisasm, 93);
        break;
      case 4:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "and");
        #endif
        FillFlags(pMyDisasm, 6);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 5:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sub");
        #endif
        FillFlags(pMyDisasm, 103);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 6:
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+LOGICAL_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xor");
        #endif
        FillFlags(pMyDisasm, 113);
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        break;
      case 7:
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+ARITHMETIC_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "cmp");
        #endif
        FillFlags(pMyDisasm, 20);
        pMyDisasm->Operand1.AccessMode = READ;
    }
}
