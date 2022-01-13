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
 *      0fbah
 * ==================================================================== */
void __bea_callspec__ G8_EvIb(PDISASM pMyDisasm)
{
    if (!Security(2, pMyDisasm)) return;
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;

    if (GV.REGOPCODE == 4) {
        EvIb(pMyDisasm);
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+BIT_UInt8;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "bt");
        #endif
        pMyDisasm->Operand1.AccessMode = READ;
        FillFlags(pMyDisasm, 11);
    }
    else if (GV.REGOPCODE == 5) {
        EvIb(pMyDisasm);
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+BIT_UInt8;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "bts");
        #endif
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        FillFlags(pMyDisasm, 11);
    }
    else if (GV.REGOPCODE == 6) {
        EvIb(pMyDisasm);
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+BIT_UInt8;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "btr");
        #endif
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        FillFlags(pMyDisasm, 11);
    }
    else if (GV.REGOPCODE == 7) {
        EvIb(pMyDisasm);
        if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
            pMyDisasm->Prefix.LockPrefix = InUsePrefix;
        }
        pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+BIT_UInt8;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "btc");
        #endif
        pMyDisasm->Operand1.AccessMode = READ + WRITE;
        FillFlags(pMyDisasm, 11);
    }
    else {
        failDecode(pMyDisasm);
    }
}
