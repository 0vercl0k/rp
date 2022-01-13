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
 *
 * ==================================================================== */
void __bea_callspec__ G16_(PDISASM pMyDisasm)
{
  if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
  if (!Security(2, pMyDisasm)) return;
  GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
  if (GV.REGOPCODE == 0) {
    if (!Security(2, pMyDisasm)) return;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
    if (GV.MOD_!= 0x3) {
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      GV.MemDecoration = Arg2byte;
      pMyDisasm->Instruction.Category = SSE_INSTRUCTION+CACHEABILITY_CONTROL;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "prefetchNTA");
      #endif
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else if (GV.REGOPCODE == 1) {

    if (!Security(2, pMyDisasm)) return;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
    if (GV.MOD_!= 0x3) {
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      GV.MemDecoration = Arg2byte;
      pMyDisasm->Instruction.Category = SSE_INSTRUCTION+CACHEABILITY_CONTROL;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "prefetchT0");
      #endif
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else if (GV.REGOPCODE == 2) {
    if (!Security(2, pMyDisasm)) return;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
    if (GV.MOD_!= 0x3) {
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      GV.MemDecoration = Arg2byte;
      pMyDisasm->Instruction.Category = SSE_INSTRUCTION+CACHEABILITY_CONTROL;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "prefetchT1");
      #endif
    }
    else {
        failDecode(pMyDisasm);
    }
  }
  else if (GV.REGOPCODE == 3) {
    if (!Security(2, pMyDisasm)) return;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
    if (GV.MOD_!= 0x3) {
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      GV.MemDecoration = Arg2byte;
      pMyDisasm->Instruction.Category = SSE_INSTRUCTION+CACHEABILITY_CONTROL;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "prefetchT2");
      #endif
    }
    else {
        failDecode(pMyDisasm);
    }
  }
  else {
    failDecode(pMyDisasm);
  }
  GV.EIP_+= GV.DECALAGE_EIP+2;
}
