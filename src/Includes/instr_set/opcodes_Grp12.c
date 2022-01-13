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
void __bea_callspec__ G12_(PDISASM pMyDisasm)
{
  if (GV.VEX.state == InUsePrefix) {
    if (GV.VEX.pp == 0) {
      failDecode(pMyDisasm);
    }
    else if (GV.VEX.pp == 1) {
      if (!Security(2, pMyDisasm)) return;
      GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
      if (GV.REGOPCODE == 6) {
        GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
        if (
          (GV.EVEX.state != InUsePrefix) &&
          (GV.MOD_!= 0x3)) {
          failDecode(pMyDisasm);
          return;
        }
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vpsllw");
        #endif
        pMyDisasm->Instruction.Category = AVX2_INSTRUCTION;
        if (GV.VEX.L == 0) {
          GV.Register_ = SSE_REG;
          GV.MemDecoration = Arg2_m128_xmm;
        }
        else if (GV.VEX.L == 1) {
          GV.Register_ = AVX_REG;
          GV.MemDecoration = Arg2_m256_ymm;
        }
        else if (GV.EVEX.LL == 2) {
          GV.Register_ = AVX512_REG;
          GV.MemDecoration = Arg2_m512_zmm;
        }
        fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        GV.EIP_+=2;
        getImmediat8(&pMyDisasm->Operand3, pMyDisasm);

      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.VEX.pp == 2) {
      failDecode(pMyDisasm);
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else {
    if (!Security(2, pMyDisasm)) return;
    GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
    if (GV.MOD_!= 0x3) {
      failDecode(pMyDisasm);
      return;
    }
    GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
    if (GV.REGOPCODE == 2) {
      if (GV.OperandSize == 16) {
        pMyDisasm->Instruction.Category = SSE_INSTRUCTION+SHIFT_ROTATE;
        GV.MemDecoration = Arg1dqword;
        GV.Register_ = SSE_REG;
      }
      else {
        pMyDisasm->Instruction.Category = MMX_INSTRUCTION+SHIFT_ROTATE;
        GV.MemDecoration = Arg1qword;
        GV.Register_ = MMX_REG;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "psrlw");
      #endif
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      GV.Register_ = 0;
      GV.EIP_ += GV.DECALAGE_EIP+2;
      getImmediat8(&pMyDisasm->Operand2, pMyDisasm);

    }
    else if (GV.REGOPCODE == 4) {
      if (GV.OperandSize == 16) {
        pMyDisasm->Instruction.Category = SSE_INSTRUCTION+SHIFT_ROTATE;
        GV.MemDecoration = Arg1dqword;
        GV.Register_ = SSE_REG;
      }
      else {
        pMyDisasm->Instruction.Category = MMX_INSTRUCTION+SHIFT_ROTATE;
        GV.MemDecoration = Arg1qword;
        GV.Register_ = MMX_REG;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "psraw");
      #endif
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      GV.Register_ = 0;
      GV.EIP_ += GV.DECALAGE_EIP+2;
      getImmediat8(&pMyDisasm->Operand2, pMyDisasm);

    }
    else if (GV.REGOPCODE == 6) {
      if (GV.OperandSize == 16) {
        pMyDisasm->Instruction.Category = SSE_INSTRUCTION+SHIFT_ROTATE;
        GV.MemDecoration = Arg1dqword;
        GV.Register_ = SSE_REG;
      }
      else {
        pMyDisasm->Instruction.Category = MMX_INSTRUCTION+SHIFT_ROTATE;
        GV.MemDecoration = Arg1qword;
        GV.Register_ = MMX_REG;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "psllw");
      #endif
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      GV.Register_ = 0;
      GV.EIP_ += GV.DECALAGE_EIP+2;
      getImmediat8(&pMyDisasm->Operand2, pMyDisasm);
    }
    else {
      failDecode(pMyDisasm);
    }
  }
}
