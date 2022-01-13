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
int __bea_callspec__ Disasm (PDISASM pMyDisasm)
{
  if (InitVariables(pMyDisasm)) {
    (void) AnalyzeOpcode(pMyDisasm);
    pMyDisasm->Error = GV.ERROR_OPCODE;
    if (!GV.OutOfBlock) {
      if (GV.ERROR_OPCODE == UNKNOWN_OPCODE) {
        #ifndef BEA_LIGHT_DISASSEMBLY
        BuildCompleteInstruction(pMyDisasm);
        #endif
        return UNKNOWN_OPCODE;
      }
      else {
        FixOpSizeForMemoryOperand(pMyDisasm);
        FixREXPrefixes(pMyDisasm);
        FillSegmentsRegisters(pMyDisasm);
        CompleteInstructionFields(pMyDisasm);
        #ifndef BEA_LIGHT_DISASSEMBLY
        BuildCompleteInstruction(pMyDisasm);
        #endif
        return (int) (GV.EIP_-pMyDisasm->EIP);
      }
    }
    else {
      pMyDisasm->Error = OUT_OF_BLOCK;
      return OUT_OF_BLOCK;
    }
  }
  else {
    return UNKNOWN_OPCODE;
  }
}

/* ====================================================================
 *
 *  used for instructions encoded with no prefix (NP)
 * 
 * ==================================================================== */
bool __bea_callspec__ prefixes_present(PDISASM pMyDisasm) {
  bool status = false;
  if ((pMyDisasm->Prefix.OperandSize == InUsePrefix) || (GV.PrefRepe == 1) || (GV.PrefRepne == 1)) 
    status = true;
  return status;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ CompleteInstructionFields (PDISASM pMyDisasm)
{
  if (
    (pMyDisasm->Instruction.BranchType == JmpType) ||
    (pMyDisasm->Instruction.BranchType == CallType)) {
    pMyDisasm->Operand1.AccessMode = READ;
  }
  if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
    GV.ERROR_OPCODE = UD_;
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ failDecode(PDISASM pMyDisasm)
{
  #ifndef BEA_LIGHT_DISASSEMBLY
   (void) strcpy (pMyDisasm->Instruction.Mnemonic, "???");
  #endif
  pMyDisasm->Operand1.AccessMode = 0;
  pMyDisasm->Operand2.AccessMode = 0;
  pMyDisasm->Operand3.AccessMode = 0;
  pMyDisasm->Operand4.AccessMode = 0;
  pMyDisasm->Operand5.AccessMode = 0;
  pMyDisasm->Operand6.AccessMode = 0;
  pMyDisasm->Operand7.AccessMode = 0;
  pMyDisasm->Operand8.AccessMode = 0;
  pMyDisasm->Operand9.AccessMode = 0;
  GV.ERROR_OPCODE = UNKNOWN_OPCODE;
}

void __bea_callspec__ ResetREX(PDISASM pMyDisasm)
{
  if ((GV.REX.state == InUsePrefix) && (GV.REX.W_ == 1))
    GV.OperandSize = GV.OriginalOperandSize;
    GV.REX.W_ = 0;
    GV.REX.R_ = 0;
    GV.REX.X_ = 0;
    GV.REX.B_ = 0;
    GV.REX.state = 0;
}

/* ====================================================================
 *
 * ==================================================================== */
int __bea_callspec__ InitVariables (PDISASM pMyDisasm)
{
  size_t i = sizeof (OPTYPE);
  (void) memset (&GV, '\x0', sizeof (InternalDatas));
  GV.EIP_ = pMyDisasm->EIP;
  GV.EIP_REAL = GV.EIP_;
  GV.EIP_VA = pMyDisasm->VirtualAddr;
  GV.EndOfBlock = GV.EIP_ + 15;
  if (
    (pMyDisasm->SecurityBlock > 0) &&
    (pMyDisasm->SecurityBlock < 15)
  ) GV.EndOfBlock = GV.EIP_ + pMyDisasm->SecurityBlock;
  GV.OperandSize = 32;
  GV.OriginalOperandSize = 32;
  GV.AddressSize = 32;
  /*GV.Register_ = 0;*/
  GV.Architecture = pMyDisasm->Archi;
  if (GV.Architecture == 0) GV.Architecture = 64;
  pMyDisasm->Prefix.Number = 0;
  if (GV.Architecture == 64) GV.AddressSize = 64;
  if (GV.Architecture == 16) {
    GV.OperandSize = 16;
    GV.OriginalOperandSize = 16;
    GV.AddressSize = 16;
  }
  (void) memset (&pMyDisasm->Operand1, 0, i);
  (void) memset (&pMyDisasm->Operand2, 0, i);
  (void) memset (&pMyDisasm->Operand3, 0, i);
  (void) memset (&pMyDisasm->Operand4, 0, i);
  (void) memset (&pMyDisasm->Operand5, 0, i);
  (void) memset (&pMyDisasm->Operand6, 0, i);
  (void) memset (&pMyDisasm->Operand7, 0, i);
  (void) memset (&pMyDisasm->Operand8, 0, i);
  (void) memset (&pMyDisasm->Operand9, 0, i);
  (void) memset (&pMyDisasm->Prefix, 0, sizeof (PREFIXINFO));

  pMyDisasm->Operand1.AccessMode = WRITE;
  pMyDisasm->Operand1.OpPosition = LowPosition;
  pMyDisasm->Operand2.OpPosition = LowPosition;
  pMyDisasm->Operand3.OpPosition = LowPosition;
  pMyDisasm->Operand4.OpPosition = LowPosition;
  pMyDisasm->Operand1.OpType = NO_ARGUMENT;
  pMyDisasm->Operand2.OpType = NO_ARGUMENT;
  pMyDisasm->Operand3.OpType = NO_ARGUMENT;
  pMyDisasm->Operand4.OpType = NO_ARGUMENT;
  pMyDisasm->Operand5.OpType = NO_ARGUMENT;
  pMyDisasm->Operand6.OpType = NO_ARGUMENT;
  pMyDisasm->Operand7.OpType = NO_ARGUMENT;
  pMyDisasm->Operand8.OpType = NO_ARGUMENT;
  pMyDisasm->Operand9.OpType = NO_ARGUMENT;
  pMyDisasm->Operand2.AccessMode = READ;
  pMyDisasm->Operand3.AccessMode = READ;
  pMyDisasm->Operand4.AccessMode = READ;
  pMyDisasm->Operand5.AccessMode = READ;
  pMyDisasm->Operand6.AccessMode = READ;
  pMyDisasm->Operand7.AccessMode = READ;
  pMyDisasm->Operand8.AccessMode = READ;
  pMyDisasm->Operand9.AccessMode = READ;
  (void) memset (&pMyDisasm->Instruction, '\x0', sizeof (INSTRTYPE));
  GV.OPTIONS = (UInt32)pMyDisasm->Options;
  GV.SYNTAX_ = (UInt32)pMyDisasm->Options & 0xff00;
  GV.FORMATNUMBER = (UInt32)pMyDisasm->Options & PrefixedNumeral;
  GV.SEGMENTREGS = (UInt32)pMyDisasm->Options & ShowSegmentRegs;
  /*
  GV.OutOfBlock = 0;
  GV.ERROR_OPCODE = 0;
  */
  GV.EVEX.masking = MERGING_ZEROING;
  return 1;
}
/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ FixOpSizeForMemoryOperand (PDISASM pMyDisasm)
{
  int i = GV.MemDecoration / 100;
  if (ArgsSize[GV.MemDecoration - (i*100+1)] != 0) {
    switch (i) {
      case 0:
        pMyDisasm->Operand1.OpSize = ArgsSize[GV.MemDecoration - 1];
        break;
      case 1:
        pMyDisasm->Operand2.OpSize = ArgsSize[GV.MemDecoration - 101];
        break;
      case 2:
        pMyDisasm->Operand3.OpSize = ArgsSize[GV.MemDecoration - 201];
        break;
      case 3:
        pMyDisasm->Operand4.OpSize = ArgsSize[GV.MemDecoration - 301];
    }
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ FixREXPrefixes (PDISASM pMyDisasm)
{
  pMyDisasm->Prefix.REX.W_ = GV.REX.W_;
  pMyDisasm->Prefix.REX.R_ = GV.REX.R_;
  pMyDisasm->Prefix.REX.X_ = GV.REX.X_;
  pMyDisasm->Prefix.REX.B_ = GV.REX.B_;
  pMyDisasm->Prefix.REX.state = GV.REX.state;
}

/* ====================================================================
 *
 * ==================================================================== */
int __bea_callspec__ AnalyzeOpcode (PDISASM pMyDisasm)
{
  UInt8 *opcode;
  if (!Security(1, pMyDisasm)) return 0;
  opcode = (UInt8*) GV.EIP_;
  pMyDisasm->Instruction.Opcode = *opcode;
  (void) opcode_map1[*opcode](pMyDisasm);
  return 1;
}
/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ EbGb(PDISASM pMyDisasm)
{
  GV.MemDecoration = Arg1byte;
  GV.OperandSize = 8;
  ExGx(pMyDisasm);
  GV.OperandSize = 32;
  if (
      (GV.MOD_ == 3) &&
      (pMyDisasm->Prefix.LockPrefix == InUsePrefix)
    ) {
    GV.ERROR_OPCODE = UD_;
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ GbEb(PDISASM pMyDisasm)
{
  GV.MemDecoration = Arg2byte;
  GV.OperandSize = 8;
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
  GV.OperandSize = 32;
  GV.EIP_ += GV.DECALAGE_EIP+2;
}
/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ EvGv(PDISASM pMyDisasm)
{
  if (GV.OperandSize == 64) {
    GV.MemDecoration = Arg1qword;
  }
  else if (GV.OperandSize == 32) {
    GV.MemDecoration = Arg1dword;
  }
  else {
    GV.MemDecoration = Arg1word;
  }
  ExGx(pMyDisasm);
  if ((GV.MOD_ == 3) && (pMyDisasm->Prefix.LockPrefix == InUsePrefix)) {
    GV.ERROR_OPCODE = UD_;
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ ExGx(PDISASM pMyDisasm)
{
  decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
  decodeRegOpcode(&pMyDisasm->Operand2, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ EvIv(PDISASM pMyDisasm)
{
  if (GV.OperandSize >= 32) {
    if (GV.OperandSize == 64) {
      GV.MemDecoration = Arg1qword;
    }
    else {
      GV.MemDecoration = Arg1dword;
    }
    GV.ImmediatSize = 32;                       /* place this instruction before MOD_RM routine to inform it there is an immediat value */
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+6;
    if (!Security(0, pMyDisasm)) return;
    #ifndef BEA_LIGHT_DISASSEMBLY
    if (GV.OperandSize == 64) {
      (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.16llX",(Int64) *((Int32*) (GV.EIP_-4)));
    }
    else {
      (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.8X",(Int64) *((UInt32*) (GV.EIP_-4)));
    }
    #endif

    pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
    pMyDisasm->Operand2.OpSize = 32;
    pMyDisasm->Instruction.Immediat = *((UInt32*) (GV.EIP_-4));
  }
  else {
    GV.MemDecoration = Arg1word;
    GV.ImmediatSize = 16;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+4;
    if (!Security(1, pMyDisasm)) return;
    #ifndef BEA_LIGHT_DISASSEMBLY
      (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.4X",(Int64)*((UInt16*) (GV.EIP_-2)));
    #endif
    pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
    pMyDisasm->Operand2.OpSize = 16;
    pMyDisasm->Instruction.Immediat = *((UInt16*) (GV.EIP_-2));
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ EvIb(PDISASM pMyDisasm)
{
  Int8 MyNumber;
  pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
  pMyDisasm->Operand2.OpSize = 8;
  GV.ImmediatSize = 8;
  if (GV.OperandSize >= 32) {
    if (GV.OperandSize == 64) {
      GV.MemDecoration = Arg1qword;
    }
    else {
      GV.MemDecoration = Arg1dword;
    }
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+3;
    if (!Security(0, pMyDisasm)) return;
    if (GV.OperandSize == 32) {
      #ifndef BEA_LIGHT_DISASSEMBLY
      MyNumber = *((Int8*) (GV.EIP_-1));
      if (MyNumber > 0) {
        (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.2X",(Int64)*((Int8*) (GV.EIP_-1)));
      }
      else {
        (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.8X",(Int64)*((Int8*) (GV.EIP_-1)));
      }
      #endif
    }
    else {
      #ifndef BEA_LIGHT_DISASSEMBLY
      MyNumber = *((Int8*) (GV.EIP_-1));
      if (MyNumber > 0) {
        (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.2X",(Int64)*((Int8*) (GV.EIP_-1)));
      }
      else {
        (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.16llX",(Int64)*((Int8*) (GV.EIP_-1)));
      }
      #endif
    }
  pMyDisasm->Instruction.Immediat = *((UInt8*) (GV.EIP_-1));
  }
  else {
    GV.MemDecoration = Arg1word;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+3;
    if (!Security(0, pMyDisasm)) return;
    #ifndef BEA_LIGHT_DISASSEMBLY
      (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.4X",(Int64)*((Int8*) (GV.EIP_-1)));
    #endif
    pMyDisasm->Instruction.Immediat = *((UInt8*) (GV.EIP_-1));
  }
}
/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ EbIb(PDISASM pMyDisasm)
{
  pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
  pMyDisasm->Operand2.OpSize = 8;
  GV.ImmediatSize = 8;
  GV.MemDecoration = Arg1byte;
  GV.OperandSize = 8;
  decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
  GV.OperandSize = 32;
  GV.EIP_ += GV.DECALAGE_EIP+3;
  if (!Security(0, pMyDisasm)) return;
  #ifndef BEA_LIGHT_DISASSEMBLY
    (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.2X",(Int64)*((Int8*) (GV.EIP_-1)));
  #endif
  pMyDisasm->Instruction.Immediat = *((UInt8*) (GV.EIP_-1));
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ Eb(PDISASM pMyDisasm)
{
  GV.MemDecoration = Arg1byte;
  GV.OperandSize = 8;
  decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
  GV.OperandSize = 32;
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ Ev(PDISASM pMyDisasm)
{
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
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ GvEv(PDISASM pMyDisasm)
{
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
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ GyEy(PDISASM pMyDisasm)
{
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand2, pMyDisasm);
  decodeModrm(&pMyDisasm->Operand3, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ ArgsVEX(PDISASM pMyDisasm)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = SSE_REG;
    GV.MemDecoration = Arg3_m128_xmm;
    GyEy(pMyDisasm);
    GV.Register_ = 0;
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = AVX_REG;
    GV.MemDecoration = Arg3_m256_ymm;
    GyEy(pMyDisasm);
    GV.Register_ = 0;
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = AVX512_REG;
    GV.MemDecoration = Arg3_m512_zmm;
    GyEy(pMyDisasm);
    GV.Register_ = 0;
  }
}

void __bea_callspec__ vex_CMPPS(PDISASM pMyDisasm)
{
  verifyVEXvvvv(pMyDisasm);
  GV.Register_ = OPMASK_REG;
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = SSE_REG;
    GV.MemDecoration = Arg3_m128_xmm;
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = AVX_REG;
    GV.MemDecoration = Arg3_m256_ymm;
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = AVX512_REG;
    GV.MemDecoration = Arg3_m512_zmm;
  }
  fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand2, pMyDisasm);
  decodeModrm(&pMyDisasm->Operand3, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}


/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ EyGy(PDISASM pMyDisasm)
{
  decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
  fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand2, pMyDisasm);
  decodeRegOpcode(&pMyDisasm->Operand3, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_EyGy(PDISASM pMyDisasm)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = SSE_REG;
    GV.MemDecoration = Arg1_m128_xmm;
    EyGy(pMyDisasm);
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = AVX_REG;
    GV.MemDecoration = Arg1_m256_ymm;
    EyGy(pMyDisasm);
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = AVX512_REG;
    GV.MemDecoration = Arg1_m512_zmm;
    EyGy(pMyDisasm);
  }
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_ExGx(PDISASM pMyDisasm)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = SSE_REG;
    GV.MemDecoration = Arg1_m128_xmm;
    ExGx(pMyDisasm);
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = AVX_REG;
    GV.MemDecoration = Arg1_m256_ymm;
    ExGx(pMyDisasm);
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = AVX512_REG;
    GV.MemDecoration = Arg1_m512_zmm;
    ExGx(pMyDisasm);
  }
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_GxE(PDISASM pMyDisasm, int reg1, int reg2, int reg3)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = reg1;
    GV.MemDecoration = Arg2_m128_xmm;
    GxEx(pMyDisasm);
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = reg2;
    GV.MemDecoration = Arg2_m256_ymm;
    GxEx(pMyDisasm);
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = reg3;
    GV.MemDecoration = Arg2_m512_zmm;
    GxEx(pMyDisasm);
  }
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_GE(PDISASM pMyDisasm, int mem1, int mem2, int mem3, int reg1, int reg2, int reg3)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = reg1;
    GV.MemDecoration = mem1;
    decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
    GV.Register_ = SSE_REG;
    decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+2;
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = reg2;
    GV.MemDecoration = mem2;
    decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
    GV.Register_ = AVX_REG;
    decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+2;
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = reg3;
    GV.MemDecoration = mem3;
    decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
    GV.Register_ = AVX512_REG;
    decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+2;
  }
}



/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_GEx(PDISASM pMyDisasm, int mem1, int mem2, int mem3)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = SSE_REG;
    GV.MemDecoration = mem1;
    GxEx(pMyDisasm);
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = AVX_REG;
    GV.MemDecoration = mem2;
    GxEx(pMyDisasm);
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = AVX512_REG;
    GV.MemDecoration = mem3;
    GxEx(pMyDisasm);
  }
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_ExG(PDISASM pMyDisasm, int mem1, int mem2, int mem3, int reg1, int reg2, int reg3)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = reg1;
    GV.MemDecoration = mem1;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.Register_ = SSE_REG;
    decodeRegOpcode(&pMyDisasm->Operand2, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+2;
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = reg2;
    GV.MemDecoration = mem2;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.Register_ = AVX_REG;
    decodeRegOpcode(&pMyDisasm->Operand2, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+2;
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = reg3;
    GV.MemDecoration = mem3;
    decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
    GV.Register_ = AVX512_REG;
    decodeRegOpcode(&pMyDisasm->Operand2, pMyDisasm);
    GV.EIP_ += GV.DECALAGE_EIP+2;
  }
}

/* ====================================================================
 * Used by AVX instructions
 * ==================================================================== */
void __bea_callspec__ vex_GxEx(PDISASM pMyDisasm)
{
  verifyVEXvvvv(pMyDisasm);
  if (GV.VEX.L == 0) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX_INSTRUCTION;
    GV.Register_ = SSE_REG;
    GV.MemDecoration = Arg2_m128_xmm;
    GxEx(pMyDisasm);
  }
  else if (GV.VEX.L == 0x1) {
    pMyDisasm->Instruction.Category = (GV.EVEX.state == InUsePrefix) ? AVX512_INSTRUCTION : AVX2_INSTRUCTION;
    GV.Register_ = AVX_REG;
    GV.MemDecoration = Arg2_m256_ymm;
    GxEx(pMyDisasm);
  }
  else if (GV.EVEX.LL == 0x2) {
    pMyDisasm->Instruction.Category = AVX512_INSTRUCTION;
    GV.Register_ = AVX512_REG;
    GV.MemDecoration = Arg2_m512_zmm;
    GxEx(pMyDisasm);
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ getImmediat8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  GV.EIP_++;
  GV.ImmediatSize = 8;
  if (!Security(0, pMyDisasm)) return;
  pMyDisasm->Instruction.Immediat = *((UInt8*) (GV.EIP_- 1));
  #ifndef BEA_LIGHT_DISASSEMBLY
     (void) CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic, "%.2X",(Int64) *((UInt8*) (GV.EIP_- 1)));
  #endif
  pMyOperand->OpType = CONSTANT_TYPE+ABSOLUTE_;
  pMyOperand->OpSize = 8;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ verifyVEXvvvv(PDISASM pMyDisasm)
{
  if (
      ((GV.EVEX.state != InUsePrefix) && (GV.VEX.vvvv != 15))
      || ((GV.EVEX.state == InUsePrefix) && (GV.EVEX.vvvv != 15))
    ) {
    GV.ERROR_OPCODE = UD_;
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ GvEb(PDISASM pMyDisasm)
{
  if (GV.OperandSize == 64) {
    GV.MemDecoration = Arg2byte;
    GV.OperandSize = 8;
    decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
    GV.OperandSize = 64;
  }
  else if (GV.OperandSize == 32) {
    GV.MemDecoration = Arg2byte;
    GV.OperandSize = 8;
    decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
    GV.OperandSize = 32;
  }
  else {
    GV.MemDecoration = Arg2byte;
    GV.OperandSize = 8;
    decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
    GV.OperandSize = 16;
  }
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ GxEx(PDISASM pMyDisasm)
{
  decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ GxExVEX(PDISASM pMyDisasm)
{
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
  fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand3, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ GvEw(PDISASM pMyDisasm)
{
  GV.MemDecoration = Arg2word;
  GV.OriginalOperandSize = GV.OperandSize;
  GV.OperandSize = 16;
  decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
  GV.OperandSize = GV.OriginalOperandSize;
  decodeRegOpcode(&pMyDisasm->Operand1, pMyDisasm);
  GV.EIP_ += GV.DECALAGE_EIP+2;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ ALIb(PDISASM pMyDisasm)
{
  long MyNumber;
  if (!Security(2, pMyDisasm)) return;
  GV.ImmediatSize = 8;
  MyNumber = *((Int8*) (GV.EIP_+1));
  #ifndef BEA_LIGHT_DISASSEMBLY
    (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.2X",(Int64) MyNumber);
  #endif
  pMyDisasm->Instruction.Immediat = MyNumber;
  #ifndef BEA_LIGHT_DISASSEMBLY
    (void) strcpy((char*) &pMyDisasm->Operand1.OpMnemonic, Registers8Bits[0]);
  #endif
  pMyDisasm->Operand1.OpType = REGISTER_TYPE;pMyDisasm->Operand1.Registers.type = GENERAL_REG;
  pMyDisasm->Operand1.Registers.gpr = REG0;
  pMyDisasm->Operand1.OpSize = 8;
  pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
  pMyDisasm->Operand2.OpSize = 8;
  GV.EIP_ += 2;
  if (pMyDisasm->Prefix.LockPrefix == InUsePrefix) {
    GV.ERROR_OPCODE = UD_;
  }
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ eAX_Iv(PDISASM pMyDisasm)
{
    UInt32 MyNumber;
    pMyDisasm->Operand1.OpType = REGISTER_TYPE;pMyDisasm->Operand1.Registers.type = GENERAL_REG;
    pMyDisasm->Operand1.Registers.gpr = REG0;
    pMyDisasm->Operand2.OpType = CONSTANT_TYPE+ABSOLUTE_;
    if (GV.OperandSize == 64) {
      if (!Security(5, pMyDisasm)) return;
      GV.ImmediatSize = 32;
      pMyDisasm->Operand1.OpSize = 64;
      pMyDisasm->Operand2.OpSize = 32;
      MyNumber = *((UInt32*) (GV.EIP_+1));
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.16llX",(Int64) MyNumber);
      #endif
      pMyDisasm->Instruction.Immediat = MyNumber;
       if (GV.REX.B_ == 1) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyDisasm->Operand1.OpMnemonic, Registers64Bits[0+8]);
          #endif
      }
      else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyDisasm->Operand1.OpMnemonic, Registers64Bits[0]);
          #endif
      }
      GV.EIP_+= 5;
    }
    else if (GV.OperandSize == 32) {
      if (!Security(5, pMyDisasm)) return;
      GV.ImmediatSize = 32;
      pMyDisasm->Operand1.OpSize = 32;
      pMyDisasm->Operand2.OpSize = 32;
      MyNumber = *((UInt32*) (GV.EIP_+1));
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.8X",(Int64) MyNumber);
      #endif
      pMyDisasm->Instruction.Immediat = MyNumber;
       if (GV.REX.B_ == 1) {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyDisasm->Operand1.OpMnemonic, Registers32Bits[0+8]);
        #endif
      }
      else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyDisasm->Operand1.OpMnemonic, Registers32Bits[0]);
        #endif
      }
      GV.EIP_+= 5;
    }
    else {
      if (!Security(3, pMyDisasm)) return;
      GV.ImmediatSize = 16;
      pMyDisasm->Operand1.OpSize = 16;
      pMyDisasm->Operand2.OpSize = 16;
      MyNumber = *((UInt16*) (GV.EIP_+1));
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) CopyFormattedNumber(pMyDisasm, (char*) &pMyDisasm->Operand2.OpMnemonic,"%.8X", (Int64) MyNumber);
      #endif
      pMyDisasm->Instruction.Immediat = MyNumber;
       if (GV.REX.B_ == 1) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyDisasm->Operand1.OpMnemonic, Registers16Bits[0+8]);
          #endif
      }
      else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyDisasm->Operand1.OpMnemonic, Registers16Bits[0]);
          #endif
      }
      GV.EIP_+= 3;
    }
    if (pMyDisasm->Prefix.LockPrefix == InUsePrefix) {
      GV.ERROR_OPCODE = UD_;
    }
}

/* ====================================================================
 *
 * ==================================================================== */
int __bea_callspec__ Security(int len, PDISASM pMyDisasm)
{
  if ((GV.EndOfBlock != 0) && (GV.EIP_+(UInt64)len > GV.EndOfBlock)) {
    GV.OutOfBlock = 1;
    GV.ERROR_OPCODE = OUT_OF_BLOCK;
    return 0;
  }
  return 1;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ FillFlags(PDISASM pMyDisasm, int index)
{
  pMyDisasm->Instruction.ImplicitModifiedRegs.type |= SPECIAL_REG;
  pMyDisasm->Instruction.ImplicitModifiedRegs.special |= REG0;
  pMyDisasm->Instruction.Flags = EFLAGS_TABLE[index];
}
/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ CalculateRelativeAddress(UInt64 * pMyAddress, Int64 MyNumber, PDISASM pMyDisasm)
{
  GV.RelativeAddress = 1;
  if (GV.EIP_VA != 0) {
      *pMyAddress = (UInt64) (GV.EIP_VA+(UInt64) MyNumber);
  }
  else {
      *pMyAddress = (UInt64) (GV.EIP_REAL+(UInt64) MyNumber);
  }
}

/* ====================================================================
 *
 * ==================================================================== */
#ifndef BEA_LIGHT_DISASSEMBLY
size_t __bea_callspec__ CopyFormattedNumber(PDISASM pMyDisasm, char* pBuffer, const char* pFormat, Int64 MyNumber)
{
  size_t i = 0;
  if (!strcmp(pFormat,"%.2X")) MyNumber = MyNumber & 0xFF;
  if (!strcmp(pFormat,"%.4X")) MyNumber = MyNumber & 0xFFFF;
  if (!strcmp(pFormat,"%.8X")) MyNumber = MyNumber & 0xFFFFFFFF;
  if (GV.OPTIONS & PrefixedNumeral) {
    (void) strcpy(pBuffer, "0x");
    (void) sprintf (pBuffer+2, pFormat, MyNumber);
    i += strlen(pBuffer);
  }
  else {
    (void) sprintf (pBuffer+i, pFormat, MyNumber);
    i += strlen(pBuffer);
    (void) strcpy(pBuffer+i, "h");
    i++;
  }
  return i;
}
#endif

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ FillSegmentsRegisters(PDISASM pMyDisasm)
{
  if (
      (pMyDisasm->Prefix.LockPrefix == InUsePrefix) &&
      (pMyDisasm->Operand1.OpType != MEMORY_TYPE) &&
      (pMyDisasm->Operand1.OpType != REGISTER_TYPE)
    ) {
      pMyDisasm->Prefix.LockPrefix = InvalidPrefix;
  }
  if (pMyDisasm->Instruction.Category == GENERAL_PURPOSE_INSTRUCTION+STRING_INSTRUCTION) {
    pMyDisasm->Operand1.SegmentReg = ESReg;
    pMyDisasm->Operand2.SegmentReg = DSReg;
    /* =============== override affects Arg2 */
    if (pMyDisasm->Operand2.OpType == MEMORY_TYPE) {
      if (pMyDisasm->Prefix.FSPrefix == InUsePrefix) {
        pMyDisasm->Operand2.SegmentReg = FSReg;
      }
      else if (pMyDisasm->Prefix.GSPrefix == InUsePrefix) {
        pMyDisasm->Operand2.SegmentReg = GSReg;
      }
      else if (pMyDisasm->Prefix.CSPrefix == InUsePrefix) {
        pMyDisasm->Operand2.SegmentReg = CSReg;
      }
      else if (pMyDisasm->Prefix.ESPrefix == InUsePrefix) {
        pMyDisasm->Operand2.SegmentReg = ESReg;
      }
      else if (pMyDisasm->Prefix.SSPrefix == InUsePrefix) {
        pMyDisasm->Operand2.SegmentReg = SSReg;
      }
      else {
        pMyDisasm->Operand2.SegmentReg = DSReg;
      }
    }
  }
  else {
    if (pMyDisasm->Operand1.OpType == MEMORY_TYPE) {
      if (
          (pMyDisasm->Operand1.Memory.BaseRegister == REG4) ||
          (pMyDisasm->Operand1.Memory.BaseRegister == REG5)
        ) {
        pMyDisasm->Operand1.SegmentReg = SSReg;
        /* ========== override is invalid here */
        if (pMyDisasm->Operand2.OpType != MEMORY_TYPE) {
          if (pMyDisasm->Prefix.FSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = FSReg;
            pMyDisasm->Prefix.FSPrefix = InvalidPrefix;
          }
          else if (pMyDisasm->Prefix.GSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = GSReg;
            pMyDisasm->Prefix.GSPrefix = InvalidPrefix;
          }
          else if (pMyDisasm->Prefix.CSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = CSReg;
            pMyDisasm->Prefix.CSPrefix = InvalidPrefix;
          }
          else if (pMyDisasm->Prefix.DSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = DSReg;
            pMyDisasm->Prefix.DSPrefix = InvalidPrefix;
          }
          else if (pMyDisasm->Prefix.ESPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = ESReg;
            pMyDisasm->Prefix.ESPrefix = InvalidPrefix;
          }
          else if (pMyDisasm->Prefix.SSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = SSReg;
            pMyDisasm->Prefix.SSPrefix = InvalidPrefix;
          }
        }
      }
      else {
        pMyDisasm->Operand1.SegmentReg = DSReg;
        /* ============= test if there is override */
        if (pMyDisasm->Prefix.FSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = FSReg;
        }
        else if (pMyDisasm->Prefix.GSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = GSReg;
        }
        else if (pMyDisasm->Prefix.CSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = CSReg;
        }
        else if (pMyDisasm->Prefix.ESPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = ESReg;
        }
        else if (pMyDisasm->Prefix.SSPrefix == InUsePrefix) {
            pMyDisasm->Operand1.SegmentReg = SSReg;
        }
      }
    }

    if (pMyDisasm->Operand2.OpType == MEMORY_TYPE) {
      if (
        (pMyDisasm->Operand2.Memory.BaseRegister == REG4) ||
         (pMyDisasm->Operand2.Memory.BaseRegister == REG5)
       ) {
        pMyDisasm->Operand2.SegmentReg = SSReg;
        /* ========== override is invalid here */
        if (pMyDisasm->Prefix.FSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = FSReg;
            pMyDisasm->Prefix.FSPrefix = InvalidPrefix;
        }
        else if (pMyDisasm->Prefix.GSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = GSReg;
            pMyDisasm->Prefix.GSPrefix = InvalidPrefix;
        }
        else if (pMyDisasm->Prefix.CSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = CSReg;
            pMyDisasm->Prefix.CSPrefix = InvalidPrefix;
        }
        else if (pMyDisasm->Prefix.DSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = DSReg;
            pMyDisasm->Prefix.DSPrefix = InvalidPrefix;
        }
        else if (pMyDisasm->Prefix.ESPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = ESReg;
            pMyDisasm->Prefix.ESPrefix = InvalidPrefix;
        }
        else if (pMyDisasm->Prefix.SSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = SSReg;
            pMyDisasm->Prefix.SSPrefix = InvalidPrefix;
        }
      }
      else {
        pMyDisasm->Operand2.SegmentReg = DSReg;
        /* ============= test if there is override */
        if (pMyDisasm->Prefix.FSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = FSReg;
        }
        else if (pMyDisasm->Prefix.GSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = GSReg;
        }
        else if (pMyDisasm->Prefix.CSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = CSReg;
        }
        else if (pMyDisasm->Prefix.ESPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = ESReg;
        }
        else if (pMyDisasm->Prefix.SSPrefix == InUsePrefix) {
            pMyDisasm->Operand2.SegmentReg = SSReg;
        }
      }
    }
  }
}

#ifndef BEA_LIGHT_DISASSEMBLY
/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printPrefixes(PDISASM pMyDisasm, size_t i)
{
  if (pMyDisasm->Prefix.RepnePrefix == InUsePrefix) {
    (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "repne ");
    i = strlen((char*) &pMyDisasm->CompleteInstr);
  }
  if (pMyDisasm->Prefix.RepPrefix == InUsePrefix) {
    (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "rep ");
    i = strlen((char*) &pMyDisasm->CompleteInstr);
  }
  if (
    (pMyDisasm->Prefix.LockPrefix == InUsePrefix) ||
    (pMyDisasm->Prefix.LockPrefix == InvalidPrefix)
    ) {
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "lock ");
      i = strlen((char*) &pMyDisasm->CompleteInstr);
  }
  return i;
}
/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printMnemonic(PDISASM pMyDisasm, size_t i)
{
  (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, (char*) &pMyDisasm->Instruction.Mnemonic);
  i = strlen((char*) &pMyDisasm->CompleteInstr);
  return i;
}
/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printTabulation(PDISASM pMyDisasm, size_t i)
{
  (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, space_tab[i>10 ? 0 : 10-i]);
  i = strlen((char*) &pMyDisasm->CompleteInstr);
  return i;
}
/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printOneSpace(PDISASM pMyDisasm, size_t i)
{
  (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, " ");
  i = strlen((char*) &pMyDisasm->CompleteInstr);
  return i;
}
/* ====================================================================
 *
 * operand representation
 *
 * ==================================================================== */
size_t __bea_callspec__ printArg(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i)
{
  size_t mnemonic = strlen((char*) &pMyOperand->OpMnemonic);
  if (mnemonic != 0) {
    i = printOneSpace(pMyDisasm, i);
    (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, (char*) &pMyOperand->OpMnemonic);
    i = strlen((char*) &pMyDisasm->CompleteInstr);
  }
  return i;
}

/*
 *
 * used to resolve 2^n = a
 *
 */

UInt32 find_exp(UInt32 a) {
  UInt32 i = 0;
  while (a > 0) {
    a = a >> 1;
    i++;
  }
  return i;
}

/* ====================================================================
 *
 * operand representation
 *
 * ==================================================================== */
size_t __bea_callspec__ printDecoratedArg(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i)
{
  i = printOneSpace(pMyDisasm, i);
  if (GV.SYNTAX_ == NasmSyntax) {
    (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, NasmPrefixes[GV.MemDecoration-1]);
    i = strlen((char*) &pMyDisasm->CompleteInstr);
    if ((GV.SEGMENTREGS != 0) || (GV.SEGMENTFS != 0) || (pMyDisasm->Prefix.GSPrefix == InUsePrefix)){
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "[");
      i++;
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, SegmentRegs[find_exp(pMyOperand->SegmentReg)]);
      i = strlen((char*) &pMyDisasm->CompleteInstr);
    }
    else {
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "[");
      i++;
    }
  }
  else {
    if (GV.SYNTAX_ == MasmSyntax) {
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, MasmPrefixes[GV.MemDecoration-1]);
      i = strlen((char*) &pMyDisasm->CompleteInstr);
    }
    else if (GV.SYNTAX_ == IntrinsicMemSyntax) {
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, IntrinsicPrefixes[GV.MemDecoration-1]);
      i = strlen((char*) &pMyDisasm->CompleteInstr);
    }
    else {
        (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, GoAsmPrefixes[GV.MemDecoration-1]);
        i = strlen((char*) &pMyDisasm->CompleteInstr);
    }
    if ((GV.SEGMENTREGS != 0) || (GV.SEGMENTFS != 0) || (pMyDisasm->Prefix.GSPrefix == InUsePrefix)){
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, SegmentRegs[find_exp(pMyOperand->SegmentReg)]);
      i = strlen((char*) &pMyDisasm->CompleteInstr);
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "[");
      i++;
    }
    else {
      (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "[");
      i++;
    }
  }
  (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, (char*) &pMyOperand->OpMnemonic);
  i = strlen((char*) &pMyDisasm->CompleteInstr);
  (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "]");
  i++;
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printArg1(PDISASM pMyDisasm, size_t i)
{
  if ((GV.MemDecoration >0) && (GV.MemDecoration < 99)) {
    i = printDecoratedArg(&pMyDisasm->Operand1, pMyDisasm, i);
  }
  else {
    i = printArg(&pMyDisasm->Operand1, pMyDisasm, i);
  }
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printArg2(PDISASM pMyDisasm, size_t i)
{
  if ((GV.MemDecoration >100) && (GV.MemDecoration < 199)) {
    GV.MemDecoration -= 100;
    i = printDecoratedArg(&pMyDisasm->Operand2, pMyDisasm, i);
  }
  else {
    i = printArg(&pMyDisasm->Operand2, pMyDisasm, i);
  }
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printArg3(PDISASM pMyDisasm, size_t i)
{
  if ((GV.MemDecoration >200) && (GV.MemDecoration < 299)) {
    GV.MemDecoration -= 200;
    i = printDecoratedArg(&pMyDisasm->Operand3, pMyDisasm, i);
  }
  else {
    i = printArg(&pMyDisasm->Operand3, pMyDisasm, i);
  }
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printArg4(PDISASM pMyDisasm, size_t i)
{
  if ((GV.MemDecoration >300) && (GV.MemDecoration < 399)) {
    GV.MemDecoration -= 300;
    i = printDecoratedArg(&pMyDisasm->Operand4, pMyDisasm, i);
  }
  else {
    i = printArg(&pMyDisasm->Operand4, pMyDisasm, i);
  }
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printArgsSeparator(OPTYPE* pMyOperand1, OPTYPE* pMyOperand2, PDISASM pMyDisasm, size_t i)
{
  if ((pMyOperand1->OpMnemonic[0] != 0) && (pMyOperand2->OpMnemonic[0] != 0)) {
    (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, ",");
    i += 1;
  }
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
size_t __bea_callspec__ printEVEXMasking(PDISASM pMyDisasm, size_t i)
{
  #ifndef BEA_LIGHT_DISASSEMBLY
     (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, " {");
  #endif
  i+=2;
  #ifndef BEA_LIGHT_DISASSEMBLY
     (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, RegistersOpmask[GV.EVEX.aaa]);
  #endif
  i = strlen((char*) &pMyDisasm->CompleteInstr);
  #ifndef BEA_LIGHT_DISASSEMBLY
     (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "}");
  #endif
  i++;
  if (GV.EVEX.masking == MERGING_ZEROING) {
    if (GV.EVEX.z == 1) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "{1}");
      #endif
    }
    else {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy ((char*) &pMyDisasm->CompleteInstr+i, "{0}");
      #endif
    }
    i+=3;
  }
  return i;
}

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ BuildCompleteInstruction(PDISASM pMyDisasm)
{
  size_t i = 0;

  i = printPrefixes(pMyDisasm, i);
  i = printMnemonic(pMyDisasm, i);
  if (GV.OPTIONS & Tabulation) {
    i = printTabulation(pMyDisasm, i);
  }
  i = printArg1(pMyDisasm, i);
  if (
    (GV.ERROR_OPCODE != UNKNOWN_OPCODE) &&
    (GV.EVEX.state == InUsePrefix) &&
    (GV.EVEX.masking != NO_MASK) &&
    ((GV.OPTIONS & ShowEVEXMasking))
    ) {
    i = printEVEXMasking(pMyDisasm, i);
  }
  i = printArgsSeparator(&pMyDisasm->Operand1, &pMyDisasm->Operand2, pMyDisasm, i);
  i = printArg2(pMyDisasm, i);
  i = printArgsSeparator(&pMyDisasm->Operand2, &pMyDisasm->Operand3, pMyDisasm, i);
  i = printArg3(pMyDisasm, i);
  i = printArgsSeparator(&pMyDisasm->Operand3, &pMyDisasm->Operand4, pMyDisasm, i);
  i = printArg4(pMyDisasm, i);
}

#endif
