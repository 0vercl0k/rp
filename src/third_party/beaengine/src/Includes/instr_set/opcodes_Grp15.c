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
void __bea_callspec__ G15_(PDISASM pMyDisasm)
{
  if (!Security(2, pMyDisasm)) return;
  GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
  /* ========= 0xf3 */
  if (GV.PrefRepe == 1) {
    if (GV.REGOPCODE == 0) {
      if (GV.Architecture != 64) { failDecode(pMyDisasm); return; }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) { failDecode(pMyDisasm); return; }
      pMyDisasm->Instruction.Category = FSGSBASE_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rdfsbase");
      #endif
      GV.OperandSize = (GV.REX.W_ == 1) ? 64 : 32;
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      pMyDisasm->Operand2.OpType = REGISTER_TYPE;
      pMyDisasm->Operand2.OpSize = (GV.REX.W_ == 1) ? 64 : 32;
      pMyDisasm->Operand2.Registers.type = SEGMENT_REG;
      pMyDisasm->Operand2.Registers.segment = REG4;
    }
    else if (GV.REGOPCODE == 1) {
      if (GV.Architecture != 64) { failDecode(pMyDisasm); return; }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) { failDecode(pMyDisasm); return; }
      pMyDisasm->Instruction.Category = FSGSBASE_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rdgsbase");
      #endif
      GV.OperandSize = (GV.REX.W_ == 1) ? 64 : 32;
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      pMyDisasm->Operand2.OpType = REGISTER_TYPE;
      pMyDisasm->Operand2.OpSize = (GV.REX.W_ == 1) ? 64 : 32;
      pMyDisasm->Operand2.Registers.type = SEGMENT_REG;
      pMyDisasm->Operand2.Registers.segment = REG5;
    }
    else if (GV.REGOPCODE == 2) {
      if (GV.Architecture != 64) { failDecode(pMyDisasm); return; }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) { failDecode(pMyDisasm); return; }
      pMyDisasm->Instruction.Category = FSGSBASE_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "wrfsbase");
      #endif
      GV.OperandSize = (GV.REX.W_ == 1) ? 64 : 32;
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      pMyDisasm->Operand1.OpType = REGISTER_TYPE;
      pMyDisasm->Operand1.OpSize = (GV.REX.W_ == 1) ? 64 : 32;
      pMyDisasm->Operand1.Registers.type = SEGMENT_REG;
      pMyDisasm->Operand1.Registers.segment = REG4;
    }
    else if (GV.REGOPCODE == 3) {
      if (GV.Architecture != 64) { failDecode(pMyDisasm); return; }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) { failDecode(pMyDisasm); return; }
      pMyDisasm->Instruction.Category = FSGSBASE_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "wrgsbase");
      #endif
      GV.OperandSize = (GV.REX.W_ == 1) ? 64 : 32;
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      pMyDisasm->Operand1.OpType = REGISTER_TYPE;
      pMyDisasm->Operand1.OpSize = (GV.REX.W_ == 1) ? 64 : 32;
      pMyDisasm->Operand1.Registers.type = SEGMENT_REG;
      pMyDisasm->Operand1.Registers.segment = REG5;
    }
    else if (GV.REGOPCODE == 4) {
      if (pMyDisasm->Prefix.OperandSize == InUsePrefix) GV.ERROR_OPCODE = UD_;
      pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ptwrite");
      #endif
      GV.MemDecoration = (GV.REX.W_ == 1) ? Arg1qword : Arg1dword;
      GV.OperandSize = (GV.REX.W_ == 1) ? 64 : 32;
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      pMyDisasm->Operand1.AccessMode = READ;
    }
    else if (GV.REGOPCODE == 5) {
      pMyDisasm->Instruction.Category = CET_INSTRUCTION;
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) { failDecode(pMyDisasm); return; }
      if ((GV.REX.state == InUsePrefix) && (GV.REX.W_ == 1)) {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "incsspq");
        #endif
      }
      else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "incsspd");
        #endif
      }
      GV.OperandSize = (GV.REX.W_ == 1) ? 64 : 32;
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      pMyDisasm->Operand1.OpType = REGISTER_TYPE;
      pMyDisasm->Operand1.OpSize = 64;
      pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
      pMyDisasm->Operand1.Registers.special = REG2; /* SSP reg */
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  /* ========= 0x66 */
  else if (pMyDisasm->Prefix.OperandSize == InUsePrefix) {
    GV.OperandSize = GV.OriginalOperandSize;
    pMyDisasm->Prefix.OperandSize = MandatoryPrefix;
    if (GV.REGOPCODE == 6) {
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) {
        pMyDisasm->Instruction.Category = CLWB_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "clwb");
        #endif
        GV.MemDecoration = Arg1byte;

        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      }
      else  {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.REGOPCODE == 7) {
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) {
        pMyDisasm->Instruction.Category = CLFLUSHOPT_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "clflushopt");
        #endif
        GV.MemDecoration = Arg1byte;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else {
    if (GV.REGOPCODE == 0) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_ != 0x3) {
        GV.MemDecoration = Arg1multibytes;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        pMyDisasm->Instruction.Category = FXSR_INSTRUCTION;
        if (GV.REX.W_ == 1) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "fxsave64");
          #endif
        }
        else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "fxsave");
          #endif
        }
        pMyDisasm->Operand1.OpSize = 512 * 8;
        pMyDisasm->Instruction.ImplicitUsedRegs.type = FPU_REG + SSE_REG + MMX_REG;
        pMyDisasm->Instruction.ImplicitUsedRegs.fpu = REG0+REG1+REG2+REG3+REG4+REG5+REG6+REG7;
        pMyDisasm->Instruction.ImplicitUsedRegs.mmx = REG0+REG1+REG2+REG3+REG4+REG5+REG6+REG7;
        pMyDisasm->Instruction.ImplicitUsedRegs.xmm = REG0+REG1+REG2+REG3+REG4+REG5+REG6+REG7;
        pMyDisasm->Instruction.ImplicitUsedRegs.special = REG1; /* MXCSR Register */
      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.REGOPCODE == 1) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_!= 0x3) {
        GV.MemDecoration = Arg1multibytes;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        pMyDisasm->Instruction.Category = FXSR_INSTRUCTION;
        if (GV.REX.W_ == 1) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "fxrstor64");
          #endif
        }
        else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "fxrstor");
          #endif
        }
        pMyDisasm->Operand1.OpSize = 512 * 8;
        pMyDisasm->Operand1.AccessMode = READ;
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = FPU_REG + SSE_REG + MMX_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.fpu = REG0+REG1+REG2+REG3+REG4+REG5+REG6+REG7;
        pMyDisasm->Instruction.ImplicitModifiedRegs.mmx = REG0+REG1+REG2+REG3+REG4+REG5+REG6+REG7;
        pMyDisasm->Instruction.ImplicitModifiedRegs.xmm = REG0+REG1+REG2+REG3+REG4+REG5+REG6+REG7;
        pMyDisasm->Instruction.ImplicitModifiedRegs.special = REG1; /* MXCSR Register */

      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.REGOPCODE == 2) {
      if (GV.EVEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      if ((GV.VEX.state == InUsePrefix) && (GV.VEX.L != 0)) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_!= 0x3) {
        GV.MemDecoration = Arg2dword;
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        if (GV.VEX.state == InUsePrefix) {
          pMyDisasm->Instruction.Category = AVX_INSTRUCTION+STATE_MANAGEMENT;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vldmxcsr");
          #endif
        }
        else {
          pMyDisasm->Instruction.Category = SSE_INSTRUCTION+STATE_MANAGEMENT;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "ldmxcsr");
          #endif
        }
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand1.Registers.special = REG1;
        pMyDisasm->Operand1.OpSize = 32;
      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.REGOPCODE == 3) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_!= 0x3) {
        GV.MemDecoration = Arg1dword;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        if (GV.VEX.state == InUsePrefix) {
          pMyDisasm->Instruction.Category = AVX_INSTRUCTION+STATE_MANAGEMENT;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vstmxcsr");
          #endif
        }
        else {
          pMyDisasm->Instruction.Category = SSE_INSTRUCTION+STATE_MANAGEMENT;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "stmxcsr");
          #endif
        }
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand1.Registers.special = REG1;
        pMyDisasm->Operand2.OpSize = 32;
      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.REGOPCODE == 4) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      if (GV.MOD_!= 0x3) {
        GV.MemDecoration = Arg1multibytes;
        pMyDisasm->Instruction.Category = XSAVE_INSTRUCTION;
        if (GV.REX.W_ == 1) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xsave64");
          #endif
        }
        else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xsave");
          #endif
        }
        pMyDisasm->Operand1.OpSize = 512 * 8;
        pMyDisasm->Operand1.AccessMode = WRITE;
        pMyDisasm->Instruction.ImplicitUsedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitUsedRegs.gpr = REG0 + REG2;
      }
      else {
        failDecode(pMyDisasm);
      }
    }

    else if (GV.REGOPCODE == 5) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_== 0x3) {
        pMyDisasm->Instruction.Category = SSE2_INSTRUCTION+CACHEABILITY_CONTROL;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "lfence");
        #endif
      }
      else {
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        GV.MemDecoration = Arg1multibytes;
        pMyDisasm->Instruction.Category = XSAVE_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xrstor");
        #endif
        pMyDisasm->Operand1.OpSize = 512 * 8;
        pMyDisasm->Operand1.AccessMode = READ;
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.gpr = REG0 | REG2;
      }
    }
    else if (GV.REGOPCODE == 6) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_== 0x3) {
        pMyDisasm->Instruction.Category = SSE2_INSTRUCTION+CACHEABILITY_CONTROL;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "mfence");
        #endif
      }
      else {
        pMyDisasm->Instruction.Category = XSAVEOPT_INSTRUCTION;
        if (GV.REX.W_ == 1) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xsaveopt64");
          #endif
        }
        else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xsaveopt");
          #endif
        }
        GV.MemDecoration = Arg1multibytes;
        decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
        pMyDisasm->Operand1.OpSize = 512 * 8;
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type =  GENERAL_REG;
        pMyDisasm->Operand2.Registers.gpr = REG0 + REG2;
      }
    }
    else if (GV.REGOPCODE == 7) {
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
      if (GV.MOD_== 0x3) {
        pMyDisasm->Instruction.Category = SSE2_INSTRUCTION+CACHEABILITY_CONTROL;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sfence");
        #endif
      }
      else {
        GV.OperandSize = 8;
        decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        GV.OperandSize = 32;
        GV.MemDecoration = Arg2byte;
        pMyDisasm->Instruction.Category = SSE2_INSTRUCTION+CACHEABILITY_CONTROL;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "clflush");
        #endif
      }
    }
    else {
      failDecode(pMyDisasm);
    }
    GV.EIP_+= GV.DECALAGE_EIP+2;
  }
}
