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


 void __bea_callspec__ G7_regopcode1(PDISASM pMyDisasm)
 {
 if (GV.MOD_== 0x3) {
     if (GV.RM_ == 0x00) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = SSE3_INSTRUCTION+AGENT_SYNCHRONISATION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "monitor");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x01) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = SSE3_INSTRUCTION+AGENT_SYNCHRONISATION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "mwait");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x2) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+FLAG_CONTROL_INSTRUCTION;
       pMyDisasm->Operand1.OpType = REGISTER_TYPE;
       pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
       pMyDisasm->Operand1.Registers.special = REG0;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "clac");
       #endif
       FillFlags(pMyDisasm,129);
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x3) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = GENERAL_PURPOSE_INSTRUCTION+FLAG_CONTROL_INSTRUCTION;
       pMyDisasm->Operand1.OpType = REGISTER_TYPE;
       pMyDisasm->Operand1.AccessMode = WRITE;
       pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
       pMyDisasm->Operand1.Registers.special = REG0;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "stac");
       #endif
       FillFlags(pMyDisasm,129);
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x4) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (pMyDisasm->Prefix.OperandSize == InUsePrefix) {
           pMyDisasm->Instruction.Category = VM_INSTRUCTION;
           #ifndef BEA_LIGHT_DISASSEMBLY
              (void) strcpy (pMyDisasm->Instruction.Mnemonic, "tdcall");
           #endif
           GV.EIP_+= GV.DECALAGE_EIP+2;
       }
       else {
         failDecode(pMyDisasm);
       }
     }
     else if (GV.RM_ == 0x5) {
       if (GV.VEX.state == InUsePrefix){ failDecode(pMyDisasm); return; }
       if (pMyDisasm->Prefix.OperandSize == InUsePrefix) {
           pMyDisasm->Instruction.Category = VM_INSTRUCTION;
           #ifndef BEA_LIGHT_DISASSEMBLY
              (void) strcpy (pMyDisasm->Instruction.Mnemonic, "seamret");
           #endif
           GV.EIP_+= GV.DECALAGE_EIP+2;
       }
       else {
         failDecode(pMyDisasm);
       }
     }
     else if (GV.RM_ == 0x6) {
       if (GV.VEX.state == InUsePrefix){ failDecode(pMyDisasm); return; }
       if (pMyDisasm->Prefix.OperandSize == InUsePrefix) {
           pMyDisasm->Instruction.Category = VM_INSTRUCTION;
           #ifndef BEA_LIGHT_DISASSEMBLY
              (void) strcpy (pMyDisasm->Instruction.Mnemonic, "seamops");
           #endif
           pMyDisasm->Operand1.OpType = REGISTER_TYPE;
           pMyDisasm->Operand1.OpSize = 64;
           pMyDisasm->Operand1.AccessMode = READ;
           pMyDisasm->Operand1.Registers.type = GENERAL_REG;
           pMyDisasm->Operand1.Registers.gpr = REG0;
           GV.EIP_+= GV.DECALAGE_EIP+2;
       }
       else {
         failDecode(pMyDisasm);
       }
     }
     else if (GV.RM_ == 0x7) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (pMyDisasm->Prefix.OperandSize == InUsePrefix) {
           pMyDisasm->Instruction.Category = VM_INSTRUCTION;
           #ifndef BEA_LIGHT_DISASSEMBLY
              (void) strcpy (pMyDisasm->Instruction.Mnemonic, "seamcall");
           #endif
           GV.EIP_+= GV.DECALAGE_EIP+2;
       }
       else if (GV.NB_PREFIX == 0) {
         pMyDisasm->Instruction.Category = SGX_INSTRUCTION;
         #ifndef BEA_LIGHT_DISASSEMBLY
            (void) strcpy (pMyDisasm->Instruction.Mnemonic, "encls");
         #endif
         pMyDisasm->Operand1.OpType = MEMORY_TYPE;
         pMyDisasm->Operand1.Memory.BaseRegister = REG1;

         pMyDisasm->Operand2.OpType = MEMORY_TYPE;
         pMyDisasm->Operand2.Memory.BaseRegister = REG3;

         pMyDisasm->Operand3.OpType = REGISTER_TYPE;
         pMyDisasm->Operand3.OpSize = 32;
         pMyDisasm->Operand3.Registers.type = GENERAL_REG;
         pMyDisasm->Operand3.Registers.gpr = REG0;
         /*
         Flags Affected
         CF is set if an invalid token was detected else is cleared.
         ZF, PF, AF, OF and SF are cleared.
         */
         FillFlags(pMyDisasm,130);
         GV.EIP_+= GV.DECALAGE_EIP+2;
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
     if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
     GV.MemDecoration = Arg1fword;
     decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
     pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
     #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sidt");
     #endif
     pMyDisasm->Operand2.OpType = REGISTER_TYPE;
     pMyDisasm->Operand2.Registers.type = MEMORY_MANAGEMENT_REG;
     pMyDisasm->Operand2.Registers.mem_management = REG2;
     pMyDisasm->Operand2.OpSize = 48;
     GV.EIP_+= GV.DECALAGE_EIP+2;
   }

 }

 void __bea_callspec__ G7_regopcode0(PDISASM pMyDisasm)
 {
   if (GV.MOD_== 0x3) {
     if (GV.RM_ == 0) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = SGX_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "enclv");
       #endif
       pMyDisasm->Operand1.OpType = MEMORY_TYPE;
       pMyDisasm->Operand1.Memory.BaseRegister = REG1;

       pMyDisasm->Operand2.OpType = MEMORY_TYPE;
       pMyDisasm->Operand2.Memory.BaseRegister = REG3;

       pMyDisasm->Operand3.OpType = REGISTER_TYPE;
       pMyDisasm->Operand3.OpSize = 32;
       pMyDisasm->Operand3.Registers.type = GENERAL_REG;
       pMyDisasm->Operand3.Registers.gpr = REG0;

       pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
       pMyDisasm->Instruction.ImplicitModifiedRegs.gpr = REG0;

       FillFlags(pMyDisasm,130);
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }

     else if (GV.RM_ == 0x1) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmcall");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x2) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmlaunch");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x3) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmresume");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x4) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmxoff");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x5) {
       if (GV.VEX.state == InUsePrefix){ failDecode(pMyDisasm); return; }
       if (
           (GV.PrefRepne == 1) || (GV.PrefRepe == 1)
         )
         {
           GV.ERROR_OPCODE = UD_;
         }
       pMyDisasm->Instruction.Category = PCONFIG_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "pconfig");
       #endif
       pMyDisasm->Operand1.OpType = REGISTER_TYPE;
       pMyDisasm->Operand1.Registers.type = GENERAL_REG;
       pMyDisasm->Operand1.Registers.gpr = REG0;
       pMyDisasm->Operand1.OpSize = 32;
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else {
       failDecode(pMyDisasm);
     }
   }
   else {
     if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
     GV.MemDecoration = Arg1fword;
     decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
     pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
     #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy (pMyDisasm->Instruction.Mnemonic, "sgdt");
     #endif
     pMyDisasm->Operand2.OpType = REGISTER_TYPE;
     pMyDisasm->Operand2.Registers.type = MEMORY_MANAGEMENT_REG;
     pMyDisasm->Operand2.Registers.mem_management = REG0;
     pMyDisasm->Operand2.OpSize = 48;
     GV.EIP_+= GV.DECALAGE_EIP+2;
   }
 }

void __bea_callspec__ G7_regopcode2(PDISASM pMyDisasm)
{
   if (GV.MOD_== 0x3) {
     if (GV.RM_ == 0x0) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xgetbv");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x1) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xsetbv");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x4) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmfunc");
       #endif
       pMyDisasm->Operand1.OpType = REGISTER_TYPE;
       pMyDisasm->Operand1.AccessMode = READ;
       pMyDisasm->Operand1.OpSize = 32;
       pMyDisasm->Operand1.Registers.type = GENERAL_REG;
       pMyDisasm->Operand1.Registers.gpr = REG0;
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x5) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xend");
       #endif
       pMyDisasm->Operand1.OpType = REGISTER_TYPE;
       pMyDisasm->Operand1.OpSize = 32;
       pMyDisasm->Operand1.Registers.type = GENERAL_REG;
       pMyDisasm->Operand1.Registers.gpr = REG0;
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x6) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "xtest");
       #endif
       FillFlags(pMyDisasm,134);
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x7) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       if (prefixes_present(pMyDisasm)) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = SGX_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "enclu");
       #endif
       pMyDisasm->Operand1.OpType = MEMORY_TYPE;
       pMyDisasm->Operand1.Memory.BaseRegister = REG1;

       pMyDisasm->Operand2.OpType = MEMORY_TYPE;
       pMyDisasm->Operand2.Memory.BaseRegister = REG3;

       pMyDisasm->Operand3.OpType = REGISTER_TYPE;
       pMyDisasm->Operand3.OpSize = 32;
       pMyDisasm->Operand3.Registers.type = GENERAL_REG;
       pMyDisasm->Operand3.Registers.gpr = REG0;

       pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
       pMyDisasm->Instruction.ImplicitModifiedRegs.gpr = REG0;
       /*
       Flags Affected
       RFLAGS.ZF,PF,AF,OF,SF = 0
       RFLAGS.CF,PF,AF,OF,SF = 0
       */
       FillFlags(pMyDisasm,131);
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else {
       failDecode(pMyDisasm);
     }
   }
   else {
     if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
     GV.MemDecoration = Arg2fword;
     decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
     pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
     #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy (pMyDisasm->Instruction.Mnemonic, "lgdt");
     #endif
     pMyDisasm->Operand1.OpType = REGISTER_TYPE;
     pMyDisasm->Operand1.Registers.type = MEMORY_MANAGEMENT_REG;
     pMyDisasm->Operand1.Registers.mem_management = REG0;
     pMyDisasm->Operand1.OpSize = 48;
     GV.EIP_+= GV.DECALAGE_EIP+2;
   }
}

void __bea_callspec__ G7_regopcode3(PDISASM pMyDisasm)
{
   if (GV.MOD_== 0x3) {
     if (GV.RM_ == 0x0) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmrun");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x1) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmmcall");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x2) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmload");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x3) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "vmsave");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x4) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "stgi");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x5) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "clgi");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x6) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "skinit");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else if (GV.RM_ == 0x7) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = VM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "invlpga");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
     }
     else {
         failDecode(pMyDisasm);
     }
   }
   else {
     if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
     GV.MemDecoration = Arg2fword;
     decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
     pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
     #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy (pMyDisasm->Instruction.Mnemonic, "lidt");
     #endif
     pMyDisasm->Operand1.OpType = REGISTER_TYPE;
     pMyDisasm->Operand1.Registers.type = MEMORY_MANAGEMENT_REG;
     pMyDisasm->Operand1.Registers.mem_management = REG2;
     pMyDisasm->Operand1.OpSize = 48;
     GV.EIP_+= GV.DECALAGE_EIP+2;
   }
}

void __bea_callspec__ G7_regopcode7(PDISASM pMyDisasm)
{
  if (GV.MOD_== 0x3) {
    if (GV.Architecture == 64) {
      if (GV.RM_ == 0x0) {
       if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
       pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
       #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "swapgs");
       #endif
       GV.EIP_+= GV.DECALAGE_EIP+2;
      }
      else if (GV.RM_ == 0x1) {
        if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
        pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
          (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rdtscp");
        #endif
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.gpr |= REG0 | REG1 | REG2;
        pMyDisasm->Instruction.ImplicitUsedRegs.type = SPECIAL_REG;
        pMyDisasm->Instruction.ImplicitUsedRegs.special |= REG5 | REG6;
        GV.EIP_+= GV.DECALAGE_EIP+2;
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
   if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
   GV.MemDecoration = Arg2byte;
   decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
   pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
   #ifndef BEA_LIGHT_DISASSEMBLY
      (void) strcpy (pMyDisasm->Instruction.Mnemonic, "invlpg");
   #endif
   GV.EIP_+= GV.DECALAGE_EIP+2;
 }

}

void __bea_callspec__ G7_regopcode5(PDISASM pMyDisasm)
{
  if (GV.MOD_== 3) {
    if (GV.RM_ == 2) {
      if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
      /* ========= 0xf3 */
      if (GV.PrefRepe == 1) {
        pMyDisasm->Instruction.Category = CET_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "saveprevssp");
        #endif
        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.RM_ == 4) {
      if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
      /* ========= 0xf3 */
      if (GV.PrefRepe == 1) {
        pMyDisasm->Instruction.Category = UINTR_INSTRUCTION + CONTROL_TRANSFER;
        pMyDisasm->Instruction.BranchType = RetType;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "uiret");
        #endif
        /*CF, PF, AF, ZF, SF, TF, DF, OF, NT, RF, AC, and ID*/
        FillFlags(pMyDisasm, 132);
        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
      else {
        failDecode(pMyDisasm);
      }
    }
    else if (GV.RM_ == 5) {
      if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
      /* ========= 0xf3 */
      if (GV.PrefRepe == 1) {
        pMyDisasm->Instruction.Category = UINTR_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "testui");
        #endif
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand1.Registers.special = REG0;
        pMyDisasm->Operand1.OpSize = 1;
        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand2.Registers.special = REG4;
        pMyDisasm->Operand2.OpSize = 1;

        /*CF := UIF;ZF := AF := OF := PF := SF := 0;*/
        FillFlags(pMyDisasm, 133);
        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
    }
    else if (GV.RM_ == 6) {
      if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
      if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) GV.ERROR_OPCODE = UD_;
      /* ========= 0xf3 */
      if (GV.PrefRepe == 1) {
        pMyDisasm->Instruction.Category = UINTR_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "clui");
        #endif
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand1.Registers.special = REG4;
        pMyDisasm->Operand1.OpSize = 1;
        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
      else if (GV.PrefRepne == 1) {
        /* prefix 0xf2 */
        failDecode(pMyDisasm);
      }
      else if (pMyDisasm->Prefix.OperandSize == InUsePrefix) {
        /* prefix 0x66 */
        failDecode(pMyDisasm);
      }
      else {
        /* no prefix */
        pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "rdpkru");
        #endif
        pMyDisasm->Instruction.ImplicitModifiedRegs.type = GENERAL_REG;
        pMyDisasm->Instruction.ImplicitModifiedRegs.gpr |= REG0 | REG2;

        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
    }
    else if (GV.RM_ == 7) {
      if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
      if (pMyDisasm->Prefix.LockPrefix == InvalidPrefix) {
        GV.ERROR_OPCODE = UD_;
      }
      /* ========= 0xf3 */
      if (GV.PrefRepe == 1) {
        pMyDisasm->Instruction.Category = UINTR_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "stui");
        #endif
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand1.Registers.special = REG4;
        pMyDisasm->Operand1.OpSize = 1;
        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
      else {
        pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy (pMyDisasm->Instruction.Mnemonic, "wrpkru");
        #endif
        pMyDisasm->Operand1.OpType = REGISTER_TYPE;
        pMyDisasm->Operand1.Registers.type = SPECIAL_REG;
        pMyDisasm->Operand1.Registers.special = REG3;
        pMyDisasm->Operand1.OpSize = 32;

        pMyDisasm->Operand2.OpType = REGISTER_TYPE;
        pMyDisasm->Operand2.Registers.type = GENERAL_REG;
        pMyDisasm->Operand2.Registers.gpr = REG0;
        pMyDisasm->Operand2.OpSize = 32;

        GV.EIP_+= GV.DECALAGE_EIP+2;
      }
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else {
    failDecode(pMyDisasm);
  }
}

/* ====================================================================
 *      0f01h
 * ==================================================================== */
void __bea_callspec__ G7_(PDISASM pMyDisasm)
{
  if (GV.EVEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
  if (!Security(2, pMyDisasm)) return;
  GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
  GV.MOD_= ((*((UInt8*) (GV.EIP_+1))) >> 6) & 0x3;
  GV.RM_  = (*((UInt8*) (GV.EIP_+1))) & 0x7;
  switch(GV.REGOPCODE) {
    case 0:
      G7_regopcode0(pMyDisasm);
      break;
    case 1:
      G7_regopcode1(pMyDisasm);
      break;
    case 2:
      G7_regopcode2(pMyDisasm);
      break;
    case 3:
      G7_regopcode3(pMyDisasm);
      break;
    case 4:
      if (GV.VEX.state == InUsePrefix) {
        failDecode(pMyDisasm);
        return;
      }
      GV.MemDecoration = Arg2word;
      decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
      if (GV.ERROR_OPCODE == OUT_OF_BLOCK) return;
      pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "smsw");
      #endif
      pMyDisasm->Operand1.OpType = REGISTER_TYPE;
      pMyDisasm->Operand1.Registers.type = CR_REG;
      pMyDisasm->Operand1.Registers.cr = REG0;
      pMyDisasm->Operand1.OpSize = 16;
      GV.EIP_+= GV.DECALAGE_EIP+2;
      break;
    case 5:
      G7_regopcode5(pMyDisasm);
      break;
    case 6:
      if (GV.VEX.state == InUsePrefix) { failDecode(pMyDisasm); return; }
      GV.MemDecoration = Arg1word;
      GV.OperandSize = 16;
      decodeModrm(&pMyDisasm->Operand1, pMyDisasm);
      pMyDisasm->Instruction.Category = SYSTEM_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "lmsw");
      #endif
      pMyDisasm->Operand2.OpType = REGISTER_TYPE;
      pMyDisasm->Operand2.Registers.type = CR_REG;
      pMyDisasm->Operand2.Registers.cr = REG0;
      pMyDisasm->Operand2.OpSize = 16;
      GV.EIP_+= GV.DECALAGE_EIP+2;
      break;
    case 7:
      G7_regopcode7(pMyDisasm);
  }
}
