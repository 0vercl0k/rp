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
 *    along with BeaEngine.  If not, see <http://www.gnu.org/licenses/>.
 * =======================================
 *
 * ======================================= */
void __bea_callspec__ decodeModrm(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  UInt8* modrm;
  GV.DECALAGE_EIP = 0;
  if (!Security(2, pMyDisasm)) return;
  modrm = (UInt8*) (GV.EIP_ + 1);
  GV.MOD_ = (*modrm >> 6) & 0x3;
  GV.RM_  = *modrm & 0x7;
  switch(GV.MOD_) {
    case 0:
      ModRM_0[GV.RM_](pMyOperand, pMyDisasm);
      break;
    case 1:
      GV.DECALAGE_EIP++;
      if (!Security(3, pMyDisasm)) return;
      ModRM_1[GV.RM_](pMyOperand, pMyDisasm);
      break;
    case 2:
      if (GV.AddressSize >= 32) {
        GV.DECALAGE_EIP += 4;
        if (!Security(6, pMyDisasm)) return;
      }
      else {
        GV.DECALAGE_EIP += 2;
        if (!Security(4, pMyDisasm)) return;
      }
      ModRM_2[GV.RM_](pMyOperand, pMyDisasm);
      break;
    case 3:
      ModRM_3[GV.RM_](pMyOperand, pMyDisasm);
  }
}

/* =======================================
 *  used in Reg_Opcode
 * ======================================= */
void __bea_callspec__ fillRegister(int index, OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    switch(GV.Register_) {
      case OPMASK_REG:
        if (index > 7) {
          GV.ERROR_OPCODE = UD_;
          index = 8;
        }
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersOpmask[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = OPMASK_REG;
        pMyOperand->Registers.opmask = REGS[index];
        pMyOperand->OpSize = 64;
        break;
      case MPX_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersMPX[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = MPX_REG;
        pMyOperand->Registers.mpx = REGS[index];
        pMyOperand->OpSize = 128;
        break;
      case AVX_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersAVX[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = AVX_REG;
        pMyOperand->Registers.ymm = REGS[index];
        pMyOperand->OpSize = 256;
        break;
      case AVX512_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersAVX512[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = AVX512_REG;
        pMyOperand->Registers.zmm = REGS[index];
        pMyOperand->OpSize = 512;
        break;
      case MMX_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersMMX[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = MMX_REG;
        pMyOperand->Registers.mmx = REGS[index];
        pMyOperand->OpSize = 64;
        break;
      case SEGMENT_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersSEG[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = SEGMENT_REG;
        pMyOperand->Registers.segment = REGS[index];
        pMyOperand->OpSize = 16;
        break;
      case CR_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersCR[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = CR_REG;
        pMyOperand->Registers.cr = REGS[index];
        pMyOperand->OpSize = 32;
        break;
      case DR_REG:
        if (GV.SYNTAX_ == ATSyntax) {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersDR_AT[index]);
            #endif
        }
        else {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersDR[index]);
            #endif
        }
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = DR_REG;
        pMyOperand->Registers.dr = REGS[index];
        pMyOperand->OpSize = 32;
        break;
      case SSE_REG:
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersSSE[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = SSE_REG;
        pMyOperand->Registers.xmm = REGS[index];
        pMyOperand->OpSize = 128;
        break;
      case TMM_REG:
        if (index > 7) {
          GV.ERROR_OPCODE = UD_;
          index = 8;
        }
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersAMX[index]);
        #endif
        pMyOperand->OpType = REGISTER_TYPE;
        pMyOperand->Registers.type = TMM_REG;
        pMyOperand->Registers.tmm = REGS[index];
        pMyOperand->OpSize = 8192;
        break;
      default:
        switch(GV.OperandSize) {
          case 8:
            OperandSize8Reg(pMyOperand, pMyDisasm, i, index);
            break;
          case 16:
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers16Bits[index]);
            #endif
            pMyOperand->OpType = REGISTER_TYPE;
            pMyOperand->Registers.type = GENERAL_REG;
            pMyOperand->Registers.gpr = REGS[index];
            pMyOperand->OpSize = 16;
            break;
          case 32:
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers32Bits[index]);
            #endif
            pMyOperand->OpType = REGISTER_TYPE;
            pMyOperand->Registers.type = GENERAL_REG;
            pMyOperand->Registers.gpr = REGS[index];
            pMyOperand->OpSize = 32;
            break;
          case 64:
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers64Bits[index]);
            #endif
            pMyOperand->OpType = REGISTER_TYPE;
            pMyOperand->Registers.type = GENERAL_REG;
            pMyOperand->Registers.gpr = REGS[index];
            pMyOperand->OpSize = 64;
        }
    }
}

void __bea_callspec__ OperandSize8Reg(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i, int index)
{
  if (GV.REX.state == 0) {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers8BitsLegacy[index]);
    #endif
    pMyOperand->OpType = REGISTER_TYPE;
    pMyOperand->Registers.type = GENERAL_REG;
    pMyOperand->Registers.gpr = REGS8BITS[index+0];
    pMyOperand->OpSize = 8;
  }
  else {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers8Bits[index]);
    #endif
    pMyOperand->OpType = REGISTER_TYPE;
    pMyOperand->Registers.type = GENERAL_REG;
    pMyOperand->Registers.gpr = REGS[index+0];
    pMyOperand->OpSize = 8;
  }
  return;
}


/* =======================================
 *
 * ======================================= */
void __bea_callspec__ decodeRegOpcode(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  if (!Security(2, pMyDisasm)) return;
  GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
  GV.REGOPCODE += 8 * GV.REX.R_ + 16 * GV.EVEX.R1;
  fillRegister(GV.REGOPCODE, pMyOperand, pMyDisasm);
}

void __bea_callspec__ fillModrm0Register(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i, UInt8 index)
{
  int index_final;
  pMyOperand->OpType = MEMORY_TYPE;
  if (GV.AddressSize == 64) {
      index_final = (GV.REX.B_ == 1) ? index + 8 : index;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers64Bits[index_final]);
      #endif
      pMyOperand->Memory.BaseRegister = REGS[index_final];
  }
  else if (GV.AddressSize == 32) {
    index_final = (GV.REX.B_ == 1) ? index + 8 : index;
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers32Bits[index_final]);
    #endif
    pMyOperand->Memory.BaseRegister = REGS[index_final];
  }
  else {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersSIB[index]);
    #endif
  }
}


/* =======================================
 *          ModRM_0
 * ======================================= */
void __bea_callspec__ Addr_EAX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    #ifndef BEA_LIGHT_DISASSEMBLY
    size_t i = 0;
    if (GV.SYNTAX_ == ATSyntax) {
     (void) strcpy((char*) pMyOperand->OpMnemonic, "(%");
     i += 2;
    }
    #endif
    fillModrm0Register(pMyOperand, pMyDisasm, i, 0);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[3];
      pMyOperand->Memory.IndexRegister = REGS[6];
    }
    #ifndef BEA_LIGHT_DISASSEMBLY
       i = strlen ((char*) &pMyOperand->OpMnemonic);
       if (GV.SYNTAX_ == ATSyntax) {
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
           i += 1;
       }
    #endif

}
/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_ECX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  #ifndef BEA_LIGHT_DISASSEMBLY
  size_t i = 0;
  if (GV.SYNTAX_ == ATSyntax) {
    (void) strcpy((char*) pMyOperand->OpMnemonic, "(%");
    i += 2;
  }
  #endif
  fillModrm0Register(pMyOperand, pMyDisasm, i, 1);
  if (GV.AddressSize == 16) {
    pMyOperand->Memory.BaseRegister = REGS[3];
    pMyOperand->Memory.IndexRegister = REGS[7];
  }
  #ifndef BEA_LIGHT_DISASSEMBLY
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      i += 1;
    }
  #endif

}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_EDX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  #ifndef BEA_LIGHT_DISASSEMBLY
  size_t i = 0;
  if (GV.SYNTAX_ == ATSyntax) {
    (void) strcpy((char*) pMyOperand->OpMnemonic, "(%");
    i += 2;
  }
  #endif
  fillModrm0Register(pMyOperand, pMyDisasm, i, 2);
  if (GV.AddressSize == 16) {
    pMyOperand->Memory.BaseRegister = REGS[5];
    pMyOperand->Memory.IndexRegister = REGS[6];
  }
  #ifndef BEA_LIGHT_DISASSEMBLY
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      i += 1;
    }
  #endif
}


/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_EBX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    #ifndef BEA_LIGHT_DISASSEMBLY
  size_t i = 0;
    if (GV.SYNTAX_ == ATSyntax) {
        (void) strcpy((char*) pMyOperand->OpMnemonic, "(%");
        i += 2;
    }
  #endif
  fillModrm0Register(pMyOperand, pMyDisasm, i, 3);
  if (GV.AddressSize == 16) {
    pMyOperand->Memory.BaseRegister = REGS[5];
    pMyOperand->Memory.IndexRegister = REGS[7];
  }
  #ifndef BEA_LIGHT_DISASSEMBLY
  i = strlen ((char*) &pMyOperand->OpMnemonic);
  if (GV.SYNTAX_ == ATSyntax) {
      (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      i += 1;
  }
  #endif

}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_SIB(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  size_t i;
  if (!Security(3, pMyDisasm)) return;
  pMyOperand->OpType = MEMORY_TYPE;
  if (GV.AddressSize >= 32) {
    GV.DECALAGE_EIP++;
    GV.BASE_  = ((UInt8) *((UInt8*) (GV.EIP_+2))) & 0x7;
    GV.SCALE_  = (((UInt8) *((UInt8*) (GV.EIP_+2))) & 0xc0) >> 6;
    GV.INDEX_  = (((UInt8) *((UInt8*) (GV.EIP_+2))) & 0x38) >> 3;
    (void) SIB[GV.SCALE_ ](pMyOperand, 0, pMyDisasm);
    if (GV.BASE_ == 4) {
      i = strlen ((char*) &pMyOperand->OpMnemonic);
      i = printDisp8(pMyOperand, i, pMyDisasm, 0);
    }
  }
  else {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy ((char*) pMyOperand->OpMnemonic, Registers16Bits[6]);
    #endif
    pMyOperand->Memory.BaseRegister = REGS[6];
  }
}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    Int32 MyNumber;
    UInt64 MyAddress;
    size_t i = 0;
    pMyOperand->OpType = MEMORY_TYPE;
    if (GV.AddressSize >= 32) {
        if (!Security(6, pMyDisasm)) return;
        GV.DECALAGE_EIP+=4;
        MyNumber = *((Int32*) (GV.EIP_+2));
        pMyOperand->Memory.Displacement = MyNumber;
        if (GV.Architecture == 64) {
            /* add len(opcode + modrm + imm32) */
            MyNumber += 6;
            /* add nb prefixes */
            MyNumber += GV.NB_PREFIX;
            /* add immediat if exists */
            if (GV.ImmediatSize == 32) {
                MyNumber += 4;
            }
            else if (GV.ImmediatSize == 16) {
                MyNumber += 2;
            }
            else if (GV.ImmediatSize == 8) {
                MyNumber += 1;
            }
            /* add len (62h + P0 + P1 + P2) - 1 */
            if (GV.EVEX.state == InUsePrefix) {
              MyNumber += 3;
            }
            else if (GV.VEX.state == InUsePrefix) {
              /* add len (c4h + byte1 + byte2) - 1 */
              if (GV.VEX.opcode == 0xc4) {
                MyNumber += 2;
              }
              /* add len (c5h + byte1) - 1 */
              else {
                MyNumber += 1;
              }
            }
            else if (pMyDisasm->Instruction.Opcode >= 0x0F3800) {      /* add two bytes if opcode is a 3-bytes */
                MyNumber +=2;
            }
            else if (pMyDisasm->Instruction.Opcode >= 0x0100) {   /* add one byte if opcode is a 2-bytes */
                MyNumber +=1;
            }
            CalculateRelativeAddress(&MyAddress, (Int64)MyNumber, pMyDisasm);
            pMyDisasm->Instruction.AddrValue = MyAddress;
            #ifndef BEA_LIGHT_DISASSEMBLY
               i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+i,"%.16llX", (Int64)MyAddress);
            #endif
            pMyOperand->OpType |= RELATIVE_;
        }
        else {
            #ifndef BEA_LIGHT_DISASSEMBLY
               i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+i,"%.8X", (Int64)MyNumber);
            #endif
        }
    }
    else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic, Registers16Bits[7]);
        #endif
        pMyOperand->Memory.BaseRegister = REGS[7];
    }
}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_ESI(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    long MyNumber;
    size_t i = 0;
    #ifndef BEA_LIGHT_DISASSEMBLY
    if (GV.SYNTAX_ == ATSyntax) {
        (void) strcpy((char*) pMyOperand->OpMnemonic, "(%");
        i += 2;
    }
     #endif
    pMyOperand->OpType = MEMORY_TYPE;
    if (GV.AddressSize == 64) {
        if (GV.REX.B_ == 1) {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers64Bits[14]);
            #endif
            pMyOperand->Memory.BaseRegister = REGS[6+8];
        }
        else {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers64Bits[6]);
            #endif
            pMyOperand->Memory.BaseRegister = REGS[6];
        }
    }
    else if (GV.AddressSize == 32) {

        if (GV.REX.B_ == 1) {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers32Bits[14]);
            #endif
            pMyOperand->Memory.BaseRegister = REGS[6+8];
        }
        else {
            #ifndef BEA_LIGHT_DISASSEMBLY
               (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers32Bits[6]);
            #endif
            pMyOperand->Memory.BaseRegister = REGS[6];
        }
    }
    else {
        GV.DECALAGE_EIP+=2;
        if (!Security(4, pMyDisasm)) return;
        MyNumber = *((UInt16*) (GV.EIP_+2));
        pMyOperand->Memory.Displacement = MyNumber;
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+i,"%.4X", (Int64)MyNumber);
        #endif
    }
    #ifndef BEA_LIGHT_DISASSEMBLY
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
    }
  #endif
}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_EDI(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    #ifndef BEA_LIGHT_DISASSEMBLY
    if (GV.SYNTAX_ == ATSyntax) {
        (void) strcpy((char*) pMyOperand->OpMnemonic, "(%");
        i += 2;
    }
    #endif

  fillModrm0Register(pMyOperand, pMyDisasm, i, 7);
  if (GV.AddressSize == 16) {
    pMyOperand->Memory.BaseRegister = REGS[3];
  }
  #ifndef BEA_LIGHT_DISASSEMBLY
  i = strlen ((char*) &pMyOperand->OpMnemonic);
  if (GV.SYNTAX_ == ATSyntax) {
      (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      i += 1;
  }
  #endif
}

long __bea_callspec__ getDisp8N(PDISASM pMyDisasm)
{
  long N;
  switch (GV.EVEX.tupletype) {
    case FULL:
      if (GV.EVEX.b == 0) {
        N = 16 * (1 << GV.VEX.L);
      }
      else {
        N = 4 * (1 << GV.EVEX.W);
      }
      break;
    case HALF:
      if (GV.EVEX.b == 0) {
        N = 8 * (1 << GV.VEX.L);
      }
      else {
        N = 4;
      }
      break;
    case FULL_MEM:
      N = 16 * (1 << GV.VEX.L);
      break;
    case TUPLE1_SCALAR:
      N = 4 * (1 << GV.EVEX.W);
      break;
    case TUPLE1_SCALAR__8:
      N = 1;
      break;
    case TUPLE1_SCALAR__16:
      N = 2;
      break;
    case TUPLE1_FIXED__32:
      N = 4;
      break;
    case TUPLE1_FIXED__64:
      N = 8;
      break;
    case TUPLE2:
      N = 8 * (1 << GV.EVEX.W);
      break;
    case TUPLE4:
      N = 16 * (1 << GV.EVEX.W);
      break;
    case TUPLE8:
      N = 32;
      break;
    case HALF_MEM:
      N = 8 * (1 << GV.VEX.L);
      break;
    case QUARTER_MEM:
      N = 4 * (1 << GV.VEX.L);
      break;
    case EIGHTH_MEM:
      N = 2 * (1 << GV.VEX.L);
      break;
    case MEM128:
      N = 16;
      break;
    case MOVDDUP:
      if (GV.VEX.L == 0) {
        N = 8;
      }
      else if (GV.VEX.L == 1) {
        N = 32;
      }
      else if (GV.VEX.L == 2) {
        N = 64;
      }
      else {
        N = -1;
      }
      break;
    default:
      N = -1;
  }
  return N;
}

const char * __bea_callspec__ getNumFormat(long MyNumber)
{
  if ((MyNumber > -127) && (MyNumber < 128)) {
    return "%.2X";
  }
  else {
    return "%.4X";
  }
}

long __bea_callspec__ specificPop(PDISASM pMyDisasm)
{
  long N;
  if (pMyDisasm->Instruction.Opcode == 0x8f) {
      N = GV.OperandSize / 8;
    }
    else {
      N = 0;
    }
    return N;
}

size_t __bea_callspec__ printDisp8(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm, long MyNumber)
{
  size_t j;
  long N;

  if ((GV.EVEX.state == InUsePrefix) && (GV.EVEX.tupletype != 0)) {
    N = getDisp8N(pMyDisasm);
    if (N != -1) MyNumber = MyNumber * N;
  }
  if ((GV.RM_ == 4) && (GV.BASE_ == 4) && (GV.Architecture >=32)) {
    MyNumber += specificPop(pMyDisasm);
  }
  if (MyNumber < 0) {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, "-");
    #endif
    i++;
    j=i;
    #ifndef BEA_LIGHT_DISASSEMBLY
       i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+j, getNumFormat(MyNumber), (Int64) ~MyNumber+1);
    #endif
  }
  else {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, "+");
    #endif
    i ++;
    j=i;
    #ifndef BEA_LIGHT_DISASSEMBLY
       i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+j, getNumFormat(MyNumber), (Int64) MyNumber);
    #endif
  }
  return i;
}


size_t __bea_callspec__ printDisp32(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm, long MyNumber)
{
  size_t j;

  if ((GV.RM_ == 4) && (GV.BASE_ == 4) && (GV.Architecture >=32)) {
    MyNumber += specificPop(pMyDisasm);
  }

  if (MyNumber < 0) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "-");
      #endif
      i ++;
      j=i;
      #ifndef BEA_LIGHT_DISASSEMBLY
         i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+j,"%.8X",(Int64) ~MyNumber+1);
      #endif
  }
  else {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, "+");
    #endif
    i ++;
      j = i;
      #ifndef BEA_LIGHT_DISASSEMBLY
         i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+j,"%.8X",(Int64) MyNumber);
      #endif
  }

  return i;
}


/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_EAX_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    MyNumber = *((Int8*) (GV.EIP_+2));
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 0);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[3];
      pMyOperand->Memory.IndexRegister = REGS[6];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_ECX_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    MyNumber = *((Int8*) GV.EIP_+2);
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 1);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[3];
      pMyOperand->Memory.IndexRegister = REGS[7];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_EDX_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    MyNumber = *((Int8*) (GV.EIP_+2));
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 2);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[5];
      pMyOperand->Memory.IndexRegister = REGS[6];
    }

    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }

}

/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_EBX_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    MyNumber = *((Int8*) (GV.EIP_+2));
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }

    fillModrm0Register(pMyOperand, pMyDisasm, i, 3);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[5];
      pMyOperand->Memory.IndexRegister = REGS[7];
    }

    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
      (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      i += 1;
      #endif
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }

}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_SIB_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0, j;
    long MyNumber;

    if (GV.AddressSize >= 32) {
        if (!Security(4, pMyDisasm)) return;
        MyNumber = *((Int8*) (GV.EIP_+3));
    }
    else {
        if (!Security(3, pMyDisasm)) return;
        MyNumber = *((Int8*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }
    pMyOperand->OpType = MEMORY_TYPE;
    if (GV.AddressSize >= 32) {
        GV.DECALAGE_EIP++;
        GV.BASE_  = (*((UInt8*) (GV.EIP_+2))) & 0x7;
        GV.SCALE_  = ((*((UInt8*) (GV.EIP_+2))) & 0xc0) >> 6;
        GV.INDEX_  = ((*((UInt8*) (GV.EIP_+2))) & 0x38) >> 3;
        j = i;
        i += SIB[GV.SCALE_ ](pMyOperand, j, pMyDisasm);
    }
    else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic, Registers16Bits[6]);
        #endif
        i += strlen (Registers16Bits[6]);
        pMyOperand->Memory.BaseRegister = REGS[6];

    }

    if (GV.SYNTAX_ == ATSyntax) {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        #endif
        i++;
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }

}

/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_EBP_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    MyNumber = *((Int8*) (GV.EIP_+2));
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }

    fillModrm0Register(pMyOperand, pMyDisasm, i, 5);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.IndexRegister = REGS[7];
    }

    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_ESI_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    MyNumber = *((Int8*) (GV.EIP_+2));
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 6);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[5];
    }

    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    }

}

/* =======================================
 *          ModRM_1
 * ======================================= */
void __bea_callspec__ Addr_EDI_disp8(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  size_t i = 0;
  long MyNumber;
  MyNumber = *((Int8*) (GV.EIP_+2));
  pMyOperand->Memory.Displacement = MyNumber;
  if (GV.SYNTAX_ == ATSyntax) {
    i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
    #endif
    i+=2;
  }
  fillModrm0Register(pMyOperand, pMyDisasm, i, 7);
  if (GV.AddressSize == 16) {
    pMyOperand->Memory.BaseRegister = REGS[3];
  }

  i = strlen ((char*) &pMyOperand->OpMnemonic);
  if (GV.SYNTAX_ == ATSyntax) {
    #ifndef BEA_LIGHT_DISASSEMBLY
    (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
    i += 1;
    #endif
  }
  else {
    i = printDisp8(pMyOperand, i, pMyDisasm, MyNumber);
  }

}

/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_EAX_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
        i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);

        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
        #endif
        i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 0);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[3];
      pMyOperand->Memory.IndexRegister = REGS[6];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
}


/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_ECX_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
        i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
        #endif
        i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 1);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[3];
      pMyOperand->Memory.IndexRegister = REGS[7];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_EDX_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 2);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[5];
      pMyOperand->Memory.IndexRegister = REGS[6];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_EBX_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);

      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 3);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[5];
      pMyOperand->Memory.IndexRegister = REGS[7];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *
 * ======================================= */
void __bea_callspec__ Addr_SIB_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0, j;
    long MyNumber;

    if (GV.AddressSize >= 32) {
        if (!Security(7, pMyDisasm)) return;
        MyNumber = *((Int32*) (GV.EIP_+3));
    }
    else {
        if (!Security(4, pMyDisasm)) return;
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
    pMyOperand->OpType = MEMORY_TYPE;
    if (GV.AddressSize >= 32) {
        GV.DECALAGE_EIP++;
        GV.BASE_  = ((UInt8) *((UInt8*) GV.EIP_+2)) & 0x7;
        GV.SCALE_  = (((UInt8) *((UInt8*) GV.EIP_+2)) & 0xc0) >> 6;
        GV.INDEX_  = (((UInt8) *((UInt8*) GV.EIP_+2)) & 0x38) >> 3;
        j = i;
        i += SIB[GV.SCALE_ ](pMyOperand, j, pMyDisasm);
    }
    else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy ((char*) pMyOperand->OpMnemonic, Registers16Bits[6]);
        #endif
        pMyOperand->Memory.BaseRegister = REGS[6];
        i += strlen (Registers16Bits[6]);
    }

    if (GV.SYNTAX_ == ATSyntax) {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        #endif
        i += 1;
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }

}

/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_EBP_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 5);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.IndexRegister = REGS[7];
    }
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
      #endif
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
}

/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_ESI_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 6);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[5];
    }
    #ifndef BEA_LIGHT_DISASSEMBLY
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
    #endif
}

/* =======================================
 *          ModRM_2
 * ======================================= */
void __bea_callspec__ Addr_EDI_disp32(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
    size_t i = 0;
    long MyNumber;
    if (GV.AddressSize == 16) {
        MyNumber = *((Int16*) (GV.EIP_+2));
    }
    else{
        MyNumber = *((Int32*) (GV.EIP_+2));
    }
    pMyOperand->Memory.Displacement = MyNumber;
    if (GV.SYNTAX_ == ATSyntax) {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i+=2;
    }
    fillModrm0Register(pMyOperand, pMyDisasm, i, 7);
    if (GV.AddressSize == 16) {
      pMyOperand->Memory.BaseRegister = REGS[3];
    }
    #ifndef BEA_LIGHT_DISASSEMBLY
    i = strlen ((char*) &pMyOperand->OpMnemonic);
    if (GV.SYNTAX_ == ATSyntax) {
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
        i += 1;
    }
    else {
      i = printDisp32(pMyOperand, i, pMyDisasm, MyNumber);
    }
    #endif
}

void __bea_callspec__ fillModrm3Register(OPTYPE* pMyOperand, PDISASM pMyDisasm, UInt8 index)
{
  size_t i = 0;
  int index_final;
  GV.MemDecoration = 0;

  if (GV.Register_ == OPMASK_REG) {
    #ifndef BEA_LIGHT_DISASSEMBLY
      (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersOpmask[index]);
    #endif
    if (index > 8) GV.ERROR_OPCODE = UD_;
    pMyOperand->OpType = REGISTER_TYPE;
    pMyOperand->Registers.type = OPMASK_REG;
    pMyOperand->Registers.opmask = REGS[index];
    pMyOperand->OpSize = 64;
    return;
  }
  switch (GV.Register_) {
    case AVX512_REG:
      if (
          (GV.EVEX.state == InUsePrefix) &&
          (GV.EVEX.X == 1)
        ) {
        index_final = (GV.REX.B_ == 1) ? index + 8 + 16 : index + 0 + 16;
      }
      else {
        index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersAVX512[index_final]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = AVX512_REG;
      pMyOperand->Registers.zmm = REGS[index_final];
      pMyOperand->OpSize = 512;
      break;
    case AVX_REG:
      if (
          (GV.EVEX.state == InUsePrefix) &&
          (GV.EVEX.X == 1)
        ) {
        index_final = (GV.REX.B_ == 1) ? index + 8 + 16 : index + 0 + 16;
      }
      else {
        index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersAVX[index_final]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = AVX_REG;
      pMyOperand->Registers.ymm = REGS[index_final];
      pMyOperand->OpSize = 256;
      break;
    case MPX_REG:
      index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersMPX[index_final]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = MPX_REG;
      pMyOperand->Registers.mpx = REGS[index_final];
      pMyOperand->OpSize = 128;
      break;
    case MMX_REG:
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersMMX[index+0]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = MMX_REG;
      pMyOperand->Registers.mmx = REGS[index+0];
      pMyOperand->OpSize = 64;
      break;
    case SSE_REG:
      if (
          (GV.EVEX.state == InUsePrefix) &&
          (GV.EVEX.X == 1)
        ) {
        index_final = (GV.REX.B_ == 1) ? index + 8 + 16 : index + 0 + 16;
      }
      else {
        index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
        (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersSSE[index_final]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = SSE_REG;
      pMyOperand->Registers.xmm = REGS[index_final];
      pMyOperand->OpSize = 128;
      break;
    case TMM_REG:
      if (index > 7) {
        GV.ERROR_OPCODE = UD_;
        index = 8;
      }
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy ((char*) pMyOperand->OpMnemonic+i, RegistersAMX[index]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = TMM_REG;
      pMyOperand->Registers.tmm = REGS[index];
      pMyOperand->OpSize = 8192;
      break;
    default:
      switch (GV.OperandSize) {
        case 64:
          index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers64Bits[index_final]);
          #endif
          pMyOperand->OpType = REGISTER_TYPE;
          pMyOperand->Registers.type = GENERAL_REG;
          pMyOperand->Registers.gpr = REGS[index_final];
          pMyOperand->OpSize = 64;
          break;
        case 32:
          index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers32Bits[index_final]);
          #endif
          pMyOperand->OpType = REGISTER_TYPE;
          pMyOperand->Registers.type = GENERAL_REG;
          pMyOperand->Registers.gpr = REGS[index_final];
          pMyOperand->OpSize = 32;
          break;

        case 16:
          index_final = (GV.REX.B_ == 1) ? index + 8 : index + 0;
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers16Bits[index_final]);
          #endif
          pMyOperand->OpType = REGISTER_TYPE;
          pMyOperand->Registers.type = GENERAL_REG;
          pMyOperand->Registers.gpr = REGS[index_final];
          pMyOperand->OpSize = 16;
          break;
        case 8:
          OperandSize8RM(pMyOperand, pMyDisasm, i, index);
      }
  }

}

void __bea_callspec__ OperandSize8RM(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i, int index)
{
  if (GV.REX.B_ == 1) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers8Bits[index+8]);
      #endif
      pMyOperand->OpType = REGISTER_TYPE;
      pMyOperand->Registers.type = GENERAL_REG;
      pMyOperand->Registers.gpr = REGS[index+8];
      pMyOperand->OpSize = 8;
  }
  else {
      if (GV.REX.state == 0) {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers8BitsLegacy[index+0]);
          #endif
          pMyOperand->OpType = REGISTER_TYPE;
          pMyOperand->Registers.type = GENERAL_REG;
          pMyOperand->Registers.gpr = REGS8BITS[index+0];
          pMyOperand->OpSize = 8;
      }
      else {
          #ifndef BEA_LIGHT_DISASSEMBLY
             (void) strcpy ((char*) pMyOperand->OpMnemonic+i, Registers8Bits[index+0]);
          #endif
          pMyOperand->OpType = REGISTER_TYPE;
          pMyOperand->Registers.type = GENERAL_REG;
          pMyOperand->Registers.gpr = REGS[index+0];
          pMyOperand->OpSize = 8;
      }
  }

}

/* =======================================
 *          ModRM_3
 * ======================================= */
void __bea_callspec__ _rEAX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 0);
}

void __bea_callspec__ _rECX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 1);
}

void __bea_callspec__ _rEDX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 2);
}

void __bea_callspec__ _rEBX(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 3);
}

void __bea_callspec__ _rESP(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 4);
}

void __bea_callspec__ _rEBP(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 5);
}

void __bea_callspec__ _rESI(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 6);
}

void __bea_callspec__ _rEDI(OPTYPE* pMyOperand, PDISASM pMyDisasm)
{
  fillModrm3Register(pMyOperand, pMyDisasm, 7);
}

/* =======================================
 *              SIB
 * ======================================= */

size_t __bea_callspec__ interpretBase(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm)
{
  size_t j;
  if ((GV.BASE_  == 5) && (GV.MOD_ == 0)) {
    GV.DECALAGE_EIP += 4;
    if (!Security(7, pMyDisasm)) return i;
    j = i;
    #ifndef BEA_LIGHT_DISASSEMBLY
       i+= CopyFormattedNumber(pMyDisasm, (char*) pMyOperand->OpMnemonic+j,"%.8X",(Int64) *((UInt32*) (GV.EIP_+3)));
    #endif
    pMyOperand->Memory.Displacement = *((UInt32*) (GV.EIP_+3));
  }
  else {
    if (GV.SYNTAX_ == ATSyntax) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(%");
      #endif
      i += 2;
    }
    if (GV.AddressSize == 64) {
      if (GV.REX.B_ == 0) {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers64Bits[GV.BASE_ ]);
        #endif
        pMyOperand->Memory.BaseRegister = REGS[GV.BASE_ ];
        i += strlen(Registers64Bits[GV.BASE_ ]);
      }
      else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers64Bits[GV.BASE_ +8]);
        #endif
        pMyOperand->Memory.BaseRegister = REGS[GV.BASE_ +8];
        i += strlen( Registers64Bits[GV.BASE_ +8]);
      }
    }
    else if (GV.AddressSize == 32) {
      if (GV.REX.B_ == 0) {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers32Bits[GV.BASE_ ]);
        #endif
        pMyOperand->Memory.BaseRegister = REGS[GV.BASE_ ];
        i += strlen( Registers32Bits[GV.BASE_ ]);
      }
      else {
        #ifndef BEA_LIGHT_DISASSEMBLY
           (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers32Bits[GV.BASE_ +8]);
        #endif
        pMyOperand->Memory.BaseRegister = REGS[GV.BASE_ +8];
        i += strlen( Registers32Bits[GV.BASE_ +8]);
      }
    }
  }
  return i;
}

size_t __bea_callspec__ interpretIndex(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm, UInt8 scale)
{
  if (GV.INDEX_  != 4 || GV.REX.X_) {
      i = printSeparator(pMyOperand, i, pMyDisasm);

      if (GV.AddressSize == 64) {
          if (GV.REX.X_ == 0) {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers64Bits[GV.INDEX_ ]);
              #endif
              pMyOperand->Memory.IndexRegister = REGS[GV.INDEX_ ];
              i += strlen( Registers64Bits[GV.INDEX_ ]);
          }
          else {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers64Bits[GV.INDEX_ +8]);
              #endif
              pMyOperand->Memory.IndexRegister = REGS[GV.INDEX_ +8];
              i += strlen( Registers64Bits[GV.INDEX_ +8]);
          }
      }
      else if (GV.AddressSize == 32) {
          if (GV.REX.X_ == 0) {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers32Bits[GV.INDEX_ ]);
              #endif
              pMyOperand->Memory.IndexRegister = REGS[GV.INDEX_ ];
              i += strlen( Registers32Bits[GV.INDEX_ ]);
          }
          else {
              #ifndef BEA_LIGHT_DISASSEMBLY
                 (void) strcpy((char*) pMyOperand->OpMnemonic+i, Registers32Bits[GV.INDEX_ +8]);
              #endif
              pMyOperand->Memory.IndexRegister = REGS[GV.INDEX_ +8];
              i += strlen( Registers32Bits[GV.INDEX_ +8]);
          }
      }
      pMyOperand->Memory.Scale = scale;
      if (scale != 1) {
        if (GV.SYNTAX_ == ATSyntax) {
          if ((GV.BASE_  != 5) || (GV.INDEX_  != 4 || GV.REX.X_)) {
            #ifndef BEA_LIGHT_DISASSEMBLY
              char str[5] = "";
              (void) sprintf(str, ",%d", scale);
              (void) strcpy((char*) pMyOperand->OpMnemonic+i, str);
            #endif
            i+=2;
          }
        }
        else {
          #ifndef BEA_LIGHT_DISASSEMBLY
            char str[5] = "";
            (void) sprintf(str, "*%d", scale);
            (void) strcpy((char*) pMyOperand->OpMnemonic+i, str);
          #endif
          i+=2;
        }
      }

  }
  if ((GV.SYNTAX_ == ATSyntax) && ((GV.BASE_  != 5) || (GV.INDEX_  != 4 || GV.REX.X_))) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      #endif
      i++;
  }
  return i;

}



size_t __bea_callspec__ printVSIBRegisters(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i, Int32 index)
{

  if (GV.VSIB_ == SSE_REG) {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, RegistersSSE[index]);
    #endif
    i += strlen( RegistersSSE[index]);
  }
  else if (GV.VSIB_ == AVX_REG) {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, RegistersAVX[index]);
    #endif
    i += strlen( RegistersAVX[index]);
  }
  else if (GV.VSIB_ == AVX512_REG) {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, RegistersAVX512[index]);
    #endif
    i += strlen( RegistersAVX512[index]);
  }
  pMyOperand->Memory.IndexRegister = REGS[index];

  return i;

}

size_t __bea_callspec__ printSIBScale(OPTYPE* pMyOperand, PDISASM pMyDisasm, size_t i, UInt8 scale)
{

  pMyOperand->Memory.Scale = scale;
  if (scale != 1) {
    if (GV.SYNTAX_ == ATSyntax) {
      if (GV.BASE_  != 5) {
        #ifndef BEA_LIGHT_DISASSEMBLY
          char str[5] = "";
          (void) sprintf(str, ",%d", scale);
          (void) strcpy((char*) pMyOperand->OpMnemonic+i, str);
        #endif
        i+=2;
      }
    }
    else {
      #ifndef BEA_LIGHT_DISASSEMBLY
        char str[5] = "";
        (void) sprintf(str, "*%d", scale);
        (void) strcpy((char*) pMyOperand->OpMnemonic+i, str);
      #endif
      i+=2;
    }
  }

  return i;

}

size_t __bea_callspec__ printSeparator(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm)
{
  if (GV.SYNTAX_ == ATSyntax) {
    if (GV.BASE_  == 5) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, "(,%");
      #endif
      i+=3;
    }
    else {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, ",%");
      #endif
      i+=2;
    }
  }
  else {
    #ifndef BEA_LIGHT_DISASSEMBLY
       (void) strcpy((char*) pMyOperand->OpMnemonic+i, "+");
    #endif
    i+=1;
  }
  return i;
}


size_t __bea_callspec__ interpretVSIBIndex(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm, UInt8 scale)
{
  int index_final;
  i = printSeparator(pMyOperand, i, pMyDisasm);

  if (GV.AddressSize >= 32) {
    if (
        ((GV.EVEX.state == InUsePrefix) && (GV.EVEX.X == 0)) ||
        ((GV.EVEX.state != InUsePrefix) && (GV.REX.X_ == 0))
      ) {
      index_final = (GV.EVEX.V == 0) ? GV.INDEX_ : GV.INDEX_ + 16;
    }
    else {
      index_final = (GV.EVEX.V == 0) ? GV.INDEX_ + 8 : GV.INDEX_ + 8 + 16;
    }
    i = printVSIBRegisters(pMyOperand, pMyDisasm, i, index_final);
  }
  i = printSIBScale(pMyOperand, pMyDisasm, i, scale);

  if ((GV.SYNTAX_ == ATSyntax) && (GV.BASE_  != 5)) {
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy((char*) pMyOperand->OpMnemonic+i, ")");
      #endif
      i++;
  }
  return i;
}

/* =======================================
 *
 * ======================================= */
size_t __bea_callspec__ SIB_0(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm)
{
  i = interpretBase(pMyOperand, i, pMyDisasm);
  if ((GV.VEX.state == InUsePrefix) && (GV.VSIB_ != 0)) {
    i = interpretVSIBIndex(pMyOperand, i, pMyDisasm, 1);
  }
  else {
    i = interpretIndex(pMyOperand, i, pMyDisasm, 1);
  }

  return i;
}

/* =======================================
 *
 * ======================================= */
size_t __bea_callspec__ SIB_1(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm)
{
  i = interpretBase(pMyOperand, i, pMyDisasm);
  if ((GV.VEX.state == InUsePrefix) && (GV.VSIB_ != 0)) {
    i = interpretVSIBIndex(pMyOperand, i, pMyDisasm, 2);
  }
  else {
    i = interpretIndex(pMyOperand, i, pMyDisasm, 2);
  }  return i;
}

/* =======================================
 *
 * ======================================= */
size_t __bea_callspec__ SIB_2(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm)
{
  i = interpretBase(pMyOperand, i, pMyDisasm);
  if ((GV.VEX.state == InUsePrefix) && (GV.VSIB_ != 0)) {
    i = interpretVSIBIndex(pMyOperand, i, pMyDisasm, 4);
  }
  else {
    i = interpretIndex(pMyOperand, i, pMyDisasm, 4);
  }
  return i;
}

/* =======================================
 *
 * ======================================= */
size_t __bea_callspec__ SIB_3(OPTYPE* pMyOperand, size_t i, PDISASM pMyDisasm)
{
  i = interpretBase(pMyOperand, i, pMyDisasm);
  if ((GV.VEX.state == InUsePrefix) && (GV.VSIB_ != 0)) {
    i = interpretVSIBIndex(pMyOperand, i, pMyDisasm, 8);
  }
  else {
    i = interpretIndex(pMyOperand, i, pMyDisasm, 8);
  }
  return i;

}
