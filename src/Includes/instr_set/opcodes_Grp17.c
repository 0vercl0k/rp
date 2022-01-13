/*
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
 *
 * @author : beaengine@gmail.com
 */

/* ====================================================================
 *
 * ==================================================================== */
void __bea_callspec__ G17_(PDISASM pMyDisasm)
{
  if (!Security(2, pMyDisasm)) return;
  GV.REGOPCODE = ((*((UInt8*) (GV.EIP_+1))) >> 3) & 0x7;
  if (GV.REGOPCODE == 1) {
    if (GV.VEX.state == InUsePrefix) {
      pMyDisasm->Instruction.Category = AVX_INSTRUCTION + LOGICAL_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "blsr");
      #endif
      if (GV.VEX.opcode == 0xc4) {
        /* using VEX3Bytes */
        if (GV.REX.W_ == 0x1) {
          GV.OperandSize = 64;
          GV.MemDecoration = Arg2qword;
          fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
          decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        }
        else {
          GV.MemDecoration = Arg2dword;
          fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
          decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        }
      }
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else if (GV.REGOPCODE == 2) {
    if (GV.VEX.state == InUsePrefix) {
      pMyDisasm->Instruction.Category = AVX_INSTRUCTION + LOGICAL_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "blmsk");
      #endif
      if (GV.VEX.opcode == 0xc4) {
        /* using VEX3Bytes */
        if (GV.REX.W_ == 0x1) {
            GV.OperandSize = 64;
            GV.MemDecoration = Arg2qword;
            fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
            decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        }
        else {
            GV.MemDecoration = Arg2dword;
            fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
            decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        }
      }
    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else if (GV.REGOPCODE == 3) {
    if (GV.VEX.state == InUsePrefix) {
      pMyDisasm->Instruction.Category = AVX_INSTRUCTION + LOGICAL_INSTRUCTION;
      #ifndef BEA_LIGHT_DISASSEMBLY
         (void) strcpy (pMyDisasm->Instruction.Mnemonic, "blsi");
      #endif
      if (GV.VEX.opcode == 0xc4) {
        /* using VEX3Bytes */
        if (GV.REX.W_ == 0x1) {
          GV.OperandSize = 64;
          GV.MemDecoration = Arg2qword;
          fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
          decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        }
        else {
          GV.MemDecoration = Arg2dword;
          fillRegister((~GV.VEX.vvvv & 0xF) + 16 * GV.EVEX.V, &pMyDisasm->Operand1, pMyDisasm);
          decodeModrm(&pMyDisasm->Operand2, pMyDisasm);
        }
      }

    }
    else {
      failDecode(pMyDisasm);
    }
  }
  else {
    failDecode(pMyDisasm);
  }
  GV.EIP_+= GV.DECALAGE_EIP + 2;
}
