#!/usr/bin/python
# -*- coding: utf-8 -*-
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# @author : beaengine@gmail.com

from headers.BeaEnginePython import *
from nose.tools import *

class TestSuite:

    def check_np(self, data):
        Buffer = bytes.fromhex(f'66{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???')

        Buffer = bytes.fromhex(f'f2{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???')

        Buffer = bytes.fromhex(f'f3{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???')        

    def test(self):

        # 66 0F 01 CF
        # SEAMCALL

        Buffer = bytes.fromhex('660f01cf')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'seamcall')
        assert_equal(myDisasm.repr(), 'seamcall')

        # 66 0F 01 CE
        # SEAMOPS

        Buffer = bytes.fromhex('660f01ce')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'seamops')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.gpr, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 64)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)
        assert_equal(myDisasm.repr(), 'seamops')

        # 66 0F 01 CD
        # SEAMRET

        Buffer = bytes.fromhex('660f01cd')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'seamret')
        assert_equal(myDisasm.repr(), 'seamret')

        # 66 0F 01 CC
        # TDCALL

        Buffer = bytes.fromhex('660f01cc')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'tdcall')
        assert_equal(myDisasm.repr(), 'tdcall')

        # NP 0F 01 CA
        # CLAC

        Buffer = bytes.fromhex('0f01ca')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'clac')

        self.check_np('0f01ca')

        # NP 0F 01 CB
        # STAC

        Buffer = bytes.fromhex('0f01cb')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'stac')

        self.check_np('0f01cb')

        # NP 0F 01 C5
        # PCONFIG
        # #UD If any of the LOCK/REP/OSIZE/VEX prefixes are used.

        Buffer = bytes.fromhex('0f01c5')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pconfig')

        Buffer = bytes.fromhex('f00f01c5')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pconfig')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        Buffer = bytes.fromhex('f20f01c5')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pconfig')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        Buffer = bytes.fromhex('f30f01c5')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pconfig')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # NP 0F 01 C0
        # ENCLV

        Buffer = bytes.fromhex('0f01c0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'enclv')

        self.check_np('0f01c0')

        # NP 0F 01 D7
        # ENCLU

        Buffer = bytes.fromhex('0f01d7')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'enclu')

        self.check_np('0f01d7')

        # NP 0F 01 CF
        # ENCLS

        Buffer = bytes.fromhex('0f01cf')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'encls')

        # F3 0F 01 EA (mod=11, /5, RM=010)
        # SAVEPREVSSP

        Buffer = bytes.fromhex('f30f01ea')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Reserved_.REGOPCODE, 5)
        assert_equal(myDisasm.infos.Reserved_.MOD_, 3)
        assert_equal(myDisasm.infos.Reserved_.RM_, 2)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'saveprevssp')

        # F3 0F 01 EC
        # UIRET

        Buffer = bytes.fromhex('f30f01ec')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'uiret')
        assert_equal(myDisasm.infos.Instruction.Category, UINTR_INSTRUCTION + CONTROL_TRANSFER)
        assert_equal(myDisasm.infos.Instruction.BranchType, RetType)

        # F3 0F 01 ED
        # TESTUI

        Buffer = bytes.fromhex('f30f01ed')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, UINTR_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'testui')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.special, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 1)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.special, REG4)
        assert_equal(myDisasm.infos.Operand2.OpSize, 1)
        assert_equal(myDisasm.infos.Operand2.AccessMode, READ)

        # F3 0F 01 EE
        # CLUI

        Buffer = bytes.fromhex('f30f01ee')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, UINTR_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'clui')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.special, REG4)
        assert_equal(myDisasm.infos.Operand1.OpSize, 1)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        # F3 0F 01 EF
        # STUI

        Buffer = bytes.fromhex('f30f01ef')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, UINTR_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'stui')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.special, REG4)
        assert_equal(myDisasm.infos.Operand1.OpSize, 1)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        # 0F 01 EF
        # WRPKRU

        Buffer = bytes.fromhex('0f01ef')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrpkru')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.special, REG3)
        assert_equal(myDisasm.infos.Operand1.OpSize, 32)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.gpr, REG0)
        assert_equal(myDisasm.infos.Operand2.OpSize, 32)
        assert_equal(myDisasm.infos.Operand2.AccessMode, READ)

        Buffer = bytes.fromhex('f00f01ef')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrpkru')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # NP 0F 01 D4 (reg = 2, mod = 3, rm = 4)
        # VMFUNC

        Buffer = bytes.fromhex('0f01d4')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmfunc')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.gpr, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 32)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        self.check_np('0f01d4')

        # NP 0F 01 D5 (reg = 2, mod = 3, rm = 5)
        # XEND

        Buffer = bytes.fromhex('0f01d5')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xend')
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.gpr, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 32)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        self.check_np('0f01d5')

        # NP 0F 01 D6
        # XTEST

        Buffer = bytes.fromhex('0f01d6')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xtest')
        assert_equal(myDisasm.infos.Instruction.Category, VM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Flags.OF_, RE_)
        assert_equal(myDisasm.infos.Instruction.Flags.SF_, RE_)
        assert_equal(myDisasm.infos.Instruction.Flags.ZF_, MO_)
        assert_equal(myDisasm.infos.Instruction.Flags.AF_, RE_)
        assert_equal(myDisasm.infos.Instruction.Flags.PF_, RE_)
        assert_equal(myDisasm.infos.Instruction.Flags.CF_, RE_)
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.special, REG0)

        self.check_np('0f01d6')

        # NP 0F 01 EE (reg = 5, mod = 3, rm = 6)
        # RDPKRU

        Buffer = bytes.fromhex('0f01ee')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdpkru')
        assert_equal(myDisasm.infos.Instruction.Category, SYSTEM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.type, GENERAL_REG)
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.gpr, REG0 | REG2)

        # 0F 01 F9 (reg = 7, mod = 3, rm = 1)
        # RDTSCP

        Buffer = bytes.fromhex('0f01f9')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf01)
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdtscp')
        assert_equal(myDisasm.infos.Instruction.Category, SYSTEM_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.type, GENERAL_REG)
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.gpr, REG0 | REG1 | REG2)

        # IA32_TIME_STAMP_COUNTER
        assert_equal(myDisasm.infos.Instruction.ImplicitUsedRegs.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Instruction.ImplicitUsedRegs.special & REG5, REG5)

        # IA32_TSC_AUX
        assert_equal(myDisasm.infos.Instruction.ImplicitUsedRegs.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Instruction.ImplicitUsedRegs.special & REG6, REG6)
