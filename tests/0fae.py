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
    def test(self):

        # F3 0F AE /2
        # WRFSBASE r32

        Buffer = bytes.fromhex('f30faed0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrfsbase')
        assert_equal(myDisasm.repr(), 'wrfsbase eax')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.segment, REG4)

        # F3 REX.W 0F AE /2
        # WRFSBASE r64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0faed0'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrfsbase')
        assert_equal(myDisasm.repr(), 'wrfsbase rax')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.segment, REG4)

        # F3 0F AE /3
        # WRGSBASE r32

        Buffer = bytes.fromhex('f30faed8')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrgsbase')
        assert_equal(myDisasm.repr(), 'wrgsbase eax')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.segment, REG5)

        # F3 REX.W 0F AE /3
        # WRGSBASE r64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0faed8'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'wrgsbase')
        assert_equal(myDisasm.repr(), 'wrgsbase rax')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.segment, REG5)

        # F3 0F AE /0
        # RDFSBASE r32

        Buffer = bytes.fromhex('f30faec0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdfsbase')
        assert_equal(myDisasm.repr(), 'rdfsbase eax')
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.segment, REG4)

        # F3 REX.W 0F AE /0
        # RDFSBASE r64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0faec0'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdfsbase')
        assert_equal(myDisasm.repr(), 'rdfsbase rax')
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.segment, REG4)

        # F3 0F AE /1
        # RDGSBASE r32

        Buffer = bytes.fromhex('f30faec8')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdgsbase')
        assert_equal(myDisasm.repr(), 'rdgsbase eax')
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.segment, REG5)

        # F3 REX.W 0F AE /1
        # RDGSBASE r64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0faec8'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdgsbase')
        assert_equal(myDisasm.repr(), 'rdgsbase rax')
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.type, SEGMENT_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.segment, REG5)

        # F3 REX.W 0F AE /4
        # PTWRITE r64/m64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0fae20'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ptwrite')
        assert_equal(myDisasm.repr(), 'ptwrite qword ptr [rax]')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        # F3 0F AE /4
        # PTWRITE r32/m32

        Buffer = bytes.fromhex('f30fae20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ptwrite')
        assert_equal(myDisasm.repr(), 'ptwrite dword ptr [rax]')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)

        # 66 0F AE /6
        # CLWB m8

        Buffer = bytes.fromhex('660fae30')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'clwb')
        assert_equal(myDisasm.repr(), 'clwb byte ptr [rax]')

        # 66 0F AE /7
        # CLFLUSHOPT m8

        Buffer = bytes.fromhex('660fae38')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'clflushopt')
        assert_equal(myDisasm.repr(), 'clflushopt byte ptr [rax]')

        # NP 0F AE /0
        # FXSAVE m512byte

        Buffer = bytes.fromhex('0fae00')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'fxsave')
        assert_equal(myDisasm.repr(), 'fxsave  [rax]')

        # NP REX.W + 0F AE /0
        # FXSAVE64 m512byte

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('{:02x}0fae00'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'fxsave64')
        assert_equal(myDisasm.repr(), 'fxsave64  [rax]')
        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 512 * 8)


        # NP 0F AE /1
        # FXRSTOR m512byte

        Buffer = bytes.fromhex('0fae08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'fxrstor')
        assert_equal(myDisasm.repr(), 'fxrstor  [rax]')

        # NP REX.W + 0F AE /1
        # FXRSTOR64 m512byte

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('{:02x}0fae08'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'fxrstor64')
        assert_equal(myDisasm.repr(), 'fxrstor64  [rax]')
        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)

        # NP 0F AE /2
        # LDMXCSR m32

        Buffer = bytes.fromhex('0fae10')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ldmxcsr')
        assert_equal(myDisasm.repr(), 'ldmxcsr dword ptr [rax]')

        # VEX.LZ.0F.WIG AE /2
        # VLDMXCSR m32

        myVEX = VEX('VEX.LZ.0F.WIG')
        Buffer = bytes.fromhex('{}ae10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xae)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vldmxcsr')
        assert_equal(myDisasm.repr(), 'vldmxcsr dword ptr [r8]')


        # Saves the states of x87 FPU, MMX, XMM, YMM, and MXCSR registers to memory,
        # optimizing the save operation if possible.

        # NP 0F AE /6
        # XSAVEOPT mem

        Buffer = bytes.fromhex('0fae30')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xsaveopt')
        assert_equal(myDisasm.repr(), 'xsaveopt  [rax]')


        # NP REX.W + 0F AE /6
        # XSAVEOPT64 mem

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('{:02x}0fae30'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'xsaveopt64')
        assert_equal(myDisasm.repr(), 'xsaveopt64  [rax]')
        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 512 * 8)
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.type, GENERAL_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.gpr, REG0 + REG2)


        # F3 0F AE /05
        # INCSSPD r32

        Buffer = bytes.fromhex('f30faee8')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'incsspd')
        assert_equal(myDisasm.repr(), 'incsspd eax')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 64)
        assert_equal(myDisasm.infos.Operand1.Registers.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.special, REG2)

        # F3 REX.W 0F AE /05
        # INCSSPQ r64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0faee8'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'incsspq')
        assert_equal(myDisasm.repr(), 'incsspq rax')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 64)
        assert_equal(myDisasm.infos.Operand1.Registers.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.special, REG2)
