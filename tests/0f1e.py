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


        # F3 0F 1E FA
        # ENDBR64

        Buffer = bytes.fromhex('f30f1efa')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf1e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'endbr64')
        assert_equal(myDisasm.repr(), 'endbr64')

        # F3 0F 1E FB
        # ENDBR32

        Buffer = bytes.fromhex('f30f1efb')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf1e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'endbr32')
        assert_equal(myDisasm.repr(), 'endbr32')

        # F3 0F 1E /1
        # RDSSPD R32

        Buffer = bytes.fromhex('f30f1ec8')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf1e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdsspd')
        assert_equal(myDisasm.repr(), 'rdsspd eax')
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.OpSize, 64)
        assert_equal(myDisasm.infos.Operand2.Registers.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.special, REG2)

        # F3 REX.W 0F 1E /1
        # RDSSPQ R64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0f1ec8'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf1e')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rdsspq')
        assert_equal(myDisasm.repr(), 'rdsspq rax')
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.OpSize, 64)
        assert_equal(myDisasm.infos.Operand2.Registers.type, SPECIAL_REG)
        assert_equal(myDisasm.infos.Operand2.Registers.special, REG2)
