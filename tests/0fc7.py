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

        # F3 0F C7
        # SENDUIPI reg

        Buffer = bytes.fromhex('f30fc7f0')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xfc7)
        assert_equal(myDisasm.infos.Instruction.Category, UINTR_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'senduipi')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.gpr, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 64)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)
        assert_equal(myDisasm.repr(), 'senduipi rax')
