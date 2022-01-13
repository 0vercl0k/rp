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

        # VEX.128.F3.0F38.W0 5C 11:rrr:bbb
        # TDPBF16PS tmm1, tmm2, tmm3

        myVEX = VEX('VEX.128.F3.0F38.W0')
        myVEX.vvvv = 0b1111
        myVEX.R = 0b1
        Buffer = bytes.fromhex('{}5cc0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5c)
        assert_equal(myDisasm.infos.Instruction.Category, AMX_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'tdpbf16ps')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.tmm, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 8192)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)
        assert_equal(myDisasm.infos.Operand2.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand2.Registers.tmm, REG0)
        assert_equal(myDisasm.infos.Operand2.OpSize, 8192)
        assert_equal(myDisasm.infos.Operand2.AccessMode, READ)
        assert_equal(myDisasm.infos.Operand3.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand3.Registers.tmm, REG0)
        assert_equal(myDisasm.infos.Operand3.OpSize, 8192)
        assert_equal(myDisasm.infos.Operand3.AccessMode, READ)
        assert_equal(myDisasm.repr(), 'tdpbf16ps tmm0, tmm0, tmm0')
