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

        # VEX.128.NP.0F38.W0 49 !(11):000:bbb
        # LDTILECFG m512

        myVEX = VEX('VEX.128.NP.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}4900'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        print('{}4900'.format(myVEX.c4()))
        length = myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.VEX.pp, 0x0)
        assert_equal(myDisasm.infos.Reserved_.VEX.mmmmm, 0x2)
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x49)
        assert_equal(myDisasm.infos.Instruction.Category, AMX_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ldtilecfg')
        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 512)
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ)
        assert_equal(myDisasm.repr(), 'ldtilecfg  [r8]')
        assert_equal(myDisasm.length, len(Buffer))

        # VEX.128.66.0F38.W0 49 !(11):000:bbb
        # STTILECFG m512

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}4900'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x49)
        assert_equal(myDisasm.infos.Instruction.Category, AMX_INSTRUCTION)
        assert_equal(myDisasm.infos.Operand1.OpType, MEMORY_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpSize, 512)
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sttilecfg')
        assert_equal(myDisasm.repr(), 'sttilecfg  [r8]')

        # VEX.128.NP.0F38.W0 49 C0
        # TILERELEASE

        myVEX = VEX('VEX.128.NP.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}49c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x49)
        assert_equal(myDisasm.infos.Instruction.Category, AMX_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'tilerelease')
        assert_equal(myDisasm.repr(), 'tilerelease')

        # VEX.128.F2.0F38.W0 49 11:rrr:000
        # TILEZERO tmm1

        myVEX = VEX('VEX.128.F2.0F38.W0')
        myVEX.vvvv = 0b1111
        myVEX.R = 0b1
        Buffer = bytes.fromhex('{}49c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(myDisasm.length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x49)
        assert_equal(myDisasm.infos.Instruction.Category, AMX_INSTRUCTION)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'tilezero')
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.Registers.tmm, REG0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 8192)
        assert_equal(myDisasm.repr(), 'tilezero tmm0')
