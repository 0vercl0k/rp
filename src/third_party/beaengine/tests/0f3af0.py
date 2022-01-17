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



        # VEX.LZ.F2.0F3A.W0 F0 /r ib
        # RORX r32, r/m32, imm8

        myVEX = VEX('VEX.LZ.F2.0F3A.W0')
        Buffer = bytes.fromhex('{}f01033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rorx')
        assert_equal(myDisasm.repr(), 'rorx r10d, dword ptr [r8], 33h')

        myVEX = VEX('VEX.LZ.F2.0F3A.W0')
        Buffer = bytes.fromhex('{}f0c033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rorx')
        assert_equal(myDisasm.repr(), 'rorx r8d, r8d, 33h')

        # VEX.LZ.F2.0F3A.W1 F0 /r ib
        # RORX r64, r/m64, imm8

        myVEX = VEX('VEX.LZ.F2.0F3A.W1')
        Buffer = bytes.fromhex('{}f01033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rorx')
        assert_equal(myDisasm.repr(), 'rorx r10, qword ptr [r8], 33h')

        myVEX = VEX('VEX.LZ.F2.0F3A.W1')
        Buffer = bytes.fromhex('{}f0c033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf0)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'rorx')
        assert_equal(myDisasm.repr(), 'rorx r8, r8, 33h')
