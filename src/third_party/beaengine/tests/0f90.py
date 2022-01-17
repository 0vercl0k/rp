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


        # 0F 90
        # REX + 0F 90
        # SETO r/m8

        Buffer = bytes.fromhex('0f9000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f90)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'seto')
        assert_equal(myDisasm.repr(), 'seto byte ptr [rax]')

        Buffer = bytes.fromhex('0f90c0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f90)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'seto')
        assert_equal(myDisasm.repr(), 'seto al')

        # VEX.L0.0F.W0 90 /r
        # KMOVW k1, k2/m16

        myVEX = VEX('VEX.L0.0F.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}9020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x90')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kmovw')
        assert_equal(myDisasm.repr(), 'kmovw k4, word ptr [r8]')

        # VEX.L0.66.0F.W0 90 /r
        # KMOVB k1, k2/m8

        myVEX = VEX('VEX.L0.66.0F.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}9020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x90')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kmovb')
        assert_equal(myDisasm.repr(), 'kmovb k4, byte ptr [r8]')

        # VEX.L0.0F.W1 90 /r
        # KMOVQ k1, k2/m64

        myVEX = VEX('VEX.L0.0F.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}9020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x90')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kmovq')
        assert_equal(myDisasm.repr(), 'kmovq k4, qword ptr [r8]')

        # VEX.L0.66.0F.W1 90 /r
        # KMOVD k1, k2/m32

        myVEX = VEX('VEX.L0.66.0F.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}9020'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x90')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kmovd')
        assert_equal(myDisasm.repr(), 'kmovd k4, dword ptr [r8]')
