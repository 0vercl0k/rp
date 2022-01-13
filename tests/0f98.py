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

        # 0F 98
        # SETS r/m8

        Buffer = bytes.fromhex('0f9800')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f98)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sets')
        assert_equal(myDisasm.repr(), 'sets byte ptr [rax]')

        # VEX.L0.0F.W0 98 /r
        # KORTESTW k1, k2

        myVEX = VEX('VEX.L0.0F.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}98da'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x98)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kortestw')
        assert_equal(myDisasm.repr(), 'kortestw k3, k2')

        # VEX.L0.66.0F.W0 98 /r
        # KORTESTB k1, k2

        myVEX = VEX('VEX.L0.66.0F.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}98db'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x98)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kortestb')
        assert_equal(myDisasm.repr(), 'kortestb k3, k3')

        # VEX.L0.0F.W1 98 /r
        # KORTESTQ k1, k2

        myVEX = VEX('VEX.L0.0F.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}98db'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x98)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kortestq')
        assert_equal(myDisasm.repr(), 'kortestq k3, k3')

        # VEX.L0.66.0F.W1 98 /r
        # KORTESTD k1, k2

        myVEX = VEX('VEX.L0.66.0F.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}98db'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x98)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kortestd')
        assert_equal(myDisasm.repr(), 'kortestd k3, k3')
