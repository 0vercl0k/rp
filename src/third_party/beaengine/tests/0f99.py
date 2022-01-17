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

        # 0F 99
        # SETNS r/m8

        Buffer = bytes.fromhex('0f9900')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f99)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'setns')
        assert_equal(myDisasm.repr(), 'setns byte ptr [rax]')

        # VEX.L0.0F.W0 99 /r
        # kTESTW k1, k2

        myVEX = VEX('VEX.L0.0F.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}99da'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x99)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ktestw')
        assert_equal(myDisasm.repr(), 'ktestw k3, k2')

        # VEX.L0.66.0F.W0 99 /r
        # kTESTB k1, k2

        myVEX = VEX('VEX.L0.66.0F.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}99db'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x99)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ktestb')
        assert_equal(myDisasm.repr(), 'ktestb k3, k3')

        # VEX.L0.0F.W1 99 /r
        # kTESTQ k1, k2

        myVEX = VEX('VEX.L0.0F.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}99db'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x99)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ktestq')
        assert_equal(myDisasm.repr(), 'ktestq k3, k3')

        # VEX.L0.66.0F.W1 99 /r
        # kTESTD k1, k2

        myVEX = VEX('VEX.L0.66.0F.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}99db'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x99)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ktestd')
        assert_equal(myDisasm.repr(), 'ktestd k3, k3')
