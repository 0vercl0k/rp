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

        # VEX.L0.0F.W0 44 /r
        # KNOTW k1, k2

        myVEX = VEX('VEX.L0.0F.W0')
        myVEX.vvvv = 0b1101
        myVEX.R = 1
        Buffer = bytes.fromhex('{}44cb'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x44')
        assert_equal(myDisasm.infos.Reserved_.VEX.L, 0)
        assert_equal(myDisasm.infos.Reserved_.REX.W_, 0)
        assert_equal(myDisasm.infos.Reserved_.MOD_, 3)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'knotw')
        assert_equal(myDisasm.repr(), 'knotw k1, k3')

        # VEX.L0.66.0F.W0 44 /r
        # KNOTB k1, k2

        myVEX = VEX('VEX.L0.66.0F.W0')
        myVEX.vvvv = 0b1101
        myVEX.R = 1
        Buffer = bytes.fromhex('{}44cb'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x44')
        assert_equal(myDisasm.infos.Reserved_.VEX.L, 0)
        assert_equal(myDisasm.infos.Reserved_.REX.W_, 0)
        assert_equal(myDisasm.infos.Reserved_.MOD_, 3)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'knotb')
        assert_equal(myDisasm.repr(), 'knotb k1, k3')

        # VEX.L0.0F.W1 44 /r
        # KNOTQ k1, k2

        myVEX = VEX('VEX.L0.0F.W1')
        myVEX.vvvv = 0b1101
        myVEX.R = 1
        Buffer = bytes.fromhex('{}44cb'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x44')
        assert_equal(myDisasm.infos.Reserved_.VEX.L, 0)
        assert_equal(myDisasm.infos.Reserved_.REX.W_, 1)
        assert_equal(myDisasm.infos.Reserved_.MOD_, 3)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'knotq')
        assert_equal(myDisasm.repr(), 'knotq k1, k3')

        # VEX.L0.66.0F.W1 44 /r
        # KNOTD k1, k2

        myVEX = VEX('VEX.L0.66.0F.W1')
        myVEX.vvvv = 0b1101
        myVEX.R = 1
        Buffer = bytes.fromhex('{}44cb'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x44')
        assert_equal(myDisasm.infos.Reserved_.VEX.L, 0)
        assert_equal(myDisasm.infos.Reserved_.REX.W_, 1)
        assert_equal(myDisasm.infos.Reserved_.MOD_, 3)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'knotd')
        assert_equal(myDisasm.repr(), 'knotd k1, k3')
