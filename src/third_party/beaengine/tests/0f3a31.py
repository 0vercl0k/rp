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

        # VEX.L0.66.0F3A.W1 31 /r
        # KSHIFTRQ k1, k2, imm8

        myVEX = VEX('VEX.L0.66.0F3A.W1')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}31c911'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x31)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kshiftrq')
        assert_equal(myDisasm.repr(), 'kshiftrq k1, k1, 11h')

        # VEX.L0.66.0F3A.W0 31 /r
        # KSHIFTRD k1, k2, imm8

        myVEX = VEX('VEX.L0.66.0F3A.W0')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}31e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x31)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'kshiftrd')
        assert_equal(myDisasm.repr(), 'kshiftrd k4, k0, 11h')
