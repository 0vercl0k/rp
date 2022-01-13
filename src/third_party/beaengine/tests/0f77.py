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

        # NP 0F 77
        # EMMS

        Buffer = bytes.fromhex('0f77')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'emms')

        # VEX.256.0F.WIG
        # VZEROALL

        myVEX = VEX('VEX.256.0F.WIG')
        Buffer = bytes.fromhex('{}77'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vzeroall')
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.ymm, REG1|REG0
         |REG2 |REG3 |REG4 |REG5 |REG6 |REG7 |REG8 |REG9
         |REG10 |REG11 |REG12 |REG13 |REG14 |REG15)

        # VEX.128.0F.WIG 77
        # VZEROUPPER

        myVEX = VEX('VEX.128.0F.WIG')
        Buffer = bytes.fromhex('{}77'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vzeroupper')
        assert_equal(myDisasm.infos.Instruction.ImplicitModifiedRegs.ymm, REG1|REG0
         |REG2 |REG3 |REG4 |REG5 |REG6 |REG7 |REG8 |REG9
         |REG10 |REG11 |REG12 |REG13 |REG14 |REG15)


        # VEX.vvvv is reserved and must be 1111b, otherwise instructions will #UD.

        myVEX = VEX('VEX.128.0F.WIG')
        myVEX.vvvv = 0b1000
        Buffer = bytes.fromhex('{}77'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vzeroupper')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
