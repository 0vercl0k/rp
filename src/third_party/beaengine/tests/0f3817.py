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

        # 66 0F 38 17 /r
        # PTEST xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f381727')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'ptest xmm4, xmmword ptr [rdi]')

        # VEX.128.66.0F38.WIG 17 /r
        # VPTEST xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F38.WIG')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1720'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x17)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptest')
        assert_equal(myDisasm.repr(), 'vptest xmm12, xmmword ptr [r8]')

        # VEX.256.66.0F38.WIG 17 /r
        # VPTEST ymm1, ymm2/m256

        myVEX = VEX('VEX.256.66.0F38.WIG')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1720'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x17)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptest')
        assert_equal(myDisasm.repr(), 'vptest ymm12, ymmword ptr [r8]')

        myVEX = VEX('VEX.256.66.0F38.WIG')
        myVEX.vvvv = 0b1110
        Buffer = bytes.fromhex('{}1720'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x17)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vptest')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
