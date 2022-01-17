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


        # 66 0F 3A 0E /r ib
        # PBLENDW xmm1, xmm2/m128, imm8

        Buffer = bytes.fromhex('660f3a0e2011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a0e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pblendw')
        assert_equal(myDisasm.repr(), 'pblendw xmm4, xmmword ptr [rax], 11h')

        # VEX.128.66.0F3A.WIG 0E /r ib
        # VPBLENDW xmm1, xmm2, xmm3/m128, imm8

        myVEX = VEX('VEX.128.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}0e1033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpblendw')
        assert_equal(myDisasm.repr(), 'vpblendw xmm10, xmm0, xmmword ptr [r8], 33h')

        # VEX.256.66.0F3A.WIG 0E /r ib
        # VPBLENDW ymm1, ymm2, ymm3/m256, imm8

        myVEX = VEX('VEX.256.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}0e1033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpblendw')
        assert_equal(myDisasm.repr(), 'vpblendw ymm10, ymm0, ymmword ptr [r8], 33h')
