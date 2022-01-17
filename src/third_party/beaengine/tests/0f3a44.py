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


        # 66 0F 3A 44 /r ib
        # PCLMULQDQ xmm1, xmm2/m128, imm8

        Buffer = bytes.fromhex('660f3a442001')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf3a44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pclmulhqlqdq')
        assert_equal(myDisasm.repr(), 'pclmulhqlqdq xmm4, xmmword ptr [rax], 01h')

        # VEX.128.66.0F3A.WIG 44 /r ib
        # VPCLMULQDQ xmm1, xmm2, xmm3/m128, imm8

        myVEX = VEX('VEX.128.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}441033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpclmulqdq')
        assert_equal(myDisasm.repr(), 'vpclmulqdq xmm10, xmm0, xmmword ptr [r8], 33h')

        # VEX.256.66.0F3A.WIG 44 /r /ib
        # VPCLMULQDQ ymm1, ymm2, ymm3/m256, imm8

        myVEX = VEX('VEX.256.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}441033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpclmulqdq')
        assert_equal(myDisasm.repr(), 'vpclmulqdq ymm10, ymm0, ymmword ptr [r8], 33h')

        # EVEX.128.66.0F3A.WIG 44 /r /ib
        # VPCLMULQDQ xmm1, xmm2, xmm3/m128, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}442011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpclmulqdq')
        assert_equal(myDisasm.repr(), 'vpclmulqdq xmm28, xmm16, xmmword ptr [r8], 11h')

        # EVEX.256.66.0F3A.WIG 44 /r /ib
        # VPCLMULQDQ ymm1, ymm2, ymm3/m256, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}442011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpclmulqdq')
        assert_equal(myDisasm.repr(), 'vpclmulqdq ymm28, ymm16, ymmword ptr [r8], 11h')

        # EVEX.512.66.0F3A.WIG 44 /r /ib
        # VPCLMULQDQ zmm1, zmm2, zmm3/m512, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.WIG')
        Buffer = bytes.fromhex('{}442011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpclmulqdq')
        assert_equal(myDisasm.repr(), 'vpclmulqdq zmm28, zmm16, zmmword ptr [r8], 11h')
