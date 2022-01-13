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

        # VEX.256.66.0F3A.W0 19 /r ib
        # VEXTRACTF128 xmm1/m128, ymm2, imm8

        myVEX = VEX('VEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}191033'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf128')
        assert_equal(myDisasm.repr(), 'vextractf128 xmmword ptr [r8], ymm10, 33h')

        # VEX.256.66.0F3A.W0 19 /r ib
        # VEXTRACTF128 xmm1/m128, ymm2, imm8

        myVEX = VEX('VEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}19c001'.format(myVEX.c4()))

        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf128')
        assert_equal(myDisasm.repr(), 'vextractf128 xmm8, ymm8, 01h')

        # fix issue #6
        Buffer = bytes.fromhex('c4c37d19c001')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf128')
        assert_equal(myDisasm.repr(), 'vextractf128 xmm8, ymm0, 01h')


        # EVEX.256.66.0F3A.W0 19 /r ib
        # VEXTRACTF32X4 xmm1/m128 {k1}{z}, ymm2, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}192011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf32x4')
        assert_equal(myDisasm.repr(), 'vextractf32x4 xmmword ptr [r8], ymm28, 11h')

        # EVEX.512.66.0F3A.W0 19 /r ib
        # VEXTRACTF32x4 xmm1/m128 {k1}{z}, zmm2, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}192011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf32x4')
        assert_equal(myDisasm.repr(), 'vextractf32x4 xmmword ptr [r8], zmm28, 11h')


        # EVEX.256.66.0F3A.W1 19 /r ib
        # VEXTRACTF64X2 xmm1/m128 {k1}{z}, ymm2, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W1')
        Buffer = bytes.fromhex('{}192011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf64x2')
        assert_equal(myDisasm.repr(), 'vextractf64x2 xmmword ptr [r8], ymm28, 11h')

        # EVEX.512.66.0F3A.W1 19 /r ib
        # VEXTRACTF64X2 xmm1/m128 {k1}{z}, zmm2, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W1')
        Buffer = bytes.fromhex('{}192011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf64x2')
        assert_equal(myDisasm.repr(), 'vextractf64x2 xmmword ptr [r8], zmm28, 11h')
