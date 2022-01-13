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

        # 66 0F 3A 42 /r ib
        # MPSADBW xmm1, xmm2/m128, imm8

        Buffer = bytes.fromhex('660f3a422011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a42)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'mpsadbw')
        assert_equal(myDisasm.repr(), 'mpsadbw xmm4, xmmword ptr [rax], 11h')

        # VEX.128.66.0F3A.WIG 42 /r ib
        # VMPSADBW xmm1, xmm2, xmm3/m128, imm8

        myVEX = VEX('VEX.128.66.0F3A.WIG')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}42c911'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x42)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmpsadbw')
        assert_equal(myDisasm.repr(), 'vmpsadbw xmm1, xmm0, xmm9, 11h')

        # VEX.256.66.0F3A.WIG 42 /r ib
        # VMPSADBW ymm1, ymm2, ymm3/m256, imm8

        myVEX = VEX('VEX.256.66.0F3A.WIG')
        myVEX.R = 1
        Buffer = bytes.fromhex('{}42c911'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x42)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmpsadbw')
        assert_equal(myDisasm.repr(), 'vmpsadbw ymm1, ymm0, ymm9, 11h')

        # EVEX.128.66.0F3A.W0 42 /r ib
        # VDBPSADBW xmm1 {k1}{z}, xmm2, xmm3/m128, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}422011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x42)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vdbpsadbw')
        assert_equal(myDisasm.repr(), 'vdbpsadbw xmm28, xmm16, xmmword ptr [r8], 11h')

        # EVEX.256.66.0F3A.W0 42 /r ib
        # VDBPSADBW ymm1 {k1}{z}, ymm2, ymm3/m256, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}422011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x42)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vdbpsadbw')
        assert_equal(myDisasm.repr(), 'vdbpsadbw ymm28, ymm16, ymmword ptr [r8], 11h')

        # EVEX.512.66.0F3A.W0 42 /r ib
        # VDBPSADBW zmm1 {k1}{z}, zmm2, zmm3/m512, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}422011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x42)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vdbpsadbw')
        assert_equal(myDisasm.repr(), 'vdbpsadbw zmm28, zmm16, zmmword ptr [r8], 11h')
