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


        # NP 0F 15 /r
        # UNPckhpS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f15e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'unpckhps')
        assert_equal(myDisasm.repr(), 'unpckhps xmm4, xmm0')

        # VEX.NDS.128.0F.WIG 15 /r
        # VUNPckhpS xmm1,xmm2,xmm3/m128

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}15e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhps')
        assert_equal(myDisasm.repr(), 'vunpckhps xmm12, xmm15, xmm8')

        # VEX.NDS.256.0F.WIG 15 /r
        # VUNPckhpS ymm1,ymm2,ymm3/m256

        myVEX = VEX('VEX.NDS.256.0F.WIG')
        Buffer = bytes.fromhex('{}15e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhps')
        assert_equal(myDisasm.repr(), 'vunpckhps ymm12, ymm15, ymm8')

        # EVEX.NDS.128.0F.W0 15 /r
        # VUNPckhpS xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}159000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhps')
        assert_equal(myDisasm.repr(), 'vunpckhps xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.0F.W0 15 /r
        # VUNPckhpS ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}159000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhps')
        assert_equal(myDisasm.repr(), 'vunpckhps ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.0F.W0 15 /r
        # VUNPckhpS zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}159000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhps')
        assert_equal(myDisasm.repr(), 'vunpckhps zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # 66 0F 15 /r
        # UNPckhpD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f15e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'unpckhpd')
        assert_equal(myDisasm.repr(), 'unpckhpd xmm4, xmm0')

        # VEX.NDS.128.66.0F.WIG 15 /r
        # VUNPckhpD xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}15e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhpd')
        assert_equal(myDisasm.repr(), 'vunpckhpd xmm12, xmm15, xmm8')

        # VEX.NDS.256.66.0F.WIG 15 /r
        # VUNPckhpD ymm1,ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}15e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhpd')
        assert_equal(myDisasm.repr(), 'vunpckhpd ymm12, ymm15, ymm8')

        # EVEX.NDS.128.66.0F.W1 15 /r
        # VUNPckhpD xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}159000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhpd')
        assert_equal(myDisasm.repr(), 'vunpckhpd xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.66.0F.W1 15 /r
        # VUNPckhpD ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}159000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhpd')
        assert_equal(myDisasm.repr(), 'vunpckhpd ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.66.0F.W1 15 /r
        # VUNPckhpD zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}159000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x15')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vunpckhpd')
        assert_equal(myDisasm.repr(), 'vunpckhpd zmm26, zmm31, zmmword ptr [r8+00000000h]')
