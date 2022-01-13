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

        # NP 0F 28 /r
        # MOVAPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f28e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movaps')
        assert_equal(myDisasm.repr(), 'movaps xmm4, xmm0')

        # VEX.128.0F.WIG 28 /r
        # VMOVAPS xmm1, xmm2/m128

        myVEX = VEX('VEX.128.0F.WIG')
        Buffer = bytes.fromhex('{}28e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovaps')
        assert_equal(myDisasm.repr(), 'vmovaps xmm12, xmm8')

        # VEX.256.0F.WIG 28 /r
        # VMOVAPS ymm1, ymm2/m256

        myVEX = VEX('VEX.256.0F.WIG')
        Buffer = bytes.fromhex('{}28e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovaps')
        assert_equal(myDisasm.repr(), 'vmovaps ymm12, ymm8')

        # EVEX.128.0F.W0 28 /r
        # VMOVAPS xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.0F.W0')
        Buffer = bytes.fromhex('{}289000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Reserved_.EVEX.W, myEVEX.W)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovaps')
        assert_equal(myDisasm.repr(), 'vmovaps xmm26, xmmword ptr [r8+00000000h]')

        # EVEX.256.0F.W0 28 /r
        # VMOVAPS ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.0F.W0')
        Buffer = bytes.fromhex('{}289000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovaps')
        assert_equal(myDisasm.repr(), 'vmovaps ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.0F.W0 28 /r
        # VMOVAPS zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.0F.W0')
        Buffer = bytes.fromhex('{}289000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovaps')
        assert_equal(myDisasm.repr(), 'vmovaps zmm26, zmmword ptr [r8+00000000h]')

        # 66 0F 28 /r
        # MOVAPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f28e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movapd')
        assert_equal(myDisasm.repr(), 'movapd xmm4, xmm0')

        # VEX.128.66.0F.WIG 28 /r
        # VMOVAPD xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}28e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovapd')
        assert_equal(myDisasm.repr(), 'vmovapd xmm12, xmm8')

        # VEX.256.66.0F.WIG 28 /r
        # VMOVAPD ymm1, ymm2/m256

        myVEX = VEX('VEX.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}28e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovapd')
        assert_equal(myDisasm.repr(), 'vmovapd ymm12, ymm8')

        # EVEX.128.66.0F.W1 28 /r
        # VMOVAPD xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}289000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovapd')
        assert_equal(myDisasm.repr(), 'vmovapd xmm26, xmmword ptr [r8+00000000h]')

        # EVEX.256.66.0F.W1 28 /r
        # VMOVAPD ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.66.0F.W1')
        Buffer = bytes.fromhex('{}289000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovapd')
        assert_equal(myDisasm.repr(), 'vmovapd ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.66.0F.W1 28 /r
        # VMOVAPD zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.66.0F.W1')
        Buffer = bytes.fromhex('{}2820'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x28)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovapd')
        assert_equal(myDisasm.repr(), 'vmovapd zmm28, zmmword ptr [r8]')
