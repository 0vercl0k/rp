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

        # NP 0F 54 /r
        # ANDPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f549000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf54')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'andps')
        assert_equal(myDisasm.repr(), 'andps xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.0F 54 /r
        # VANDPS xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.0F')
        Buffer = bytes.fromhex('{}549000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x54')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandps')
        assert_equal(myDisasm.repr(), 'vandps xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.0F 54 /r
        # VANDPS ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.0F')
        Buffer = bytes.fromhex('{}549000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x54')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandps')
        assert_equal(myDisasm.repr(), 'vandps ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 54 /r
        # VANDPS xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}549000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x54)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandps')
        assert_equal(myDisasm.repr(), 'vandps xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.0F.W0 54 /r
        # VANDPS ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}549000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x54)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandps')
        assert_equal(myDisasm.repr(), 'vandps ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.0F.W0 54 /r
        # VANDPS zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}549000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x54)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandps')
        assert_equal(myDisasm.repr(), 'vandps zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # 66 0F 54 /r
        # ANDPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f549000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf54')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'andpd')
        assert_equal(myDisasm.repr(), 'andpd xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F 54 /r
        # VANDPD xmm1, xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F')
        Buffer = bytes.fromhex('{}549000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x54')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandpd')
        assert_equal(myDisasm.repr(), 'vandpd xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.66.0F 54 /r
        # VANDPD ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F')
        Buffer = bytes.fromhex('{}549000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x54')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandpd')
        assert_equal(myDisasm.repr(), 'vandpd ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.66.0F.W1 54 /r
        # VANDPD xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}549000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x54)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandpd')
        assert_equal(myDisasm.repr(), 'vandpd xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.66.0F.W1 54 /r
        # VANDPD ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}549000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x54)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandpd')
        assert_equal(myDisasm.repr(), 'vandpd ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.66.0F.W1 54 /r
        # VANDPD zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}549000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x54)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandpd')
        assert_equal(myDisasm.repr(), 'vandpd zmm26, zmm31, zmmword ptr [r8+00000000h]')
