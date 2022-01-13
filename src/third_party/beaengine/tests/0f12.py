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

        # NP 0F 12 /r
        # MOVHLPS xmm1, xmm2

        Buffer = bytes.fromhex('0f12e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movhlps')
        assert_equal(myDisasm.repr(), 'movhlps xmm4, xmm0')

        # VEX.NDS.128.0F.WIG 12 /r
        # VMOVHLPS xmm1, xmm2, xmm3

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}12e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovhlps')
        assert_equal(myDisasm.repr(), 'vmovhlps xmm12, xmm15, xmm8')

        # EVEX.NDS.128.0F.W0 12 /r
        # VMOVHLPS xmm1, xmm2, xmm3

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}12e0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovhlps')
        assert_equal(myDisasm.repr(), 'vmovhlps xmm28, xmm31, xmm24')

        # NP 0F 12 /r
        # MOVLPS xmm1, m64

        Buffer = bytes.fromhex('0f129000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movlps')
        assert_equal(myDisasm.repr(), 'movlps xmm2, qword ptr [rax+00000000h]')

        # VEX.NDS.128.0F.WIG 12 /r
        # VMOVLPS xmm2, xmm1, m64

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}129000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovlps')
        assert_equal(myDisasm.repr(), 'vmovlps xmm10, xmm15, qword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 12 /r
        # VMOVLPS xmm2, xmm1, m64

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovlps')
        assert_equal(myDisasm.repr(), 'vmovlps xmm26, xmm31, qword ptr [r8+00000000h]')

        # 66 0F 12 /r
        # MOVLPD xmm1, m64

        Buffer = bytes.fromhex('660f129000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movlpd')
        assert_equal(myDisasm.repr(), 'movlpd xmm2, qword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F.WIG 12 /r
        # VMOVLPD xmm2, xmm1, m64

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}1220'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovlpd')
        assert_equal(myDisasm.repr(), 'vmovlpd xmm12, xmm15, qword ptr [r8]')

        # EVEX.NDS.128.66.0F.W1 12 /r
        # VMOVLPD xmm2, xmm1, m64

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovlpd')
        assert_equal(myDisasm.repr(), 'vmovlpd xmm26, xmm31, qword ptr [r8+00000000h]')

        # F2 0F 12 /r
        # MOVDDUP xmm1, xmm2/m64

        Buffer = bytes.fromhex('f20f129000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movddup')
        assert_equal(myDisasm.repr(), 'movddup xmm2, qword ptr [rax+00000000h]')

        # VEX.128.F2.0F.WIG 12 /r
        # VMOVDDUP xmm1, xmm2/m64

        myVEX = VEX('VEX.128.F2.0F.WIG')
        Buffer = bytes.fromhex('{}129000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovddup')
        assert_equal(myDisasm.repr(), 'vmovddup xmm10, qword ptr [r8+00000000h]')

        # VEX.256.F2.0F.WIG 12 /r
        # VMOVDDUP ymm1, ymm2/m256

        myVEX = VEX('VEX.256.F2.0F.WIG')
        Buffer = bytes.fromhex('{}129000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovddup')
        assert_equal(myDisasm.repr(), 'vmovddup ymm10, ymmword ptr [r8+00000000h]')

        # EVEX.128.F2.0F.W1 12 /r
        # VMOVDDUP xmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.128.F2.0F.W1')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovddup')
        assert_equal(myDisasm.repr(), 'vmovddup xmm26, qword ptr [r8+00000000h]')

        # EVEX.256.F2.0F.W1 12 /r
        # VMOVDDUP ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F2.0F.W1')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovddup')
        assert_equal(myDisasm.repr(), 'vmovddup ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.F2.0F.W1 12 /r
        # VMOVDDUP zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F2.0F.W1')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovddup')
        assert_equal(myDisasm.repr(), 'vmovddup zmm26, zmmword ptr [r8+00000000h]')

        # F3 0F 12 /r
        # MOVSLDUP xmm1, xmm2/m128

        Buffer = bytes.fromhex('f30f129000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movsldup')
        assert_equal(myDisasm.repr(), 'movsldup xmm2, xmmword ptr [rax+00000000h]')

        # VEX.128.F3.0F.WIG 12 /r
        # VMOVSLDUP xmm1, xmm2/m128

        myVEX = VEX('VEX.128.F3.0F.WIG')
        Buffer = bytes.fromhex('{}129000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovsldup')
        assert_equal(myDisasm.repr(), 'vmovsldup xmm10, xmmword ptr [r8+00000000h]')

        # VEX.256.F3.0F.WIG 12 /r
        # VMOVSLDUP ymm1, ymm2/m256

        myVEX = VEX('VEX.256.F3.0F.WIG')
        Buffer = bytes.fromhex('{}129000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x12')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovsldup')
        assert_equal(myDisasm.repr(), 'vmovsldup ymm10, ymmword ptr [r8+00000000h]')

        # EVEX.128.F3.0F.W0 12 /r
        # VMOVSLDUP xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.F3.0F.W0')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovsldup')
        assert_equal(myDisasm.repr(), 'vmovsldup xmm26, xmmword ptr [r8+00000000h]')

        # EVEX.256.F3.0F.W0 12 /r
        # VMOVSLDUP ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F3.0F.W0')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovsldup')
        assert_equal(myDisasm.repr(), 'vmovsldup ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.F3.0F.W0 12 /r
        # VMOVSLDUP zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F3.0F.W0')
        Buffer = bytes.fromhex('{}129000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x12)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovsldup')
        assert_equal(myDisasm.repr(), 'vmovsldup zmm26, zmmword ptr [r8+00000000h]')
