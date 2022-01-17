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

        # 66 0F 16 /r
        # MOVHPD xmm1, m64

        Buffer = bytes.fromhex('660f16e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movhpd')
        assert_equal(myDisasm.repr(), 'movhpd xmm4, xmm0')

        # VEX.NDS.128.66.0F.WIG 16 /r
        # VMOVHPD xmm2, xmm1, m64

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}169000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovhpd')
        assert_equal(myDisasm.repr(), 'vmovhpd xmm10, xmm15, qword ptr [r8+00000000h]')

        # EVEX.NDS.128.66.0F.W1 16 /r
        # VMOVHPD xmm2, xmm1, m64

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}169000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovhpd')
        assert_equal(myDisasm.repr(), 'vmovhpd xmm26, xmm31, qword ptr [r8+00000000h]')

        # NP 0F 16 /r
        # MOVHPS xmm1, m64

        Buffer = bytes.fromhex('0f169000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movhps')
        assert_equal(myDisasm.repr(), 'movhps xmm2, qword ptr [rax+00000000h]')

        # VEX.NDS.128.0F.WIG 16 /r
        # VMOVHPS xmm2, xmm1, m64

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}169000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovhps')
        assert_equal(myDisasm.repr(), 'vmovhps xmm10, xmm15, qword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 16 /r
        # VMOVHPS xmm2, xmm1, m64

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}169000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovhps')
        assert_equal(myDisasm.repr(), 'vmovhps xmm26, xmm31, qword ptr [r8+00000000h]')

        # NP 0F 16 /r
        # MOVLHPS xmm1, xmm2

        Buffer = bytes.fromhex('0f16e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movlhps')
        assert_equal(myDisasm.repr(), 'movlhps xmm4, xmm0')

        # VEX.NDS.128.0F.WIG 16 /r
        # VMOVLHPS xmm1, xmm2, xmm3

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}16e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovlhps')
        assert_equal(myDisasm.repr(), 'vmovlhps xmm12, xmm15, xmm8')

        # EVEX.NDS.128.0F.W0 16 /r
        # VMOVLHPS xmm1, xmm2, xmm3

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}16e0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovlhps')
        assert_equal(myDisasm.repr(), 'vmovlhps xmm28, xmm31, xmm24')

        # F3 0F 16 /r
        # MOVSHDUP xmm1, xmm2/m128

        Buffer = bytes.fromhex('f30f169000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movshdup')
        assert_equal(myDisasm.repr(), 'movshdup xmm2, xmmword ptr [rax+00000000h]')

        # VEX.128.F3.0F.WIG 16 /r
        # VMOVSHDUP xmm1, xmm2/m128

        myVEX = VEX('VEX.128.F3.0F.WIG')
        Buffer = bytes.fromhex('{}169000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovshdup')
        assert_equal(myDisasm.repr(), 'vmovshdup xmm10, xmmword ptr [r8+00000000h]')

        # VEX.256.F3.0F.WIG 16 /r
        # VMOVSHDUP ymm1, ymm2/m256

        myVEX = VEX('VEX.256.F3.0F.WIG')
        Buffer = bytes.fromhex('{}169000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x16')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovshdup')
        assert_equal(myDisasm.repr(), 'vmovshdup ymm10, ymmword ptr [r8+00000000h]')

        # EVEX.128.F3.0F.W0 16 /r
        # VMOVSHDUP xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.F3.0F.W0')
        Buffer = bytes.fromhex('{}169000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovshdup')
        assert_equal(myDisasm.repr(), 'vmovshdup xmm26, xmmword ptr [r8+00000000h]')

        # EVEX.256.F3.0F.W0 16 /r
        # VMOVSHDUP ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F3.0F.W0')
        Buffer = bytes.fromhex('{}169000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovshdup')
        assert_equal(myDisasm.repr(), 'vmovshdup ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.F3.0F.W0 16 /r
        # VMOVSHDUP zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F3.0F.W0')
        Buffer = bytes.fromhex('{}169000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovshdup')
        assert_equal(myDisasm.repr(), 'vmovshdup zmm26, zmmword ptr [r8+00000000h]')
