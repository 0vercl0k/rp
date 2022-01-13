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

        # 66 0F 5f /r
        # maxpd xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f5f9000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'maxpd')
        assert_equal(myDisasm.repr(), 'maxpd xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F.WIG 5f /r
        # Vmaxpd xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxpd')
        assert_equal(myDisasm.repr(), 'vmaxpd xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.66.0F.WIG 5f /r
        # Vmaxpd ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxpd')
        assert_equal(myDisasm.repr(), 'vmaxpd ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.66.0F.W1 5f /r
        # Vmaxpd xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxpd')
        assert_equal(myDisasm.repr(), 'vmaxpd xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.66.0F.W1 5f /r
        # Vmaxpd ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxpd')
        assert_equal(myDisasm.repr(), 'vmaxpd ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.66.0F.W1 5f /r
        # Vmaxpd zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxpd')
        assert_equal(myDisasm.repr(), 'vmaxpd zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # NP 0F 5f /r
        # maxps xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f5f9000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'maxps')
        assert_equal(myDisasm.repr(), 'maxps xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.0F.WIG 5f /r
        # Vmaxps xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxps')
        assert_equal(myDisasm.repr(), 'vmaxps xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.0F.WIG 5f /r
        # Vmaxps ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.0F.WIG')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxps')
        assert_equal(myDisasm.repr(), 'vmaxps ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 5f /r
        # Vmaxps xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxps')
        assert_equal(myDisasm.repr(), 'vmaxps xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.0F.W0 5f /r
        # Vmaxps ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxps')
        assert_equal(myDisasm.repr(), 'vmaxps ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.0F.W0 5f /r
        # Vmaxps zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst {er}

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxps')
        assert_equal(myDisasm.repr(), 'vmaxps zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # F2 0F 5f /r
        # maxsd xmm1, xmm2/m64

        Buffer = bytes.fromhex('f20f5f9000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'maxsd')
        assert_equal(myDisasm.repr(), 'maxsd xmm2, qword ptr [rax+00000000h]')

        # VEX.NDS.LIG.F2.0F.WIG 5f /r
        # Vmaxsd xmm1, xmm2, xmm3/m64

        myVEX = VEX('VEX.NDS.LIG.F2.0F.WIG')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxsd')
        assert_equal(myDisasm.repr(), 'vmaxsd xmm10, xmm15, qword ptr [r8+00000000h]')

        # EVEX.NDS.LIG.F2.0F.W1 5f /r
        # Vmaxsd xmm1 {k1}{z}, xmm2, xmm3/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxsd')
        assert_equal(myDisasm.repr(), 'vmaxsd xmm26, xmm31, qword ptr [r8+00000000h]')

        # F3 0F 5f /r
        # maxss xmm1, xmm2/m32

        Buffer = bytes.fromhex('f30f5f9000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'maxss')
        assert_equal(myDisasm.repr(), 'maxss xmm2, dword ptr [rax+00000000h]')

        # VEX.NDS.LIG.F3.0F.WIG 5f /r
        # Vmaxss xmm1,xmm2, xmm3/m32

        myVEX = VEX('VEX.NDS.LIG.F3.0F.WIG')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxss')
        assert_equal(myDisasm.repr(), 'vmaxss xmm10, xmm15, dword ptr [r8+00000000h]')

        # EVEX.NDS.LIG.F3.0F.W0 5f /r
        # Vmaxss xmm1{k1}{z}, xmm2, xmm3/m32{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}5f9000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmaxss')
        assert_equal(myDisasm.repr(), 'vmaxss xmm26, xmm31, dword ptr [r8+00000000h]')
