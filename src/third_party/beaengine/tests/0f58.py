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

        # 66 0F 58 /r
        # ADDPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f589000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addpd')
        assert_equal(myDisasm.repr(), 'addpd xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F.WIG 58 /r
        # VADDPD xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}589000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddpd')
        assert_equal(myDisasm.repr(), 'vaddpd xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.66.0F.WIG 58 /r
        # VADDPD ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}589000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddpd')
        assert_equal(myDisasm.repr(), 'vaddpd ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.66.0F.W1 58 /r
        # VADDPD xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddpd')
        assert_equal(myDisasm.repr(), 'vaddpd xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.66.0F.W1 58 /r
        # VADDPD ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddpd')
        assert_equal(myDisasm.repr(), 'vaddpd ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.66.0F.W1 58 /r
        # VADDPD zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddpd')
        assert_equal(myDisasm.repr(), 'vaddpd zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # NP 0F 58 /r
        # ADDPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f589000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addps')
        assert_equal(myDisasm.repr(), 'addps xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.0F.WIG 58 /r
        # VADDPS xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}589000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddps')
        assert_equal(myDisasm.repr(), 'vaddps xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.0F.WIG 58 /r
        # VADDPS ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.0F.WIG')
        Buffer = bytes.fromhex('{}589000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddps')
        assert_equal(myDisasm.repr(), 'vaddps ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 58 /r
        # VADDPS xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddps')
        assert_equal(myDisasm.repr(), 'vaddps xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.0F.W0 58 /r
        # VADDPS ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddps')
        assert_equal(myDisasm.repr(), 'vaddps ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.0F.W0 58 /r
        # VADDPS zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst {er}

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddps')
        assert_equal(myDisasm.repr(), 'vaddps zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('f20f589000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm2, qword ptr [rax+00000000h]')

        # VEX.NDS.LIG.F2.0F.WIG 58 /r
        # VADDSD xmm1, xmm2, xmm3/m64

        myVEX = VEX('VEX.NDS.LIG.F2.0F.WIG')
        Buffer = bytes.fromhex('{}589000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddsd')
        assert_equal(myDisasm.repr(), 'vaddsd xmm10, xmm15, qword ptr [r8+00000000h]')

        # EVEX.NDS.LIG.F2.0F.W1 58 /r
        # VADDSD xmm1 {k1}{z}, xmm2, xmm3/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddsd')
        assert_equal(myDisasm.repr(), 'vaddsd xmm26, xmm31, qword ptr [r8+00000000h]')

        # F3 0F 58 /r
        # ADDSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('f30f589000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addss')
        assert_equal(myDisasm.repr(), 'addss xmm2, dword ptr [rax+00000000h]')

        # VEX.NDS.LIG.F3.0F.WIG 58 /r
        # VADDSS xmm1,xmm2, xmm3/m32

        myVEX = VEX('VEX.NDS.LIG.F3.0F.WIG')
        Buffer = bytes.fromhex('{}589000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddss')
        assert_equal(myDisasm.repr(), 'vaddss xmm10, xmm15, dword ptr [r8+00000000h]')

        Buffer = bytes.fromhex('c5fa58c4')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddss')
        assert_equal(myDisasm.repr(), 'vaddss xmm0, xmm0, xmm4')


        # EVEX.NDS.LIG.F3.0F.W0 58 /r
        # VADDSS xmm1{k1}{z}, xmm2, xmm3/m32{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}589000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaddss')
        assert_equal(myDisasm.repr(), 'vaddss xmm26, xmm31, dword ptr [r8+00000000h]')
