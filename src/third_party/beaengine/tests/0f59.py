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

        # 66 0F 59 /r
        # mulpd xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f599000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'mulpd')
        assert_equal(myDisasm.repr(), 'mulpd xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F.WIG 59 /r
        # Vmulpd xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}599000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulpd')
        assert_equal(myDisasm.repr(), 'vmulpd xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.66.0F.WIG 59 /r
        # Vmulpd ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}599000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulpd')
        assert_equal(myDisasm.repr(), 'vmulpd ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.66.0F.W1 59 /r
        # Vmulpd xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulpd')
        assert_equal(myDisasm.repr(), 'vmulpd xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.66.0F.W1 59 /r
        # Vmulpd ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulpd')
        assert_equal(myDisasm.repr(), 'vmulpd ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.66.0F.W1 59 /r
        # Vmulpd zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulpd')
        assert_equal(myDisasm.repr(), 'vmulpd zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # NP 0F 59 /r
        # mulps xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f599000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'mulps')
        assert_equal(myDisasm.repr(), 'mulps xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.0F.WIG 59 /r
        # Vmulps xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}599000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulps')
        assert_equal(myDisasm.repr(), 'vmulps xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.0F.WIG 59 /r
        # Vmulps ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.0F.WIG')
        Buffer = bytes.fromhex('{}599000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulps')
        assert_equal(myDisasm.repr(), 'vmulps ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 59 /r
        # Vmulps xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulps')
        assert_equal(myDisasm.repr(), 'vmulps xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.0F.W0 59 /r
        # Vmulps ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulps')
        assert_equal(myDisasm.repr(), 'vmulps ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.0F.W0 59 /r
        # Vmulps zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst {er}

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulps')
        assert_equal(myDisasm.repr(), 'vmulps zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # F2 0F 59 /r
        # mulsd xmm1, xmm2/m64

        Buffer = bytes.fromhex('f20f599000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'mulsd')
        assert_equal(myDisasm.repr(), 'mulsd xmm2, qword ptr [rax+00000000h]')

        # VEX.NDS.LIG.F2.0F.WIG 59 /r
        # Vmulsd xmm1, xmm2, xmm3/m64

        myVEX = VEX('VEX.NDS.LIG.F2.0F.WIG')
        Buffer = bytes.fromhex('{}599000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulsd')
        assert_equal(myDisasm.repr(), 'vmulsd xmm10, xmm15, qword ptr [r8+00000000h]')

        # EVEX.NDS.LIG.F2.0F.W1 59 /r
        # Vmulsd xmm1 {k1}{z}, xmm2, xmm3/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulsd')
        assert_equal(myDisasm.repr(), 'vmulsd xmm26, xmm31, qword ptr [r8+00000000h]')

        # F3 0F 59 /r
        # mulss xmm1, xmm2/m32

        Buffer = bytes.fromhex('f30f599000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'mulss')
        assert_equal(myDisasm.repr(), 'mulss xmm2, dword ptr [rax+00000000h]')

        # VEX.NDS.LIG.F3.0F.WIG 59 /r
        # Vmulss xmm1,xmm2, xmm3/m32

        myVEX = VEX('VEX.NDS.LIG.F3.0F.WIG')
        Buffer = bytes.fromhex('{}599000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulss')
        assert_equal(myDisasm.repr(), 'vmulss xmm10, xmm15, dword ptr [r8+00000000h]')

        # EVEX.NDS.LIG.F3.0F.W0 59 /r
        # Vmulss xmm1{k1}{z}, xmm2, xmm3/m32{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}599000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmulss')
        assert_equal(myDisasm.repr(), 'vmulss xmm26, xmm31, dword ptr [r8+00000000h]')
