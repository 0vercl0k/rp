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

        # 66 0F 51 /r
        # SQRTPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f5113')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sqrtpd')
        assert_equal(myDisasm.repr(), 'sqrtpd xmm2, xmmword ptr [rbx]')

        # VEX.128.66.0F.WIG 51 /r
        # VSQRTPD xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}51e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtpd')
        assert_equal(myDisasm.repr(), 'vsqrtpd xmm12, xmm8')


        # VEX.256.66.0F.WIG 51 /r
        # VSQRTPD ymm1, ymm2/m256

        myVEX = VEX('VEX.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}51e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtpd')
        assert_equal(myDisasm.repr(), 'vsqrtpd ymm12, ymm8')

        # EVEX.128.66.0F.W1 51 /r
        # VSQRTPD xmm1 {k1}{z},xmm2/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}519000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtpd')
        assert_equal(myDisasm.repr(), 'vsqrtpd xmm26, xmmword ptr [r8+00000000h]')


        # EVEX.256.66.0F.W1 51 /r
        # VSQRTPD ymm1 {k1}{z}, ymm2/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F.W1')
        Buffer = bytes.fromhex('{}519000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtpd')
        assert_equal(myDisasm.repr(), 'vsqrtpd ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.66.0F.W1 51 /r
        # VSQRTPD zmm1 {k1}{z}, zmm2/m512/m64bcst{er}

        myEVEX = EVEX('EVEX.512.66.0F.W1')
        Buffer = bytes.fromhex('{}519000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtpd')
        assert_equal(myDisasm.repr(), 'vsqrtpd zmm26, zmmword ptr [r8+00000000h]')

        # NP 0F 51 /r
        # SQRTPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f51e0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sqrtps')
        assert_equal(myDisasm.repr(), 'sqrtps xmm4, xmm0')

        # VEX.128.0F.WIG 51 /r
        # VSQRTPS xmm1, xmm2/m128

        myVEX = VEX('VEX.128.0F.WIG')
        Buffer = bytes.fromhex('{}51e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtps')
        assert_equal(myDisasm.repr(), 'vsqrtps xmm12, xmm8')

        # VEX.256.0F.WIG 51/r
        # VSQRTPS ymm1, ymm2/m256

        myVEX = VEX('VEX.256.0F.WIG')
        Buffer = bytes.fromhex('{}51e0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtps')
        assert_equal(myDisasm.repr(), 'vsqrtps ymm12, ymm8')

        # EVEX.128.0F.W0 51 /r
        # VSQRTPS xmm1 {k1}{z},xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.128.0F.W0')
        Buffer = bytes.fromhex('{}519000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtps')
        assert_equal(myDisasm.repr(), 'vsqrtps xmm26, xmmword ptr [r8+00000000h]')

        # EVEX.256.0F.W0 51 /r
        # VSQRTPS ymm1 {k1}{z},ymm2/m256/m32bcst

        myEVEX = EVEX('EVEX.256.0F.W0')
        Buffer = bytes.fromhex('{}519000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtps')
        assert_equal(myDisasm.repr(), 'vsqrtps ymm26, ymmword ptr [r8+00000000h]')

        # EVEX.512.0F.W0 51/r
        # VSQRTPS zmm1 {k1}{z},zmm2/m512/m32bcst{er}

        myEVEX = EVEX('EVEX.512.0F.W0')
        Buffer = bytes.fromhex('{}519000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtps')
        assert_equal(myDisasm.repr(), 'vsqrtps zmm26, zmmword ptr [r8+00000000h]')


        # F3 0F 51 /r
        # SQRTSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('f30f5113')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sqrtss')
        assert_equal(myDisasm.repr(), 'sqrtss xmm2, dword ptr [rbx]')


        # VEX.NDS.LIG.F3.0F.WIG 51 /r
        # VSQRTSS xmm1, xmm2, xmm3/m32

        myVEX = VEX('VEX.NDS.LIG.F3.0F.WIG')
        myVEX.B = 1
        myVEX.R = 1
        Buffer = bytes.fromhex('{}5113'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtss')
        assert_equal(myDisasm.repr(), 'vsqrtss xmm2, dword ptr [rbx]')

        # EVEX.NDS.LIG.F3.0F.W0 51 /r
        # VSQRTSS xmm1 {k1}{z}, xmm2, xmm3/m32{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}5113'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtss')
        assert_equal(myDisasm.repr(), 'vsqrtss xmm26, dword ptr [r11]')

        # F2 0F 51/r
        # SQRTSD xmm1,xmm2/m64

        Buffer = bytes.fromhex('f20f5113')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sqrtsd')
        assert_equal(myDisasm.repr(), 'sqrtsd xmm2, qword ptr [rbx]')

        # VEX.NDS.LIG.F2.0F.WIG 51/r
        # VSQRTSD xmm1,xmm2, xmm3/m64

        myVEX = VEX('VEX.NDS.LIG.F2.0F.WIG')
        Buffer = bytes.fromhex('{}5113'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtsd')
        assert_equal(myDisasm.repr(), 'vsqrtsd xmm10, qword ptr [r11]')

        # EVEX.NDS.LIG.F2.0F.W1 51/r
        # VSQRTSD xmm1 {k1}{z}, xmm2, xmm3/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}5113'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x51')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsqrtsd')
        assert_equal(myDisasm.repr(), 'vsqrtsd xmm26, qword ptr [r11]')
