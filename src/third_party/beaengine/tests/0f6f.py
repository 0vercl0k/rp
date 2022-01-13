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


        # NP 0F 6F /r
        # MOVQ mm, mm/m64

        Buffer = bytes.fromhex('0f6f20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movq')
        assert_equal(myDisasm.repr(), 'movq mm4, qword ptr [rax]')

        # 66 0F 6F /r
        # MOVDQA xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f6f20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movdqa')
        assert_equal(myDisasm.repr(), 'movdqa xmm4, xmmword ptr [rax]')

        # VEX.128.66.0F.WIG 6F /r
        # VMOVDQA xmm1, xmm2/m128

        myVEX = VEX('VEX.128.66.0F.WIG')
        Buffer = bytes.fromhex('{}6f20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa')
        assert_equal(myDisasm.repr(), 'vmovdqa xmm12, xmmword ptr [r8]')

        # VEX.256.66.0F.WIG 6F /r
        # VMOVDQA ymm1, ymm2/m256

        myVEX = VEX('VEX.256.66.0F.WIG')
        Buffer = bytes.fromhex('{}6f20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa')
        assert_equal(myDisasm.repr(), 'vmovdqa ymm12, ymmword ptr [r8]')

        # EVEX.128.66.0F.W0 6F /r
        # VMOVDQA32 xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.66.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa32')
        assert_equal(myDisasm.repr(), 'vmovdqa32 xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F.W0 6F /r
        # VMOVDQA32 ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.66.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa32')
        assert_equal(myDisasm.repr(), 'vmovdqa32 ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F.W0 6F /r
        # VMOVDQA32 zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.66.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa32')
        assert_equal(myDisasm.repr(), 'vmovdqa32 zmm28, zmmword ptr [r8]')

        # EVEX.128.66.0F.W1 6F /r
        # VMOVDQA64 xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.66.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa64')
        assert_equal(myDisasm.repr(), 'vmovdqa64 xmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F.W1 6F /r
        # VMOVDQA64 ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.66.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa64')
        assert_equal(myDisasm.repr(), 'vmovdqa64 ymm28, ymmword ptr [r8]')

        # EVEX.512.66.0F.W1 6F /r
        # VMOVDQA64 zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.66.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqa64')
        assert_equal(myDisasm.repr(), 'vmovdqa64 zmm28, zmmword ptr [r8]')

        # F3 0F 6F /r
        # MOVDQU xmm1, xmm2/m128

        Buffer = bytes.fromhex('f30f6f20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'movdqu')
        assert_equal(myDisasm.repr(), 'movdqu xmm4, xmmword ptr [rax]')

        # VEX.128.F3.0F.WIG 6F /r
        # VMOVDQU xmm1, xmm2/m128

        myVEX = VEX('VEX.128.F3.0F.WIG')
        Buffer = bytes.fromhex('{}6f20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu')
        assert_equal(myDisasm.repr(), 'vmovdqu xmm12, xmmword ptr [r8]')

        # VEX.256.F3.0F.WIG 6F /r
        # VMOVDQU ymm1, ymm2/m256

        myVEX = VEX('VEX.256.F3.0F.WIG')
        Buffer = bytes.fromhex('{}6f20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu')
        assert_equal(myDisasm.repr(), 'vmovdqu ymm12, ymmword ptr [r8]')

        # EVEX.128.F3.0F.W0 6F /r
        # VMOVDQU32 xmm1 {k1}{z}, xmm2/mm128

        myEVEX = EVEX('EVEX.128.F3.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu32')
        assert_equal(myDisasm.repr(), 'vmovdqu32 xmm28, xmmword ptr [r8]')

        # EVEX.256.F3.0F.W0 6F /r
        # VMOVDQU32 ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F3.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu32')
        assert_equal(myDisasm.repr(), 'vmovdqu32 ymm28, ymmword ptr [r8]')

        # EVEX.512.F3.0F.W0 6F /r
        # VMOVDQU32 zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F3.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu32')
        assert_equal(myDisasm.repr(), 'vmovdqu32 zmm28, zmmword ptr [r8]')

        # EVEX.128.F3.0F.W1 6F /r
        # VMOVDQU64 xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.F3.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu64')
        assert_equal(myDisasm.repr(), 'vmovdqu64 xmm28, xmmword ptr [r8]')

        # EVEX.256.F3.0F.W1 6F /r
        # VMOVDQU64 ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F3.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu64')
        assert_equal(myDisasm.repr(), 'vmovdqu64 ymm28, ymmword ptr [r8]')

        # EVEX.512.F3.0F.W1 6F /r
        # VMOVDQU64 zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F3.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu64')
        assert_equal(myDisasm.repr(), 'vmovdqu64 zmm28, zmmword ptr [r8]')

        # EVEX.128.F2.0F.W0 6F /r
        # VMOVDQU8 xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.F2.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu8')
        assert_equal(myDisasm.repr(), 'vmovdqu8 xmm28, xmmword ptr [r8]')

        # EVEX.256.F2.0F.W0 6F /r
        # VMOVDQU8 ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F2.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu8')
        assert_equal(myDisasm.repr(), 'vmovdqu8 ymm28, ymmword ptr [r8]')

        # EVEX.512.F2.0F.W0 6F /r
        # VMOVDQU8 zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F2.0F.W0')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu8')
        assert_equal(myDisasm.repr(), 'vmovdqu8 zmm28, zmmword ptr [r8]')

        # EVEX.128.F2.0F.W1 6F /r
        # VMOVDQU16 xmm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.128.F2.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu16')
        assert_equal(myDisasm.repr(), 'vmovdqu16 xmm28, xmmword ptr [r8]')

        # EVEX.256.F2.0F.W1 6F /r
        # VMOVDQU16 ymm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.256.F2.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu16')
        assert_equal(myDisasm.repr(), 'vmovdqu16 ymm28, ymmword ptr [r8]')

        # EVEX.512.F2.0F.W1 6F /r
        # VMOVDQU16 zmm1 {k1}{z}, zmm2/m512

        myEVEX = EVEX('EVEX.512.F2.0F.W1')
        Buffer = bytes.fromhex('{}6f20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x6f)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vmovdqu16')
        assert_equal(myDisasm.repr(), 'vmovdqu16 zmm28, zmmword ptr [r8]')
