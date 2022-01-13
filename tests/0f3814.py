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
    """
    Variable Blend Packed Bytes
    """

    def test(self):

        # 66 0F 38 14 /r
        # BLENDVPS xmm1, xmm2/m128, <XMM0>

        Buffer = bytes.fromhex('660f381427')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'blendvps xmm4, xmmword ptr [rdi], xmm0')

        # VEX.NDS.128.66.0F.W0 38 /r /is4
        # VBLENDVPS xmm1, xmm2, xmm3/m128, xmm4

        myVEX = VEX('VEX.NDS.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}142b11'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        #assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f38)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vblendvps')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)



        # EVEX.NDS.128.66.0F38.W0 14 /r
        # VPRORVD xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprorvd')
        assert_equal(myDisasm.repr(), 'vprorvd xmm26, xmm16, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W0 14 /r
        # VPRORVD ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprorvd')
        assert_equal(myDisasm.repr(), 'vprorvd ymm26, ymm16, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W0 14 /r
        # VPRORVD zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprorvd')
        assert_equal(myDisasm.repr(), 'vprorvd zmm26, zmm16, zmmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.W1 14 /r
        # VPRORVQ xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprorvq')
        assert_equal(myDisasm.repr(), 'vprorvq xmm26, xmm16, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W1 14 /r
        # VPRORVQ ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprorvq')
        assert_equal(myDisasm.repr(), 'vprorvq ymm26, ymm16, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W1 14 /r
        # VPRORVQ zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprorvq')
        assert_equal(myDisasm.repr(), 'vprorvq zmm26, zmm16, zmmword ptr [r14]')

        # EVEX.128.F3.0F38.W0 14 /r
        # VPMOVUSQW xmm1/m32 {k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.repr(), 'vpmovusqw dword ptr [r14], xmm26')

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}14ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.repr(), 'vpmovusqw xmm26, xmm25')

        # EVEX.256.F3.0F38.W0 14 /r
        # VPMOVUSQW xmm1/m64 {k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.repr(), 'vpmovusqw qword ptr [r14], ymm26')

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}14ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.repr(), 'vpmovusqw xmm26, ymm25')

        # EVEX.512.F3.0F38.W0 14 /r
        # VPMOVUSQW xmm1/m128 {k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1416'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.repr(), 'vpmovusqw xmmword ptr [r14], zmm26')

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}14ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.repr(), 'vpmovusqw xmm26, zmm25')


        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1110
        Buffer = bytes.fromhex('{}14ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x14)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqw')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
