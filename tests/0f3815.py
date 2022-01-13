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

        # 66 0F 38 15 /r
        # BLENDVPD xmm1, xmm2/m128, <XMM0>

        Buffer = bytes.fromhex('660f381527')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'blendvpd xmm4, xmmword ptr [rdi], xmm0')


        # VEX.NDS.128.66.0F.W0 38 /r /is4
        # VBLENDvpd xmm1, xmm2, xmm3/m128, xmm4

        myVEX = VEX('VEX.NDS.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}152b11'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        #assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f38)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vblendvpd')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # EVEX.NDS.128.66.0F38.W0 15 /r
        # vprolVD xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprolvd')
        assert_equal(myDisasm.repr(), 'vprolvd xmm26, xmm16, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W0 15 /r
        # vprolVD ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprolvd')
        assert_equal(myDisasm.repr(), 'vprolvd ymm26, ymm16, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W0 15 /r
        # vprolVD zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprolvd')
        assert_equal(myDisasm.repr(), 'vprolvd zmm26, zmm16, zmmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.W1 15 /r
        # vprolVQ xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprolvq')
        assert_equal(myDisasm.repr(), 'vprolvq xmm26, xmm16, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W1 15 /r
        # vprolVQ ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprolvq')
        assert_equal(myDisasm.repr(), 'vprolvq ymm26, ymm16, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W1 15 /r
        # vprolVQ zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vprolvq')
        assert_equal(myDisasm.repr(), 'vprolvq zmm26, zmm16, zmmword ptr [r14]')

        # EVEX.128.F3.0F38.W0 15 /r
        # VPMOVusqd xmm1/m32 {k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.repr(), 'vpmovusqd dword ptr [r14], xmm26')

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}15ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.repr(), 'vpmovusqd xmm26, xmm25')

        # EVEX.256.F3.0F38.W0 15 /r
        # VPMOVusqd xmm1/m64 {k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.repr(), 'vpmovusqd qword ptr [r14], ymm26')

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}15ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.repr(), 'vpmovusqd xmm26, ymm25')

        # EVEX.512.F3.0F38.W0 15 /r
        # VPMOVusqd xmm1/m128 {k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1516'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.repr(), 'vpmovusqd xmmword ptr [r14], zmm26')

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}15ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.repr(), 'vpmovusqd xmm26, zmm25')


        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1110
        Buffer = bytes.fromhex('{}15ca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x15)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusqd')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
