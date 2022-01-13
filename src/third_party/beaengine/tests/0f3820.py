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

        # 66 0f 38 20 /r
        # PMOVSXBW xmm1, xmm2/m64

        Buffer = bytes.fromhex('660f38209000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3820)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmovsxbw')
        assert_equal(myDisasm.repr(), 'pmovsxbw xmm2, qword ptr [rax+00000000h]')

        # VEX.128.66.0F38.WIG 20 /r
        # vpmovsxbw xmm1, xmm2/m64

        myVEX = VEX('VEX.128.66.0F38.WIG')
        Buffer = bytes.fromhex('{}209000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbw')
        assert_equal(myDisasm.repr(), 'vpmovsxbw xmm10, qword ptr [r8+00000000h]')

        # VEX.256.66.0F38.WIG 20 /r
        # vpmovsxbw ymm1, xmm2/m128

        myVEX = VEX('VEX.256.66.0F38.WIG')
        Buffer = bytes.fromhex('{}209000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbw')
        assert_equal(myDisasm.repr(), 'vpmovsxbw ymm10, xmmword ptr [r8+00000000h]')

        # EVEX.128.66.0F38.WIG 20 /r
        # vpmovsxbw xmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.128.66.0F38.WIG')
        Buffer = bytes.fromhex('{}209000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbw')
        assert_equal(myDisasm.repr(), 'vpmovsxbw xmm26, qword ptr [r8+00000000h]')

        # EVEX.256.66.0F38.WIG 20 /r
        # vpmovsxbw ymm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.256.66.0F38.WIG')
        Buffer = bytes.fromhex('{}209000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbw')
        assert_equal(myDisasm.repr(), 'vpmovsxbw ymm26, xmmword ptr [r8+00000000h]')

        # EVEX.512.66.0F38.WIG 20 /r
        # vpmovsxbw zmm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.512.66.0F38.WIG')
        Buffer = bytes.fromhex('{}209000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbw')
        assert_equal(myDisasm.repr(), 'vpmovsxbw zmm26, ymmword ptr [r8+00000000h]')

        # EVEX.128.F3.0F38.W0 20 /r
        # vpmovswb xmm1/m64 {k1}{z},xmm2

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}209000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovswb')
        assert_equal(myDisasm.repr(), 'vpmovswb qword ptr [r8+00000000h], xmm26')

        # EVEX.256.F3.0F38.W0 20 /r
        # vpmovswb xmm1/m128 {k1}{z},ymm2

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}209000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovswb')
        assert_equal(myDisasm.repr(), 'vpmovswb xmmword ptr [r8+00000000h], ymm26')

        # EVEX.512.F3.0F38.W0 20 /r
        # vpmovswb ymm1/m256 {k1}{z},zmm2

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}209000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x20)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovswb')
        assert_equal(myDisasm.repr(), 'vpmovswb ymmword ptr [r8+00000000h], zmm26')
