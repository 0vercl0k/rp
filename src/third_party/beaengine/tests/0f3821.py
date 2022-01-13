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

        # 66 0f 38 21 /r
        # PMOVSXBW xmm1, xmm2/m64

        Buffer = bytes.fromhex('660f38219000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3821)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmovsxbd')
        assert_equal(myDisasm.repr(), 'pmovsxbd xmm2, qword ptr [rax+00000000h]')

        # VEX.128.66.0F38.WIG 21 /r
        # vpmovsxbd xmm1, xmm2/m64

        myVEX = VEX('VEX.128.66.0F38.WIG')
        Buffer = bytes.fromhex('{}219000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbd')
        assert_equal(myDisasm.repr(), 'vpmovsxbd xmm10, qword ptr [r8+00000000h]')

        # VEX.256.66.0F38.WIG 21 /r
        # vpmovsxbd ymm1, xmm2/m128

        myVEX = VEX('VEX.256.66.0F38.WIG')
        Buffer = bytes.fromhex('{}219000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbd')
        assert_equal(myDisasm.repr(), 'vpmovsxbd ymm10, xmmword ptr [r8+00000000h]')

        # EVEX.128.66.0F38.WIG 21 /r
        # vpmovsxbd xmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.128.66.0F38.WIG')
        Buffer = bytes.fromhex('{}219000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbd')
        assert_equal(myDisasm.repr(), 'vpmovsxbd xmm26, qword ptr [r8+00000000h]')

        # EVEX.256.66.0F38.WIG 21 /r
        # vpmovsxbd ymm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.256.66.0F38.WIG')
        Buffer = bytes.fromhex('{}219000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbd')
        assert_equal(myDisasm.repr(), 'vpmovsxbd ymm26, xmmword ptr [r8+00000000h]')

        # EVEX.512.66.0F38.WIG 21 /r
        # vpmovsxbd zmm1 {k1}{z}, ymm2/m256

        myEVEX = EVEX('EVEX.512.66.0F38.WIG')
        Buffer = bytes.fromhex('{}219000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsxbd')
        assert_equal(myDisasm.repr(), 'vpmovsxbd zmm26, ymmword ptr [r8+00000000h]')

        # EVEX.128.F3.0F38.W0 21 /r
        # vpmovsdb xmm1/m64 {k1}{z},xmm2

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        Buffer = bytes.fromhex('{}219000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsdb')
        assert_equal(myDisasm.repr(), 'vpmovsdb qword ptr [r8+00000000h], xmm26')

        # EVEX.256.F3.0F38.W0 21 /r
        # vpmovsdb xmm1/m128 {k1}{z},ymm2

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        Buffer = bytes.fromhex('{}219000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsdb')
        assert_equal(myDisasm.repr(), 'vpmovsdb xmmword ptr [r8+00000000h], ymm26')

        # EVEX.512.F3.0F38.W0 21 /r
        # vpmovsdb ymm1/m256 {k1}{z},zmm2

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        Buffer = bytes.fromhex('{}219000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x21)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovsdb')
        assert_equal(myDisasm.repr(), 'vpmovsdb ymmword ptr [r8+00000000h], zmm26')
