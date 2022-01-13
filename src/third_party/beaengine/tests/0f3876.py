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


        # EVEX.128.66.0F38.W0 76 /r
        # vpermi2d xmm1{k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}760e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x76)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2d')
        assert_equal(myDisasm.repr(), 'vpermi2d xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 76 /r
        # vpermi2d ymm1{k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}760e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x76)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2d')
        assert_equal(myDisasm.repr(), 'vpermi2d ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 76 /r
        # vpermi2d zmm1{k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}760e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x76)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2d')
        assert_equal(myDisasm.repr(), 'vpermi2d zmm25, zmm16, zmmword ptr [r14]')

        # EVEX.128.66.0F38.W1 76 /r
        # vpermi2q xmm1{k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}760e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x76)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2q')
        assert_equal(myDisasm.repr(), 'vpermi2q xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W1 76 /r
        # vpermi2q ymm1{k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}760e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x76)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2q')
        assert_equal(myDisasm.repr(), 'vpermi2q ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W1 76 /r
        # vpermi2q zmm1{k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}760e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x76)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2q')
        assert_equal(myDisasm.repr(), 'vpermi2q zmm25, zmm16, zmmword ptr [r14]')
