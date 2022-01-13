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


        # EVEX.128.66.0F38.W0 77 /r
        # vpermi2ps xmm1{k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}770e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2ps')
        assert_equal(myDisasm.repr(), 'vpermi2ps xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 77 /r
        # vpermi2ps ymm1{k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}770e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2ps')
        assert_equal(myDisasm.repr(), 'vpermi2ps ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 77 /r
        # vpermi2ps zmm1{k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}770e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2ps')
        assert_equal(myDisasm.repr(), 'vpermi2ps zmm25, zmm16, zmmword ptr [r14]')

        # EVEX.128.66.0F38.W1 77 /r
        # vpermi2pd xmm1{k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}770e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2pd')
        assert_equal(myDisasm.repr(), 'vpermi2pd xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W1 77 /r
        # vpermi2pd ymm1{k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}770e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2pd')
        assert_equal(myDisasm.repr(), 'vpermi2pd ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W1 77 /r
        # vpermi2pd zmm1{k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}770e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x77)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermi2pd')
        assert_equal(myDisasm.repr(), 'vpermi2pd zmm25, zmm16, zmmword ptr [r14]')
