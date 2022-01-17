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

        # EVEX.128.66.0F38.W0 8b /r
        # vpcompressd xmm2/m128 {k1}{z}, xmm1

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}8b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressd')
        assert_equal(myDisasm.repr(), 'vpcompressd xmmword ptr [r14], xmm25')

        # EVEX.256.66.0F38.W0 8b /r
        # vpcompressd ymm2/m256 {k1}{z}, ymm1

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}8b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressd')
        assert_equal(myDisasm.repr(), 'vpcompressd ymmword ptr [r14], ymm25')

        # EVEX.512.66.0F38.W0 8b /r
        # vpcompressd zmm2/m512 {k1}{z}, zmm1

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}8b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressd')
        assert_equal(myDisasm.repr(), 'vpcompressd zmmword ptr [r14], zmm25')

        # EVEX.128.66.0F38.W1 8b /r
        # vpcompressq  xmm2/m128 {k1}{z},xmm1

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}8b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressq')
        assert_equal(myDisasm.repr(), 'vpcompressq xmmword ptr [r14], xmm25')

        # EVEX.256.66.0F38.W1 8b /r
        # vpcompressq ymm2/m256 {k1}{z},ymm1

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}8b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressq')
        assert_equal(myDisasm.repr(), 'vpcompressq ymmword ptr [r14], ymm25')

        # EVEX.512.66.0F38.W1 8b /r
        # vpcompressq zmm2/m512 {k1}{z}, zmm1

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}8b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpcompressq')
        assert_equal(myDisasm.repr(), 'vpcompressq zmmword ptr [r14], zmm25')
