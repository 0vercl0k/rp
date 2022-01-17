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

        # EVEX.128.66.0F38.W0 8a /r
        # vcompressps xmm2/m128 {k1}{z}, xmm1

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}8a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcompressps')
        assert_equal(myDisasm.repr(), 'vcompressps xmmword ptr [r14], xmm25')

        # EVEX.256.66.0F38.W0 8a /r
        # vcompressps ymm2/m256 {k1}{z}, ymm1

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}8a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcompressps')
        assert_equal(myDisasm.repr(), 'vcompressps ymmword ptr [r14], ymm25')

        # EVEX.512.66.0F38.W0 8a /r
        # vcompressps zmm2/m512 {k1}{z}, zmm1

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}8a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcompressps')
        assert_equal(myDisasm.repr(), 'vcompressps zmmword ptr [r14], zmm25')

        # EVEX.128.66.0F38.W1 8a /r
        # vcompresspd  xmm2/m128 {k1}{z},xmm1

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}8a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcompresspd')
        assert_equal(myDisasm.repr(), 'vcompresspd xmmword ptr [r14], xmm25')

        # EVEX.256.66.0F38.W1 8a /r
        # vcompresspd ymm2/m256 {k1}{z},ymm1

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}8a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcompresspd')
        assert_equal(myDisasm.repr(), 'vcompresspd ymmword ptr [r14], ymm25')

        # EVEX.512.66.0F38.W1 8a /r
        # vcompresspd zmm2/m512 {k1}{z}, zmm1

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}8a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcompresspd')
        assert_equal(myDisasm.repr(), 'vcompresspd zmmword ptr [r14], zmm25')
