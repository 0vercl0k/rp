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


        # EVEX.128.66.0F38.W0 8D /r
        # VPERMB xmm1 {k1}{z}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}8d0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermb')
        assert_equal(myDisasm.repr(), 'vpermb xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 8D /r
        # VPERMB ymm1 {k1}{z}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}8d0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermb')
        assert_equal(myDisasm.repr(), 'vpermb ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 8D /r
        # VPERMB zmm1 {k1}{z}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}8d0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermb')
        assert_equal(myDisasm.repr(), 'vpermb zmm25, zmm16, zmmword ptr [r14]')

        # EVEX.128.66.0F38.W1 8D /r
        # VPERMW xmm1 {k1}{z}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}8d0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermw')
        assert_equal(myDisasm.repr(), 'vpermw xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W1 8D /r
        # VPERMW ymm1 {k1}{z}, ymm2, ymm3/m256

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}8d0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermw')
        assert_equal(myDisasm.repr(), 'vpermw ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W1 8D /r
        # VPERMW zmm1 {k1}{z}, zmm2, zmm3/m512

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}8d0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x8d)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermw')
        assert_equal(myDisasm.repr(), 'vpermw zmm25, zmm16, zmmword ptr [r14]')
