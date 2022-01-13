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


        # EVEX.128.66.0F38.W0 44 /r
        # VPLZCNTD xmm1 {k1}{z},  xmm2/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntd')
        assert_equal(myDisasm.repr(), 'vplzcntd xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 44 /r
        # VPLZCNTD ymm1 {k1}{z}, ymm2/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntd')
        assert_equal(myDisasm.repr(), 'vplzcntd ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 44 /r
        # VPLZCNTD zmm1 {k1}{z}, zmm2/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntd')
        assert_equal(myDisasm.repr(), 'vplzcntd zmm25, zmm16, zmmword ptr [r14]')

        # EVEX.128.66.0F38.W1 44 /r
        # VPLZCNTQ xmm1 {k1}{z}, xmm2/m128/m64bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntq')
        assert_equal(myDisasm.repr(), 'vplzcntq xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W1 44 /r
        # VPLZCNTQ ymm1 {k1}{z}, ymm2/m256/m64bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntq')
        assert_equal(myDisasm.repr(), 'vplzcntq ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W1 44 /r
        # VPLZCNTQ zmm1 {k1}{z}, zmm2/m512/m64bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntq')
        assert_equal(myDisasm.repr(), 'vplzcntq zmm25, zmm16, zmmword ptr [r14]')


        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1110
        Buffer = bytes.fromhex('{}440e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x44)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vplzcntq')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
