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

        # EVEX.128.66.0F38.W0 53 /r
        # vpdpwssds xmm1{k1}{z}, xmm2,  xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}530e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x53)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpdpwssds')
        assert_equal(myDisasm.repr(), 'vpdpwssds xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 53 /r
        # vpdpwssds ymm1{k1}{z}, ymm2,  ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}530e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x53)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpdpwssds')
        assert_equal(myDisasm.repr(), 'vpdpwssds ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 53 /r
        # vpdpwssds zmm1{k1}{z}, zmm2,  zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}530e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x53)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpdpwssds')
        assert_equal(myDisasm.repr(), 'vpdpwssds zmm25, zmm16, zmmword ptr [r14]')

        # EVEX.512.F2.0F38.W0 53 /r
        # VP4DPWSSDS zmm1{k1}{z}, zmm2+3, m128

        myEVEX = EVEX('EVEX.512.F2.0F38.W0')
        myEVEX.vvvv = 0b1011
        Buffer = bytes.fromhex('{}530e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x53)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vp4dpwssds')
        assert_equal(myDisasm.infos.Operand2.Registers.zmm, REG20+REG21+REG22+REG23)
        assert_equal(myDisasm.repr(), 'vp4dpwssds zmm25, zmm20...zmm23, xmmword ptr [r14]')
