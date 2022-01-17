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

        # EVEX.128.66.0F38.W0 52 /r
        # vpdpwssd xmm1{k1}{z}, xmm2,  xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}520e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x52)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpdpwssd')
        assert_equal(myDisasm.repr(), 'vpdpwssd xmm25, xmm16, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W0 52 /r
        # vpdpwssd ymm1{k1}{z}, ymm2,  ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}520e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x52)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpdpwssd')
        assert_equal(myDisasm.repr(), 'vpdpwssd ymm25, ymm16, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W0 52 /r
        # vpdpwssd zmm1{k1}{z}, zmm2,  zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}520e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x52)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpdpwssd')
        assert_equal(myDisasm.repr(), 'vpdpwssd zmm25, zmm16, zmmword ptr [r14]')

        # EVEX.512.F2.0F38.W0 52 /r
        # VP4DPWSSD zmm1{k1}{z}, zmm2+3, m128

        myEVEX = EVEX('EVEX.512.F2.0F38.W0')
        myEVEX.vvvv = 0b1011
        Buffer = bytes.fromhex('{}520e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x52)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vp4dpwssd')
        assert_equal(myDisasm.infos.Operand2.Registers.zmm, REG20+REG21+REG22+REG23)
        assert_equal(myDisasm.repr(), 'vp4dpwssd zmm25, zmm20...zmm23, xmmword ptr [r14]')
