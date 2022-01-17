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

        # EVEX.128.66.0F3A.W0 03 /r ib
        # VALIGND xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}032011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'valignd')
        assert_equal(myDisasm.repr(), 'valignd xmm28, xmm16, xmmword ptr [r8], 11h')

        # EVEX.128.66.0F3A.W1 03 /r ib
        # VALIGNQ xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W1')
        Buffer = bytes.fromhex('{}032011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'valignq')
        assert_equal(myDisasm.repr(), 'valignq xmm28, xmm16, xmmword ptr [r8], 11h')

        # EVEX.256.66.0F3A.W0 03 /r ib
        # VALIGND ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}032011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'valignd')
        assert_equal(myDisasm.repr(), 'valignd ymm28, ymm16, ymmword ptr [r8], 11h')

        # EVEX.256.66.0F3A.W1 03 /r ib
        # VALIGNQ ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W1')
        Buffer = bytes.fromhex('{}032011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'valignq')
        assert_equal(myDisasm.repr(), 'valignq ymm28, ymm16, ymmword ptr [r8], 11h')

        # EVEX.512.66.0F3A.W0 03 /r ib
        # VALIGND zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}032011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'valignd')
        assert_equal(myDisasm.repr(), 'valignd zmm28, zmm16, zmmword ptr [r8], 11h')

        # EVEX.512.66.0F3A.W1 03 /r ib
        # VALIGNQ zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W1')
        Buffer = bytes.fromhex('{}032011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x03)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'valignq')
        assert_equal(myDisasm.repr(), 'valignq zmm28, zmm16, zmmword ptr [r8], 11h')
