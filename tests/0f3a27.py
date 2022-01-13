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

        # EVEX.256.66.0F3A.W0 27 /r ib
        # vgetmantss ymm1{k1}{z}, ymm2, ymm3/m32, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}272011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgetmantss')
        assert_equal(myDisasm.repr(), 'vgetmantss ymm28, ymm16, dword ptr [r8], 11h')

        # EVEX.512.66.0F3A.W0 27 /r ib
        # vgetmantss zmm1{k1}{z}, zmm2, zmm3/m32, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}272011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgetmantss')
        assert_equal(myDisasm.repr(), 'vgetmantss zmm28, zmm16, dword ptr [r8], 11h')

        # EVEX.256.66.0F3A.W1 27 /r ib
        # vgetmantsd ymm1{k1}{z}, ymm2, ymm3/m64, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W1')
        Buffer = bytes.fromhex('{}272011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgetmantsd')
        assert_equal(myDisasm.repr(), 'vgetmantsd ymm28, ymm16, qword ptr [r8], 11h')

        # EVEX.512.66.0F3A.W1 27 /r ib
        # vgetmantsd zmm1{k1}{z}, zmm2, zmm3/m64, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W1')
        Buffer = bytes.fromhex('{}272011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x27)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgetmantsd')
        assert_equal(myDisasm.repr(), 'vgetmantsd zmm28, zmm16, qword ptr [r8], 11h')
