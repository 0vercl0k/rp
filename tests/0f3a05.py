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

        # VEX.128.66.0F3A.W0 05 /r ib
        # vpermilpd xmm1, xmm2/m128, imm8

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}05e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x05)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermilpd')
        assert_equal(myDisasm.repr(), 'vpermilpd xmm12, xmm8, 11h')

        # VEX.256.66.0F3A.W0 05 /r ib
        # vpermilpd ymm1, ymm2/m256, imm8

        myVEX = VEX('VEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}05e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x05)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermilpd')
        assert_equal(myDisasm.repr(), 'vpermilpd ymm12, ymm8, 11h')

        # EVEX.128.66.0F3A.W0 05 /r ib
        # vpermilpd xmm1 {k1}{z}, xmm2/m128/m32bcst, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}052011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x05)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermilpd')
        assert_equal(myDisasm.repr(), 'vpermilpd xmm28, xmmword ptr [r8], 11h')

        # EVEX.256.66.0F3A.W0 05 /r ib
        # vpermilpd ymm1 {k1}{z}, ymm2/m256/m32bcst, imm8

        myEVEX = EVEX('EVEX.256.66.0F3A.W0')
        Buffer = bytes.fromhex('{}052011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x05)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermilpd')
        assert_equal(myDisasm.repr(), 'vpermilpd ymm28, ymmword ptr [r8], 11h')

        # EVEX.512.66.0F3A.W0 05 /r
        # vpermilpd zmm1 {k1}{z}, zmm2/m512/m32bcst, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}052011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x05)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpermilpd')
        assert_equal(myDisasm.repr(), 'vpermilpd zmm28, zmmword ptr [r8], 11h')
