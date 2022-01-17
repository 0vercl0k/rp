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


        # EVEX.512.66.0F3A.W0 1B /r ib
        # VEXTRACTF32X8 ymm1/m256 {k1}{z}, zmm2, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1b2011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf32x8')
        assert_equal(myDisasm.repr(), 'vextractf32x8 ymmword ptr [r8], zmm28, 11h')

        myEVEX = EVEX('EVEX.512.66.0F3A.W0')
        Buffer = bytes.fromhex('{}1bc011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf32x8')
        assert_equal(myDisasm.repr(), 'vextractf32x8 ymm24, zmm24, 11h')

        # EVEX.512.66.0F3A.W1 1B /r ib
        # VEXTRACTF64x4 ymm1/m256 {k1}{z}, zmm2, imm8

        myEVEX = EVEX('EVEX.512.66.0F3A.W1')
        Buffer = bytes.fromhex('{}1b2011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf64x4')
        assert_equal(myDisasm.repr(), 'vextractf64x4 ymmword ptr [r8], zmm28, 11h')

        myEVEX = EVEX('EVEX.512.66.0F3A.W1')
        Buffer = bytes.fromhex('{}1bc011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vextractf64x4')
        assert_equal(myDisasm.repr(), 'vextractf64x4 ymm24, zmm24, 11h')
