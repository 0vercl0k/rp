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

        # EVEX.512.66.0F38.W0 5B /r
        # VBROADCASTI32X8 zmm1 {k1}{z}, m256

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}5b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti32x8')
        assert_equal(myDisasm.repr(), 'vbroadcasti32x8 zmm25, ymmword ptr [r14]')

        # EVEX.512.66.0F38.W1 5B /r
        # VBROADCASTI64X4 zmm1 {k1}{z}, m256

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}5b0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti64x4')
        assert_equal(myDisasm.repr(), 'vbroadcasti64x4 zmm25, ymmword ptr [r14]')
