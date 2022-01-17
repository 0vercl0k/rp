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


        # VEX.256.66.0F38.W0 5A /r
        # VBROADCASTI128 ymm1, m128

        myVEX = VEX('VEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}5a10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti128')
        assert_equal(myDisasm.repr(), 'vbroadcasti128 ymm10, xmmword ptr [r8]')

        # EVEX.256.66.0F38.W0 5A /r
        # VBROADCASTI32X4 ymm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}5a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti32x4')
        assert_equal(myDisasm.repr(), 'vbroadcasti32x4 ymm25, xmmword ptr [r14]')

        # EVEX.512.66.0F38.W0 5A /r
        # VBROADCASTI32X4 zmm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}5a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti32x4')
        assert_equal(myDisasm.repr(), 'vbroadcasti32x4 zmm25, xmmword ptr [r14]')

        # EVEX.256.66.0F38.W1 5A /r
        # VBROADCASTI64X2 ymm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}5a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti64x2')
        assert_equal(myDisasm.repr(), 'vbroadcasti64x2 ymm25, xmmword ptr [r14]')

        # EVEX.512.66.0F38.W1 5A /r
        # VBROADCASTI64X2 zmm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}5a0e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti64x2')
        assert_equal(myDisasm.repr(), 'vbroadcasti64x2 zmm25, xmmword ptr [r14]')
