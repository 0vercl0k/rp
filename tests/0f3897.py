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

        # VEX.NDS.128.66.0F38.W0 97 /r
        # vfmsubadd132ps xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c40201970e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfmsubadd132ps')
        assert_equal(myDisasm.repr(), 'vfmsubadd132ps xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F38.W0 97 /r
        # vfmsubadd132ps ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c40205970e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfmsubadd132ps')
        assert_equal(myDisasm.repr(), 'vfmsubadd132ps ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.W0 97 /r
        # vfmsubadd132ps xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('62020506970e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x97')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfmsubadd132ps')
        assert_equal(myDisasm.repr(), 'vfmsubadd132ps xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W0 97 /r
        # vfmsubadd132ps ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('62020520970e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x97')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfmsubadd132ps')
        assert_equal(myDisasm.repr(), 'vfmsubadd132ps ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W0 97 /r
        # vfmsubadd132ps zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('62020540970e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x97')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfmsubadd132ps')
        assert_equal(myDisasm.repr(), 'vfmsubadd132ps zmm25, zmm31, zmmword ptr [r14]')


        # VEX.NDS.128.66.0F38.W1 97 /r
        # vfmsubadd132pd xmm1, xmm2, xmm3/m128

        myVEX = VEX()
        myVEX.L = 0
        myVEX.W = 1
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b0

        Buffer = bytes.fromhex('c4{:02x}{:02x}970e'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfmsubadd132pd')
        assert_equal(myDisasm.repr(), 'vfmsubadd132pd xmm9, xmm15, xmmword ptr [r14]')
