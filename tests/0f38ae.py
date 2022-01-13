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

        # VEX.NDS.128.66.0F38.W0 ae /r
        # vfnmsub213ps xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c40201ae0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfnmsub213ps')
        assert_equal(myDisasm.repr(), 'vfnmsub213ps xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F38.W0 ae /r
        # vfnmsub213ps ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c40205ae0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfnmsub213ps')
        assert_equal(myDisasm.repr(), 'vfnmsub213ps ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.W0 ae /r
        # vfnmsub213ps xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('62020506ae0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfnmsub213ps')
        assert_equal(myDisasm.repr(), 'vfnmsub213ps xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.W0 ae /r
        # vfnmsub213ps ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('62020520ae0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfnmsub213ps')
        assert_equal(myDisasm.repr(), 'vfnmsub213ps ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.W0 ae /r
        # vfnmsub213ps zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('62020540ae0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xae')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfnmsub213ps')
        assert_equal(myDisasm.repr(), 'vfnmsub213ps zmm25, zmm31, zmmword ptr [r14]')


        # VEX.NDS.128.66.0F38.W1 ae /r
        # vfnmsub213pd xmm1, xmm2, xmm3/m128

        myVEX = VEX()
        myVEX.L = 0
        myVEX.W = 1
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b0

        Buffer = bytes.fromhex('c4{:02x}{:02x}ae0e'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vfnmsub213pd')
        assert_equal(myDisasm.repr(), 'vfnmsub213pd xmm9, xmm15, xmmword ptr [r14]')
