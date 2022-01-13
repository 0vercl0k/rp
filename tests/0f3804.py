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
    """
    Multiply and Add Packed Signed and Unsigned Bytes
    - pmaddubsw Pq, Qq
    - vpmaddubsw Vx, Hx, Wx
    """
    def test(self):
        # NP 0F 38 04 /r 1
        # pmaddubsw mm1, mm2/m64
        Buffer = bytes.fromhex('0f38049011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf3804')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmaddubsw')
        assert_equal(myDisasm.repr(), 'pmaddubsw mm2, qword ptr [rax+44332211h]')

        # 66 0F 38 04 /r
        # pmaddubsw xmm1, xmm2/m128
        Buffer = bytes.fromhex('660f38049011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf3804')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmaddubsw')
        assert_equal(myDisasm.repr(), 'pmaddubsw xmm2, xmmword ptr [rax+44332211h]')

        # NP 0F 38 04 /r 1
        # pmaddubsw mm1, mm2/m64
        Buffer = bytes.fromhex('f20f38049011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), "???")

        # NP 0F 38 04 /r 1
        # pmaddubsw mm1, mm2/m64
        Buffer = bytes.fromhex('f30f38049011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), "???")

        # VEX.NDS.128.66.0F38.WIG 04 /r
        # Vpmaddubsw xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c40201040e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaddubsw')
        assert_equal(myDisasm.repr(), 'vpmaddubsw xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F38.WIG 04 /r
        # Vpmaddubsw ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c40205040e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaddubsw')
        assert_equal(myDisasm.repr(), 'vpmaddubsw ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.WIG 04 /r
        # Vpmaddubsw xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('62020506040e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaddubsw')
        assert_equal(myDisasm.repr(), 'vpmaddubsw xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.WIG 04 /r
        # Vpmaddubsw ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('62020520040e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaddubsw')
        assert_equal(myDisasm.repr(), 'vpmaddubsw ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.WIG 04 /r
        # Vpmaddubsw zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('62020540040e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x4)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaddubsw')
        assert_equal(myDisasm.repr(), 'vpmaddubsw zmm25, zmm31, zmmword ptr [r14]')
