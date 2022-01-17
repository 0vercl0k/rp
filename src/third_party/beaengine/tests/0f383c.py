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
        # 66 0F 38 3c /r
        # pmaxsb mm1, mm2/m64
        Buffer = bytes.fromhex('660f383c9011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf383c')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmaxsb')
        assert_equal(myDisasm.repr(), 'pmaxsb xmm2, xmmword ptr [rax+44332211h]')

        # VEX.NDS.128.66.0F38.WIG 3c /r
        # vpmaxsb xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c402013c0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaxsb')
        assert_equal(myDisasm.repr(), 'vpmaxsb xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F38.WIG 3c /r
        # vpmaxsb ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c402053c0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaxsb')
        assert_equal(myDisasm.repr(), 'vpmaxsb ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.WIG 3c /r
        # vpmaxsb xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('620205063c0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x3c')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaxsb')
        assert_equal(myDisasm.repr(), 'vpmaxsb xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F38.WIG 3c /r
        # vpmaxsb ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('620205203c0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x3c')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaxsb')
        assert_equal(myDisasm.repr(), 'vpmaxsb ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F38.WIG 3c /r
        # vpmaxsb zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('620205403c0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x2)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x2)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x3c')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmaxsb')
        assert_equal(myDisasm.repr(), 'vpmaxsb zmm25, zmm31, zmmword ptr [r14]')
