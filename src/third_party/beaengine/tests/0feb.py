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
        # 66 0F eb /r
        # por mm1, mm2/m64
        Buffer = bytes.fromhex('660feb9011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfeb')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'por')
        assert_equal(myDisasm.repr(), 'por xmm2, xmmword ptr [rax+44332211h]')

        # VEX.NDS.128.66.0F.WIG eb /r
        # vpor xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c40101eb0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpor')
        assert_equal(myDisasm.repr(), 'vpor xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F.WIG eb /r
        # vpor ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c40105eb0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpor')
        assert_equal(myDisasm.repr(), 'vpor ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F.W0 EB /r
        # VPORD xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        Buffer = bytes.fromhex('62010506eb0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xeb')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpord')
        assert_equal(myDisasm.repr(), 'vpord xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F.W0 EB /r
        # VPORD ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        Buffer = bytes.fromhex('62010520eb0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xeb')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpord')
        assert_equal(myDisasm.repr(), 'vpord ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F.W0 EB /r
        # VPORD zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        Buffer = bytes.fromhex('62010540eb0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xeb')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpord')
        assert_equal(myDisasm.repr(), 'vpord zmm25, zmm31, zmmword ptr [r14]')

        # EVEX.NDS.128.66.0F.W1 EB /r
        # VPORQ xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        # EVEX.NDS.256.66.0F.W1 EB /r
        # VPORQ ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        # EVEX.NDS.512.66.0F.W1 EB /r
        # VPORQ zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst
