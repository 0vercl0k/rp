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
        # 66 0F 6a /r
        # punpckhdq mm1, mm2/m64
        Buffer = bytes.fromhex('660f6a9011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf6a')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhdq')
        assert_equal(myDisasm.repr(), 'punpckhdq xmm2, xmmword ptr [rax+44332211h]')

        # VEX.NDS.128.66.0F.WIG 6a /r
        # vpunpckhdq xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c401016a0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpunpckhdq')
        assert_equal(myDisasm.repr(), 'vpunpckhdq xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F.WIG 6a /r
        # vpunpckhdq ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c401056a0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpunpckhdq')
        assert_equal(myDisasm.repr(), 'vpunpckhdq ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F.WIG 6a /r
        # vpunpckhdq xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('620105066a0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x6)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x6a')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpunpckhdq')
        assert_equal(myDisasm.repr(), 'vpunpckhdq xmm25, xmm31, xmmword ptr [r14]')

        # EVEX.NDS.256.66.0F.WIG 6a /r
        # vpunpckhdq ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('620105206a0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x6a')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpunpckhdq')
        assert_equal(myDisasm.repr(), 'vpunpckhdq ymm25, ymm31, ymmword ptr [r14]')

        # EVEX.NDS.512.66.0F.WIG 6a /r
        # vpunpckhdq zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('620105406a0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x6a')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpunpckhdq')
        assert_equal(myDisasm.repr(), 'vpunpckhdq zmm25, zmm31, zmmword ptr [r14]')
