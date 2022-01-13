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
        # 66 0F fe /r
        # paddd mm1, mm2/m64
        Buffer = bytes.fromhex('660ffe9011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xffe')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'paddd')
        assert_equal(myDisasm.repr(), 'paddd xmm2, xmmword ptr [rax+44332211h]')

        # VEX.NDS.128.66.0F.WIG fe /r
        # vpaddd xmm1, xmm2, xmm3/m128
        Buffer = bytes.fromhex('c40101fe0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpaddd')
        assert_equal(myDisasm.repr(), 'vpaddd xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F.WIG fe /r
        # vpaddd ymm1, ymm2, ymm3/m256
        Buffer = bytes.fromhex('c40105fe0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpaddd')
        assert_equal(myDisasm.repr(), 'vpaddd ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F.WIG fe /r
        # vpaddd xmm1 {k1}{z}, xmm2, xmm3/m128

        myEVEX = EVEX('EVEX.NDS.128.66.0F.WIG')
        myEVEX.b = 0
        myEVEX.W = 0
        Buffer = bytes.fromhex('{}fe4350'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfe')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpaddd')
        assert_equal(myDisasm.repr(), 'vpaddd xmm24, xmm31, xmmword ptr [r11+0500h]')

        # EVEX.NDS.256.66.0F.WIG fe /r
        # vpaddd ymm1 {k1}{z}, ymm2, ymm3/m256
        Buffer = bytes.fromhex('62010520fe443322')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x20)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfe')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpaddd')
        assert_equal(myDisasm.repr(), 'vpaddd ymm24, ymm31, ymmword ptr [r11+r14+0440h]')

        # EVEX.NDS.512.66.0F.WIG fe /r
        # vpaddd zmm1 {k1}{z}, zmm2, zmm3/m512
        Buffer = bytes.fromhex('62010540fe0e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x5)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0x40)
        assert_equal(myDisasm.infos.Reserved_.EVEX.pp, 0x1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.mm, 0x1)
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfe')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpaddd')
        assert_equal(myDisasm.repr(), 'vpaddd zmm25, zmm31, zmmword ptr [r14]')
