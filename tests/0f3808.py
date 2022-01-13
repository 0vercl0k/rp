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
    Packed Sign
    - psignb Pq, Qq
    - vpsignb Vx, Hx, Wx
    """
    def test(self):
        # NP 0F 38 08 /r1
        # PSIGNB mm1, mm2/m64

        Buffer = bytes.fromhex('0f38089011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf3808')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psignb')
        assert_equal(myDisasm.repr(), 'psignb mm2, qword ptr [rax+44332211h]')

        # 66 0F 38 08 /r
        # psignb xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f38089011223344')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf3808')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psignb')
        assert_equal(myDisasm.repr(), 'psignb xmm2, xmmword ptr [rax+44332211h]')

        # VEX.NDS.128.66.0F38.WIG 08 /r
        # vpsignb xmm1, xmm2, xmm3/m128

        Buffer = bytes.fromhex('c40201080e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpsignb')
        assert_equal(myDisasm.repr(), 'vpsignb xmm9, xmm15, xmmword ptr [r14]')

        # VEX.NDS.256.66.0F38.WIG 08 /r
        # vpsignb ymm1, ymm2, ymm3/m256

        Buffer = bytes.fromhex('c40205080e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpsignb')
        assert_equal(myDisasm.repr(), 'vpsignb ymm9, ymm15, ymmword ptr [r14]')

        # EVEX.NDS.128.66.0F38.WIG 08 /r
        # vpsignb xmm1 {k1}{z}, xmm2, xmm3/m128
        Buffer = bytes.fromhex('62020508070e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'???')
