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

    def check_np(self, data):
        Buffer = bytes.fromhex(f'66{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???')

        Buffer = bytes.fromhex(f'f2{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???')

        Buffer = bytes.fromhex(f'f3{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???') 

    def test(self):

        # NP 0F 38 CD /r
        # SHA256MSG2 xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f38cd6b11')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf38cd')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sha256msg2')
        assert_equal(myDisasm.repr(), 'sha256msg2 xmm5, xmmword ptr [rbx+11h]')

        self.check_np('0f38cd6b11')

        # EVEX.NDS.LIG.66.0F38.W0 CD /r
        # VRSQRT28SS xmm1 {k1}{z}, xmm2, xmm3/m32 {sae}

        myEVEX = EVEX('EVEX.NDS.LIG.66.0F38.W0')
        Buffer = bytes.fromhex('{}cd00'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xcd)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vrsqrt28ss')
        assert_equal(myDisasm.repr(), 'vrsqrt28ss xmm24, xmm31, dword ptr [r8]')

        # EVEX.NDS.LIG.66.0F38.W1 CD /r
        # VRSQRT28SD xmm1 {k1}{z}, xmm2, xmm3/m64 {sae}

        myEVEX = EVEX('EVEX.NDS.LIG.66.0F38.W1')
        Buffer = bytes.fromhex('{}cd00'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xcd)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vrsqrt28sd')
        assert_equal(myDisasm.repr(), 'vrsqrt28sd xmm24, xmm31, qword ptr [r8]')
