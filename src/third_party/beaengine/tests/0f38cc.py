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

        # NP 0F 38 CC /r
        # SHA256MSG1 xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f38cc6b11')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf38cc')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sha256msg1')
        assert_equal(myDisasm.repr(), 'sha256msg1 xmm5, xmmword ptr [rbx+11h]')

        self.check_np('0f38cc6b11')

        # EVEX.512.66.0F38.W0 CC /r
        # VRSQRT28PS zmm1 {k1}{z},zmm2/m512/m32bcst {sae}

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}cc00'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xcc)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vrsqrt28ps')
        assert_equal(myDisasm.repr(), 'vrsqrt28ps zmm24, zmmword ptr [r8]')


        # EVEX.512.66.0F38.W1 CC /r
        # VRSQRT28PD zmm1 {k1}{z}, zmm2/m512/m64bcst {sae}

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}cc00'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xcc)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vrsqrt28pd')
        assert_equal(myDisasm.repr(), 'vrsqrt28pd zmm24, zmmword ptr [r8]')
