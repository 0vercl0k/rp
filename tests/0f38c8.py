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
    Variable Blend Packed
    """

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


        # EVEX.512.66.0F38.W1 C8 /r
        # VEXP2PD zmm1 {k1}{z}, zmm2/m512/m64bcst {sae}

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}c800'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc8)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexp2pd')
        assert_equal(myDisasm.repr(), 'vexp2pd zmm24, zmmword ptr [r8]')

        # EVEX.512.66.0F38.W0 C8 /r
        # VEXP2PS zmm1 {k1}{z}, zmm2/m512/m32bcst {sae}

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}c800'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xc8)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vexp2ps')
        assert_equal(myDisasm.repr(), 'vexp2ps zmm24, zmmword ptr [r8]')

        # NP 0F 38 C8 /r
        # SHA1NEXTE xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f38c86b11')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf38c8')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sha1nexte')
        assert_equal(myDisasm.repr(), 'sha1nexte xmm5, xmmword ptr [rbx+11h]')

        self.check_np('0f38c86b11')