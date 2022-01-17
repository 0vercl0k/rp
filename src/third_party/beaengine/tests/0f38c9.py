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


        # NP 0F 38 C9 /r
        # sha1msg1 xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f38c96b11')
        myDisasm = Disasm(Buffer)
        length = myDisasm.read()
        assert_equal(length, len(Buffer))
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38c9)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sha1msg1')
        assert_equal(myDisasm.repr(), 'sha1msg1 xmm5, xmmword ptr [rbx+11h]')

        self.check_np('0f38c96b11')