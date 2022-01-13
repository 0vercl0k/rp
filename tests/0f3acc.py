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

        # NP 0F 3A CC /r ib
        # SHA1RNDS4 xmm1, xmm2/m128, imm8

        Buffer = bytes.fromhex('0f3acc2033')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf3acc)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'sha1rnds4')
        assert_equal(myDisasm.repr(), 'sha1rnds4 xmm4, xmmword ptr [rax], 33h')

        self.check_np('0f3acc2033')