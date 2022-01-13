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
import struct
import yaml

class TestSuite:

    def test(self):

        # https://code.google.com/archive/p/corkami/wikis/x86oddities.wiki

        # test REX prefix

        Buffer = bytes.fromhex('4088ec')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'mov spl, bpl')

        Buffer = bytes.fromhex('4f89d8')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'mov r8, r11')


        Buffer = bytes.fromhex('2e00f7')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'add bh, dh')

        Buffer = bytes.fromhex('402e00f7')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'add bh, dh')

        Buffer = bytes.fromhex('4000f7')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'add dil, sil')

        Buffer = bytes.fromhex('402e00f7')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'add bh, dh')

        # multiple REX prefixes
        Buffer = bytes.fromhex('48438911')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x89')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'mov')
        assert_equal(myDisasm.repr(), 'mov dword ptr [r9], edx')
