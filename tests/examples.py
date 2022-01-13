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

class TestExample:

    #def setUp(self):

    def test_SimpleUseCase(self):
        Buffer = bytes.fromhex('4889ce')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'mov rsi, rcx')

    def test_VirtualAddrUseCase(self):
        Buffer = b'\xe9\x00\x00\x00\x00'
        myDisasm = Disasm(Buffer)
        myDisasm.infos.VirtualAddr = 0x401000
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.AddrValue, 0x401005)

    def test_OptionsUseCase(self):
        Buffer = b'\x89\x94\x88\x00\x20\x40\x00'
        myDisasm = Disasm(Buffer)
        myDisasm.infos.Options = NasmSyntax + PrefixedNumeral + ShowSegmentRegs
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'mov  [ds:rax+rcx*4+0x00402000], edx')
