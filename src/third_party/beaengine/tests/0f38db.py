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

    def test(self):

        # 66 0F 38 db /r
        # aesimc xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f38db6bA2')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf38db')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'aesimc')
        assert_equal(myDisasm.repr(), 'aesimc xmm5, xmmword ptr [rbx-5Eh]')


        # VEX.NDS.128.66.0F38.WIG db /r
        # Vaesimc xmm1, xmm2, xmm3/m128

        myVEX = VEX()
        myVEX.L = 0
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.B = 1

        Buffer = bytes.fromhex('c4{:02x}{:02x}db6ba2'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'vaesimc xmm5, xmmword ptr [rbx-5Eh]')

        # if VEX.vvvv != 0b1111 #UD

        myVEX.reset()
        myVEX.L = 0
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1110
        myVEX.R = 1
        myVEX.B = 1

        Buffer = bytes.fromhex('c4{:02x}{:02x}db6ba2'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vaesimc')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
