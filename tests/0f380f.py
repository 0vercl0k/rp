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
    Packed Bit Test
    """

    def test(self):

        # VEX.128.66.0F38.W0 0F /r
        # vtestpd xmm1, xmm2/m128

        myVEX = VEX()
        myVEX.L = 0
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.B = 1

        Buffer = bytes.fromhex('c4{:02x}{:02x}0fc0'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'vtestpd xmm0, xmm0')

        # VEX.128.66.0F38.W0 0F /r
        # vtestpd xmm1, xmm2/m128

        myVEX = VEX()
        myVEX.L = 0
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.B = 1

        Buffer = bytes.fromhex('c4{:02x}{:02x}0f27'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'vtestpd xmm4, xmmword ptr [rdi]')

        # VEX.256.66.0F38.W0 0F /r
        # vtestpd ymm1, ymm2/m256

        myVEX.reset()
        myVEX.L = 1
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.B = 1

        Buffer = bytes.fromhex('c4{:02x}{:02x}0fc0'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'vtestpd ymm0, ymm0')

        # VEX.256.66.0F38.W0 0F /r
        # vtestpd ymm1, ymm2/m256

        myVEX.reset()
        myVEX.L = 1
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1111
        myVEX.R = 1
        myVEX.B = 1

        Buffer = bytes.fromhex('c4{:02x}{:02x}0f8200000000'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), 'vtestpd ymm0, ymmword ptr [rdx+00000000h]')

        # if VEX.W = 1 #UD

        myVEX.reset()
        myVEX.W = 1
        myVEX.L = 1
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0b1111

        Buffer = bytes.fromhex('c4{:02x}{:02x}0f00'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vtestpd')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # if VEX.vvvv != 0b1111 #UD

        myVEX.reset()
        myVEX.L = 1
        myVEX.pp = 0b1
        myVEX.mmmm = 0b10
        myVEX.vvvv = 0

        Buffer = bytes.fromhex('c4{:02x}{:02x}0f00'.format(myVEX.byte1(), myVEX.byte2()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vtestpd')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
