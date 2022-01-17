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
    """
    VEX Prefix #UD
    vphsubsw xmm1, xmm2, xmm3/m128
    """
    def test(self):
        # VEX Prefix must be the last one just before the opcode
        # @TODO : Find examples

        # VEX precedeed by 66h
        Buffer = bytes.fromhex('66c40201070e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX precedeed by F2h
        Buffer = bytes.fromhex('f2c40201070e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX precedeed by F3h
        Buffer = bytes.fromhex('f3c40201070e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX precedeed by F0h
        Buffer = bytes.fromhex('f0c40201070e')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX precedeed by REX
        for i in range(0x48, 0x4f):
            Buffer = bytes.fromhex('{:2x}c40201070e'.format(i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX precedeed by REX
        for i in range(0x40, 0x47):
            Buffer = bytes.fromhex('{:2x}c40201070e'.format(i))
            print(Buffer)
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # VEX.L for specific instructions

        # VEX.W for specific instructions

        # The VEX prefix will #UD on any instruction containing MMX register sources or destinations.
