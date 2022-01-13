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
    def test(self):


        # 0F 37 /r
        # GETSEC

        Buffer = bytes.fromhex('0f37')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf37')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'getsec')
        assert_equal(myDisasm.repr(), 'getsec')


        # 66 0F 37 /r
        # GETSEC

        Buffer = bytes.fromhex('660f37')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf37')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'getsec')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # F0 0F 37 /r
        # GETSEC

        Buffer = bytes.fromhex('f00f37')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf37')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'getsec')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # F2 0F 37 /r
        # GETSEC

        Buffer = bytes.fromhex('f20f37')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf37')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'getsec')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        # F3 0F 37 /r
        # GETSEC

        Buffer = bytes.fromhex('f30f37')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf37')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'getsec')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)


        # VEX.NDS.128.0F.WIG 37 /r
        # getsec

        myVEX = VEX('VEX.NDS.128.0F.WIG')
        Buffer = bytes.fromhex('{}37'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'???')

        # EVEX.NDS.128.0F.W0 37 /r
        # getsec

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}37'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'???')
