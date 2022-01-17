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
    https://github.com/BeaEngine/beaengine/issues/3
    """
    def test(self):

        Buffer = bytes.fromhex('0fef08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pxor')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fef08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pxor')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0f6208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckldq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660f6208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckldq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0f6108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpcklwd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660f6108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpcklwd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0f6008')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpcklbw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660f6008')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpcklbw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0f6a08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhdq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660f6a08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhdq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0f6908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhwd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660f6908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhwd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0f6808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhbw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660f6808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'punpckhbw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fd908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubusw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fd908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubusw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fd808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubusb')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fd808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubusb')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fe908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubsw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        Buffer = bytes.fromhex('660fe908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubsw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        Buffer = bytes.fromhex('0fe808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubsb')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fe808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubsb')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ffa08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ffa08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ff908')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubb')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ff808')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubb')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fe208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrad')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fe208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrad')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fe108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psraw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fe108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psraw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fd308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrlq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fd308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrlq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fd208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrld')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fd208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrld')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fd108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrlw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fd108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psrlw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psllq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ff308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psllq')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pslld')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ff208')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pslld')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psllw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ff108')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psllw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0feb08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'por')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660fe508')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmulhw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fe508')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmulhw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff508')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmaddwd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('660ff508')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pmaddwd')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fa308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bt')
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        Buffer = bytes.fromhex('0fab08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bts')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fb308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'btr')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fa308')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'bt')
        assert_equal(myDisasm.infos.Operand1.AccessMode, WRITE)

        Buffer = bytes.fromhex('0fbb08')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'btc')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0fc708')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cmpxchg8b')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)

        Buffer = bytes.fromhex('0ff911')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'psubw')
        assert_equal(myDisasm.infos.Operand1.AccessMode, READ + WRITE)
