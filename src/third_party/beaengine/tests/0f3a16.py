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

        # 66 0F 3A 16 /r ib
        # PEXTRD r/m32, xmm2, imm8

        Buffer = bytes.fromhex('660f3a162011')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pextrd')
        assert_equal(myDisasm.repr(), 'pextrd dword ptr [rax], xmm4, 11h')

        # 66 REX.W 0F 3A 16 /r ib
        # PEXTRQ r/m64, xmm2, imm8

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('66{:02x}0f3a162011'.format(myREX.byte()))

        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f3a16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'pextrq')
        assert_equal(myDisasm.repr(), 'pextrq qword ptr [rax], xmm4, 11h')

        # VEX.128.66.0F3A.W0 16 /r ib
        # VPEXTRD r32/m32, xmm2, imm8

        myVEX = VEX('VEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}16e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrd')
        assert_equal(myDisasm.repr(), 'vpextrd r8d, xmm12, 11h')

        # VEX.128.66.0F3A.W1 16 /r ib
        # VPEXTRQ r64/m64, xmm2, imm8

        myVEX = VEX('VEX.128.66.0F3A.W1')
        Buffer = bytes.fromhex('{}16e011'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrq')
        assert_equal(myDisasm.repr(), 'vpextrq r8, xmm12, 11h')

        # EVEX.128.66.0F3A.W0 16 /r ib
        # VPEXTRD r32/m32, xmm2, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W0')
        Buffer = bytes.fromhex('{}162011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrd')
        assert_equal(myDisasm.repr(), 'vpextrd dword ptr [r8], xmm28, 11h')

        # EVEX.128.66.0F3A.W1 16 /r ib
        # VPEXTRQ r64/m64, xmm2, imm8

        myEVEX = EVEX('EVEX.128.66.0F3A.W1')
        Buffer = bytes.fromhex('{}162011'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x16)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpextrq')
        assert_equal(myDisasm.repr(), 'vpextrq qword ptr [r8], xmm28, 11h')
