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


        # NP 0F 2E /r
        # UCOMISS xmm1, xmm2/m32

        Buffer = bytes.fromhex('0f2e20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ucomiss')
        assert_equal(myDisasm.repr(), 'ucomiss xmm4, dword ptr [rax]')


        # VEX.LIG.0F.WIG 2E /r
        # VUCOMISS xmm1, xmm2/m32

        myVEX = VEX('VEX.LIG.0F.WIG')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2e10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vucomiss')
        assert_equal(myDisasm.repr(), 'vucomiss xmm10, dword ptr [r8]')
        assert_equal(myDisasm.infos.Reserved_.VEX.vvvv, 15)
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, 0)


        # EVEX.LIG.0F.W0 2E /r
        # VUCOMISS xmm1, xmm2/m32{sae}

        myEVEX = EVEX('EVEX.LIG.0F.W0')
        Buffer = bytes.fromhex('{}2e16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vucomiss')
        assert_equal(myDisasm.repr(), 'vucomiss xmm26, dword ptr [r14]')

        # 66 0F 2E /r
        # UCOMISD xmm1, xmm2/m64

        Buffer = bytes.fromhex('660f2e20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'ucomisd')
        assert_equal(myDisasm.repr(), 'ucomisd xmm4, qword ptr [rax]')

        # VEX.LIG.66.0F.WIG 2E /r
        # VUCOMISD xmm1, xmm2/m64

        myVEX = VEX('VEX.LIG.66.0F.WIG')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}2e10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vucomisd')
        assert_equal(myDisasm.repr(), 'vucomisd xmm10, qword ptr [r8]')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, 0)

        # EVEX.LIG.66.0F.W1 2E /r
        # VUCOMISD xmm1, xmm2/m64{sae}

        myEVEX = EVEX('EVEX.LIG.66.0F.W1')
        Buffer = bytes.fromhex('{}2e16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vucomisd')
        assert_equal(myDisasm.repr(), 'vucomisd xmm26, qword ptr [r14]')

        # VEX.vvvv and EVEX.vvvv are reserved and must be 1111b, otherwise instructions will #UD.

        myEVEX = EVEX('EVEX.LIG.66.0F.W1')
        myEVEX.vvvv = 0b1000
        Buffer = bytes.fromhex('{}2e16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2e)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vucomisd')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
