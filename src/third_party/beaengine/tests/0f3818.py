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

        # VEX.128.66.0F38.W0 18 /r
        # VBROADCASTSS xmm1, m32

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1820'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss xmm12, dword ptr [r8]')

        # VEX.256.66.0F38.W0 18 /r
        # VBROADCASTSS ymm1, m32

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1820'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss ymm12, dword ptr [r8]')

        # VEX.128.66.0F38.W0 18/r
        # VBROADCASTSS xmm1, xmm2

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}18c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss xmm8, xmm8')

        # VEX.256.66.0F38.W0 18 /r
        # VBROADCASTSS ymm1, xmm2

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}18c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss ymm8, xmm8')

        # EVEX.128.66.0F38.W0 18 /r
        # VBROADCASTSS xmm1 {k1}{z}, xmm2/m32

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}1820'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss xmm28, dword ptr [r8]')

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}18c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss xmm24, xmm24')

        # EVEX.256.66.0F38.W0 18 /r
        # VBROADCASTSS ymm1 {k1}{z}, xmm2/m32

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}1820'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss ymm28, dword ptr [r8]')

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}18c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss ymm24, xmm24')

        # EVEX.512.66.0F38.W0 18 /r
        # VBROADCASTSS zmm1 {k1}{z}, xmm2/m32

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}1820'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss zmm28, dword ptr [r8]')

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}18c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x18)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastss')
        assert_equal(myDisasm.repr(), 'vbroadcastss zmm24, xmm24')
