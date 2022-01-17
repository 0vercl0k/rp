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

        # VEX.128.66.0F38.W0 59 /r
        # VPBROADCASTQ xmm1, xmm2/m64

        myVEX = VEX('VEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}5910'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastq')
        assert_equal(myDisasm.repr(), 'vpbroadcastq xmm10, qword ptr [r8]')

        # VEX.256.66.0F38.W0 59 /r
        # VPBROADCASTQ ymm1, xmm2/m64

        myVEX = VEX('VEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}5910'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastq')
        assert_equal(myDisasm.repr(), 'vpbroadcastq ymm10, qword ptr [r8]')

        # EVEX.128.66.0F38.W1 59 /r
        # VPBROADCASTQ xmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}590e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastq')
        assert_equal(myDisasm.repr(), 'vpbroadcastq xmm25, qword ptr [r14]')

        # EVEX.256.66.0F38.W1 59 /r
        # VPBROADCASTQ ymm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}590e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastq')
        assert_equal(myDisasm.repr(), 'vpbroadcastq ymm25, qword ptr [r14]')

        # EVEX.512.66.0F38.W1 59 /r
        # VPBROADCASTQ zmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}590e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpbroadcastq')
        assert_equal(myDisasm.repr(), 'vpbroadcastq zmm25, qword ptr [r14]')

        # EVEX.128.66.0F38.W0 59 /r
        # VBROADCASTI32x2 xmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}590e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti32x2')
        assert_equal(myDisasm.repr(), 'vbroadcasti32x2 xmm25, qword ptr [r14]')

        # EVEX.256.66.0F38.W0 59 /r
        # VBROADCASTI32x2 ymm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}590e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti32x2')
        assert_equal(myDisasm.repr(), 'vbroadcasti32x2 ymm25, qword ptr [r14]')

        # EVEX.512.66.0F38.W0 59 /r
        # VBROADCASTI32x2 zmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}590e'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x59)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcasti32x2')
        assert_equal(myDisasm.repr(), 'vbroadcasti32x2 zmm25, qword ptr [r14]')
