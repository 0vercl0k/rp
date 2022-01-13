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



        # EVEX.512.66.0F38.W0 1B /r
        # VBROADCASTF32X8 zmm1 {k1}{z}, m256

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}1b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf32x8')
        assert_equal(myDisasm.repr(), 'vbroadcastf32x8 zmm28, ymmword ptr [r8]')

        # EVEX.512.66.0F38.W1 1B /r
        # VBROADCASTF64X4 zmm1 {k1}{z}, m256

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}1b20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1b)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf64x4')
        assert_equal(myDisasm.repr(), 'vbroadcastf64x4 zmm28, ymmword ptr [r8]')


        # VEX.256.66.0F38.W0 1A /r
        # VBROADCASTF128 ymm1, m128

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1a20'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf128')
        assert_equal(myDisasm.repr(), 'vbroadcastf128 ymm12, xmmword ptr [r8]')

        # EVEX.256.66.0F38.W0 1A /r
        # VBROADCASTF32X4 ymm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}1a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf32x4')
        assert_equal(myDisasm.repr(), 'vbroadcastf32x4 ymm28, xmmword ptr [r8]')

        # EVEX.512.66.0F38.W0 1A /r
        # VBROADCASTF32X4 zmm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}1a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf32x4')
        assert_equal(myDisasm.repr(), 'vbroadcastf32x4 zmm28, xmmword ptr [r8]')

        # EVEX.256.66.0F38.W1 1A /r
        # VBROADCASTF64X2 ymm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}1a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf64x2')
        assert_equal(myDisasm.repr(), 'vbroadcastf64x2 ymm28, xmmword ptr [r8]')

        # EVEX.512.66.0F38.W1 1A /r
        # VBROADCASTF64X2 zmm1 {k1}{z}, m128

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}1a20'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x1a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf64x2')
        assert_equal(myDisasm.repr(), 'vbroadcastf64x2 zmm28, xmmword ptr [r8]')







        # VEX.256.66.0F38.W0 19 /r
        # VBROADCASTSD ymm1, m64

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1920'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastsd')
        assert_equal(myDisasm.repr(), 'vbroadcastsd ymm12, qword ptr [r8]')

        # VEX.256.66.0F38.W0 19 /r
        # VBROADCASTSD ymm1, xmm2

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}19c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastsd')
        assert_equal(myDisasm.repr(), 'vbroadcastsd ymm8, xmm8')

        # EVEX.256.66.0F38.W1 19 /r
        # VBROADCASTSD ymm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}1920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastsd')
        assert_equal(myDisasm.repr(), 'vbroadcastsd ymm28, qword ptr [r8]')

        # EVEX.512.66.0F38.W1 19 /r
        # VBROADCASTSD zmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}1920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastsd')
        assert_equal(myDisasm.repr(), 'vbroadcastsd zmm28, qword ptr [r8]')

        # EVEX.256.66.0F38.W0 19 /r
        # VBROADCASTF32X2 ymm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}1920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf32x2')
        assert_equal(myDisasm.repr(), 'vbroadcastf32x2 ymm28, qword ptr [r8]')

        # EVEX.512.66.0F38.W0 19 /r
        # VBROADCASTF32X2 zmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}1920'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x19)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vbroadcastf32x2')
        assert_equal(myDisasm.repr(), 'vbroadcastf32x2 zmm28, qword ptr [r8]')
