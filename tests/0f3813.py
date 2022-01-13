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

        # VEX.128.66.0F38.W0 13 /r
        # VCVTPH2PS xmm1, xmm2/m64

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.R = 1
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}132b'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps xmm5, qword ptr [r11]')

        myVEX = VEX('VEX.128.66.0F38.W0')
        myVEX.R = 1
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps xmm0, xmm8')

        # VEX.256.66.0F38.W0 13 /r
        # VCVTPH2PS ymm1, xmm2/m128

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.R = 1
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}132b'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps ymm5, xmmword ptr [r11]')

        myVEX = VEX('VEX.256.66.0F38.W0')
        myVEX.R = 1
        myVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps ymm0, xmm8')

        # EVEX.128.66.0F38.W0 13 /r
        # VCVTPH2PS xmm1 {k1}{z}, xmm2/m64

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1316'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps xmm26, qword ptr [r14]')

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps xmm24, xmm24')

        # EVEX.256.66.0F38.W0 13 /r
        # VCVTPH2PS ymm1 {k1}{z}, xmm2/m128

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1316'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps ymm26, xmmword ptr [r14]')

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps ymm24, xmm24')

        # EVEX.512.66.0F38.W0 13 /r
        # VCVTPH2PS zmm1 {k1}{z}, ymm2/m256 {sae}

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1316'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps zmm26, ymmword ptr [r14]')

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtph2ps')
        assert_equal(myDisasm.repr(), 'vcvtph2ps zmm24, ymm24')

        # EVEX.128.F3.0F38.W0 13 /r
        # VPMOVUSDW xmm1/m64 {k1}{z}, xmm2

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1316'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdw')
        assert_equal(myDisasm.repr(), 'vpmovusdw qword ptr [r14], xmm26')

        myEVEX = EVEX('EVEX.128.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdw')
        assert_equal(myDisasm.repr(), 'vpmovusdw xmm24, xmm24')


        # EVEX.256.F3.0F38.W0 13 /r
        # VPMOVUSDW xmm1/m128 {k1}{z}, ymm2

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1316'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdw')
        assert_equal(myDisasm.repr(), 'vpmovusdw xmmword ptr [r14], ymm26')

        myEVEX = EVEX('EVEX.256.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdw')
        assert_equal(myDisasm.repr(), 'vpmovusdw xmm24, ymm24')

        # EVEX.512.F3.0F38.W0 13 /r
        # VPMOVUSDW ymm1/m256 {k1}{z}, zmm2

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}1316'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdw')
        assert_equal(myDisasm.repr(), 'vpmovusdw ymmword ptr [r14], zmm26')

        myEVEX = EVEX('EVEX.512.F3.0F38.W0')
        myEVEX.vvvv = 0b1111
        Buffer = bytes.fromhex('{}13c0'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x13)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpmovusdw')
        assert_equal(myDisasm.repr(), 'vpmovusdw ymm24, zmm24')
