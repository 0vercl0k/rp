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

    def test(self):

        # VEX.NDS.256.66.0F.WIG 5c /r
        # vsubpd ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        myVEX.B = 1
        Buffer = bytes.fromhex('{}5c4544'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsubpd')
        assert_equal(myDisasm.repr(), 'vsubpd ymm8, ymm15, ymmword ptr [rbp+44h]')

        myVEX = VEX('VEX.NDS.256.66.0F.WIG')
        myVEX.B = 1
        Buffer = bytes.fromhex('{}5c0500111111'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.infos.VirtualAddr = 0x11111100
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5c)
        assert_equal(myDisasm.infos.Reserved_.NB_PREFIX, 1)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsubpd')
        assert_equal(myDisasm.infos.Operand3.Memory.Displacement, 0x11111100)
        assert_equal(myDisasm.repr(), 'vsubpd ymm8, ymm15, ymmword ptr [0000000022222209h]')


        # EVEX.NDS.128.66.0F.W1 5c /r
        # vsubpd xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}5c0500111111'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.infos.VirtualAddr = 0x11111100
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsubpd')
        assert_equal(myDisasm.repr(), 'vsubpd xmm24, xmm31, xmmword ptr [000000002222220Ah]')


        # 66 0F 38 DF /r
        # AESdeclast xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f38df0500111111')
        myDisasm = Disasm(Buffer)
        myDisasm.infos.VirtualAddr = 0x11111100
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'aesdeclast')
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf38df)
        assert_equal(myDisasm.infos.Instruction.AddrValue, 0x22222209)
        assert_equal(myDisasm.infos.Reserved_.NB_PREFIX, 1)
        assert_equal(myDisasm.infos.Operand2.Memory.Displacement, 0x11111100)
        assert_equal(myDisasm.repr(), 'aesdeclast xmm0, xmmword ptr [0000000022222209h]')


        # 66 0F 5c /r
        # subpd xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f5c0500111111')
        myDisasm = Disasm(Buffer)
        myDisasm.infos.VirtualAddr = 0x11111100
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf5c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'subpd')
        assert_equal(myDisasm.repr(), 'subpd xmm0, xmmword ptr [0000000022222208h]')


        # EVEX.NDS.128.66.0F.W1 5c /r
        # vsubpd xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        myEVEX.B = 1
        myEVEX.R = 1
        myEVEX.Rprime = 1
        myEVEX.X = 1
        myEVEX.V = 1
        Buffer = bytes.fromhex('{}5cca'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.infos.VirtualAddr = 0x11111100
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x5c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vsubpd')
        assert_equal(myDisasm.repr(), 'vsubpd xmm1, xmm15, xmm2')


        # EVEX.128.66.0F38.W0 91 /vsib
        # VPgatherqD xmm1 {k1}, vm32x

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        myEVEX.X = 1
        myEVEX.V = 1
        Buffer = bytes.fromhex('{}91443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vpgatherqd')
        assert_equal(myDisasm.repr(), 'vpgatherqd xmm24, qword ptr [r11+xmm6+22h]')
