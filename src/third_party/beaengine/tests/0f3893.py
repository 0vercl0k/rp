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


        # EVEX.128.66.0F38.W0 93 /vsib
        # VGATHERQPS xmm1 {k1}, vm64x

        myEVEX = EVEX('EVEX.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}93443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqps')
        #assert_equal(myDisasm.infos.Reserved_.EVEX.X, 1)
        assert_equal(myDisasm.repr(), 'vgatherqps xmm24, qword ptr [r11+xmm30+22h]')

        # EVEX.256.66.0F38.W0 93 /vsib
        # VGATHERQPS xmm1 {k1}, vm64y

        myEVEX = EVEX('EVEX.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}93443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqps')
        assert_equal(myDisasm.repr(), 'vgatherqps xmm24, qword ptr [r11+ymm30+22h]')

        # EVEX.512.66.0F38.W0 93 /vsib
        # VGATHERQPS ymm1 {k1}, vm64z

        myEVEX = EVEX('EVEX.512.66.0F38.W0')
        Buffer = bytes.fromhex('{}93443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqps')
        assert_equal(myDisasm.repr(), 'vgatherqps ymm24, qword ptr [r11+zmm30+0088h]')

        # EVEX.128.66.0F38.W1 93 /vsib
        # VGATHERQPD xmm1 {k1}, vm64x

        myEVEX = EVEX('EVEX.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}93443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqpd')
        assert_equal(myDisasm.repr(), 'vgatherqpd xmm24, qword ptr [r11+xmm30+22h]')

        # EVEX.256.66.0F38.W1 93 /vsib
        # VGATHERQPD ymm1 {k1}, vm64y

        myEVEX = EVEX('EVEX.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}93443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqpd')
        assert_equal(myDisasm.repr(), 'vgatherqpd ymm24, qword ptr [r11+ymm30+22h]')

        # EVEX.512.66.0F38.W1 93 /vsib
        # VGATHERQPD zmm1 {k1}, vm64z

        myEVEX = EVEX('EVEX.512.66.0F38.W1')
        Buffer = bytes.fromhex('{}93443322'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqpd')
        assert_equal(myDisasm.repr(), 'vgatherqpd zmm24, qword ptr [r11+zmm30+0110h]')

        # VEX.DDS.128.66.0F38.W1 93 /r
        # VGATHERQPD xmm1, vm64x, xmm2

        myVEX = VEX('VEX.DDS.128.66.0F38.W1')
        Buffer = bytes.fromhex('{}930e'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqpd')
        assert_equal(myDisasm.repr(), 'vgatherqpd xmm9, qword ptr [r14], xmm15')

        # VEX.DDS.256.66.0F38.W1 93 /r
        # VGATHERQPD ymm1, vm64y, ymm2

        myVEX = VEX('VEX.DDS.256.66.0F38.W1')
        Buffer = bytes.fromhex('{}93443322'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqpd')
        assert_equal(myDisasm.repr(), 'vgatherqpd ymm8, dword ptr [r11+ymm14+22h], ymm15')

        # VEX.DDS.128.66.0F38.W0 93 /r
        # VGATHERQPS xmm1, vm64x, xmm2

        myVEX = VEX('VEX.DDS.128.66.0F38.W0')
        Buffer = bytes.fromhex('{}93443322'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqps')
        assert_equal(myDisasm.repr(), 'vgatherqps xmm8, qword ptr [r11+xmm14+22h], xmm15')

        # VEX.DDS.256.66.0F38.W0 93 /r
        # VGATHERQPS xmm1, vm64y, xmm2

        myVEX = VEX('VEX.DDS.256.66.0F38.W0')
        Buffer = bytes.fromhex('{}93443322'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vgatherqps')
        assert_equal(myDisasm.repr(), 'vgatherqps xmm8, qword ptr [r11+ymm14+22h], xmm15')
