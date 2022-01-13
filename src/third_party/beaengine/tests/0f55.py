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

    def check_np(self, data):
        Buffer = bytes.fromhex(f'f2{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???')

        Buffer = bytes.fromhex(f'f3{data}')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.repr(), '???') 

    def test(self):

        # NP 0F 55 /r
        # andnpS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f559000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf55')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'andnps')
        assert_equal(myDisasm.repr(), 'andnps xmm2, xmmword ptr [rax+00000000h]')

        self.check_np('0f559000000000')

        # VEX.NDS.128.0F 55 /r
        # VandnpS xmm1,xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.0F')
        Buffer = bytes.fromhex('{}559000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x55')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnps')
        assert_equal(myDisasm.repr(), 'vandnps xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.0F 55 /r
        # VandnpS ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.0F')
        Buffer = bytes.fromhex('{}559000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x55')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnps')
        assert_equal(myDisasm.repr(), 'vandnps ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.0F.W0 55 /r
        # VandnpS xmm1 {k1}{z}, xmm2, xmm3/m128/m32bcst

        myEVEX = EVEX('EVEX.NDS.128.0F.W0')
        Buffer = bytes.fromhex('{}559000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x55)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnps')
        assert_equal(myDisasm.repr(), 'vandnps xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.0F.W0 55 /r
        # VandnpS ymm1 {k1}{z}, ymm2, ymm3/m256/m32bcst

        myEVEX = EVEX('EVEX.NDS.256.0F.W0')
        Buffer = bytes.fromhex('{}559000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x55)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnps')
        assert_equal(myDisasm.repr(), 'vandnps ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.0F.W0 55 /r
        # VandnpS zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst

        myEVEX = EVEX('EVEX.NDS.512.0F.W0')
        Buffer = bytes.fromhex('{}559000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x55)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnps')
        assert_equal(myDisasm.repr(), 'vandnps zmm26, zmm31, zmmword ptr [r8+00000000h]')

        # 66 0F 55 /r
        # andnpD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f559000000000')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xf55')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'andnpd')
        assert_equal(myDisasm.repr(), 'andnpd xmm2, xmmword ptr [rax+00000000h]')

        # VEX.NDS.128.66.0F 55 /r
        # VandnpD xmm1, xmm2, xmm3/m128

        myVEX = VEX('VEX.NDS.128.66.0F')
        Buffer = bytes.fromhex('{}559000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x55')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnpd')
        assert_equal(myDisasm.repr(), 'vandnpd xmm10, xmm15, xmmword ptr [r8+00000000h]')

        # VEX.NDS.256.66.0F 55 /r
        # VandnpD ymm1, ymm2, ymm3/m256

        myVEX = VEX('VEX.NDS.256.66.0F')
        Buffer = bytes.fromhex('{}559000000000'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0x55')
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnpd')
        assert_equal(myDisasm.repr(), 'vandnpd ymm10, ymm15, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.128.66.0F.W1 55 /r
        # VandnpD xmm1 {k1}{z}, xmm2, xmm3/m128/m64bcst

        myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
        Buffer = bytes.fromhex('{}559000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x55)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnpd')
        assert_equal(myDisasm.repr(), 'vandnpd xmm26, xmm31, xmmword ptr [r8+00000000h]')

        # EVEX.NDS.256.66.0F.W1 55 /r
        # VandnpD ymm1 {k1}{z}, ymm2, ymm3/m256/m64bcst

        myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
        Buffer = bytes.fromhex('{}559000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x55)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnpd')
        assert_equal(myDisasm.repr(), 'vandnpd ymm26, ymm31, ymmword ptr [r8+00000000h]')

        # EVEX.NDS.512.66.0F.W1 55 /r
        # VandnpD zmm1 {k1}{z}, zmm2, zmm3/m512/m64bcst

        myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
        Buffer = bytes.fromhex('{}559000000000'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x55)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vandnpd')
        assert_equal(myDisasm.repr(), 'vandnpd zmm26, zmm31, zmmword ptr [r8+00000000h]')
