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


        # NP 0F 2A /r
        # CVTPI2PS xmm, mm/m64

        Buffer = bytes.fromhex('0f2a20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtpi2ps')
        assert_equal(myDisasm.repr(), 'cvtpi2ps xmm4, qword ptr [rax]')

        # 66 0F 2A /r
        # CVTPI2PD xmm, mm/m64*

        Buffer = bytes.fromhex('660f2a20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtpi2pd')
        assert_equal(myDisasm.repr(), 'cvtpi2pd xmm4, qword ptr [rax]')

        # F3 0F 2A /r
        # CVTSI2SS xmm1, r/m32

        Buffer = bytes.fromhex('f30f2a20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtsi2ss')
        assert_equal(myDisasm.repr(), 'cvtsi2ss xmm4, dword ptr [rax]')

        # F3 REX.W 0F 2A /r
        # CVTSI2SS xmm1, r/m64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0f2a20'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtsi2ss')
        assert_equal(myDisasm.repr(), 'cvtsi2ss xmm4, qword ptr [rax]')

        # VEX.NDS.LIG.F3.0F.W0 2A /r
        # VCVTSI2SS xmm1, xmm2, r/m32

        myVEX = VEX('VEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}2a10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2ss')
        assert_equal(myDisasm.repr(), 'vcvtsi2ss xmm10, xmm15, dword ptr [r8]')

        # VEX.NDS.LIG.F3.0F.W1 2A /r
        # VCVTSI2SS xmm1, xmm2, r/m64

        myVEX = VEX('VEX.NDS.LIG.F3.0F.W1')
        Buffer = bytes.fromhex('{}2a10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Reserved_.REX.W_, 1)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2ss')
        assert_equal(myDisasm.repr(), 'vcvtsi2ss xmm10, xmm15, qword ptr [r8]')

        # EVEX.NDS.LIG.F3.0F.W0 2A /r
        # VCVTSI2SS xmm1, xmm2, r/m32{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}2a16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2ss')
        assert_equal(myDisasm.repr(), 'vcvtsi2ss xmm26, xmm31, dword ptr [r14]')

        # EVEX.NDS.LIG.F3.0F.W1 2A /r
        # VCVTSI2SS xmm1, xmm2, r/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W1')
        Buffer = bytes.fromhex('{}2a16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2ss')
        assert_equal(myDisasm.repr(), 'vcvtsi2ss xmm26, xmm31, qword ptr [r14]')

        # F2 0F 2A /r
        # CVTSI2SD xmm1, r32/m32

        Buffer = bytes.fromhex('f20f2a20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtsi2sd')
        assert_equal(myDisasm.repr(), 'cvtsi2sd xmm4, dword ptr [rax]')

        # F2 REX.W 0F 2A /r
        # CVTSI2SD xmm1, r/m64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f2{:02x}0f2a20'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvtsi2sd')
        assert_equal(myDisasm.repr(), 'cvtsi2sd xmm4, qword ptr [rax]')

        # VEX.NDS.LIG.F2.0F.W0 2A /r
        # VCVTSI2SD xmm1, xmm2, r/m32

        myVEX = VEX('VEX.NDS.LIG.F2.0F.W0')
        Buffer = bytes.fromhex('{}2a10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2sd')
        assert_equal(myDisasm.repr(), 'vcvtsi2sd xmm10, xmm15, dword ptr [r8]')

        # VEX.NDS.LIG.F2.0F.W1 2A /r
        # VCVTSI2SD xmm1, xmm2, r/m64

        myVEX = VEX('VEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}2a10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2sd')
        assert_equal(myDisasm.repr(), 'vcvtsi2sd xmm10, xmm15, qword ptr [r8]')

        # EVEX.NDS.LIG.F2.0F.W0 2A /r
        # VCVTSI2SD xmm1, xmm2, r/m32

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W0')
        Buffer = bytes.fromhex('{}2a16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2sd')
        assert_equal(myDisasm.repr(), 'vcvtsi2sd xmm26, xmm31, dword ptr [r14]')

        # EVEX.NDS.LIG.F2.0F.W1 2A /r
        # VCVTSI2SD xmm1, xmm2, r/m64{er}

        myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}2a16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2a)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvtsi2sd')
        assert_equal(myDisasm.repr(), 'vcvtsi2sd xmm26, xmm31, qword ptr [r14]')
