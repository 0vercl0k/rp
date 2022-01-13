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

        # 66 0F 2C /r
        # CVTTPD2PI mm, xmm/m128

        Buffer = bytes.fromhex('660f2c20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttpd2pi')
        assert_equal(myDisasm.repr(), 'cvttpd2pi mm4, xmmword ptr [rax]')

        # NP 0F 2C /r
        # CVTTPS2PI mm, xmm/m64

        Buffer = bytes.fromhex('0f2c20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttps2pi')
        assert_equal(myDisasm.repr(), 'cvttps2pi mm4, qword ptr [rax]')

        # F2 0F 2C /r
        # CVTTSD2SI r32, xmm1/m64

        Buffer = bytes.fromhex('f20f2c20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttsd2si')
        assert_equal(myDisasm.repr(), 'cvttsd2si esp, qword ptr [rax]')

        Buffer = bytes.fromhex('f20f2ce0')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttsd2si')
        assert_equal(myDisasm.repr(), 'cvttsd2si esp, xmm0')


        # F2 REX.W 0F 2C /r
        # CVTTSD2SI r64, xmm1/m64

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f2{:02x}0f2c20'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttsd2si')
        assert_equal(myDisasm.repr(), 'cvttsd2si rsp, qword ptr [rax]')

        # VEX.LIG.F2.0F.W0 2C /r 1
        # VCVTTSD2SI r32, xmm1/m64

        myVEX = VEX('VEX.LIG.F2.0F.W0')
        Buffer = bytes.fromhex('{}2c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttsd2si')
        assert_equal(myDisasm.repr(), 'vcvttsd2si r10d, qword ptr [r8]')

        # VEX.LIG.F2.0F.W1 2C /r 1
        # VCVTTSD2SI r64, xmm1/m64

        myVEX = VEX('VEX.LIG.F2.0F.W1')
        Buffer = bytes.fromhex('{}2c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttsd2si')
        assert_equal(myDisasm.repr(), 'vcvttsd2si r10, qword ptr [r8]')

        # EVEX.LIG.F2.0F.W0 2C /r
        # VCVTTSD2SI r32, xmm1/m64{sae}

        myEVEX = EVEX('EVEX.LIG.F2.0F.W0')
        myEVEX.Rprime = 1
        myEVEX.R = 0
        Buffer = bytes.fromhex('{}2c16'.format(myEVEX.prefix()))
        #Buffer = '62017f002c16')
        myDisasm = Disasm(Buffer)
        myDisasm.read()

        assert_equal(myEVEX.p0(), 17)
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttsd2si')
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, 0)
        assert_equal(myDisasm.infos.Reserved_.REGOPCODE, 10)
        assert_equal(myDisasm.infos.Reserved_.REX.R_, 1)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P0, 17)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P1, 0x7f)
        assert_equal(myDisasm.infos.Reserved_.EVEX.P2, 0)
        assert_equal(myDisasm.infos.Reserved_.EVEX.R1, 0)
        assert_equal(myDisasm.infos.Operand1.OpSize, 32)
        assert_equal(myDisasm.infos.Operand1.OpType, REGISTER_TYPE)
        assert_equal(myDisasm.infos.Operand1.OpMnemonic, b"r10d")
        assert_equal(myDisasm.infos.Operand1.Registers.type, GENERAL_REG)
        assert_equal(myDisasm.infos.Operand1.Registers.cr, 0)
        assert_equal(myDisasm.infos.Operand1.Registers.gpr, REG10)
        assert_equal(myDisasm.repr(), 'vcvttsd2si r10d, qword ptr [r14]')

        # EVEX.LIG.F2.0F.W1 2C /r
        # VCVTTSD2SI r64, xmm1/m64{sae}

        myEVEX = EVEX('EVEX.LIG.F2.0F.W1')
        myEVEX.Rprime = 1
        myEVEX.R = 1
        Buffer = bytes.fromhex('{}2c16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttsd2si')
        assert_equal(myDisasm.repr(), 'vcvttsd2si rdx, qword ptr [r14]')

        # F3 0F 2C /r
        # CVTTSS2SI r32, xmm1/m32

        Buffer = bytes.fromhex('f30f2c20')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttss2si')
        assert_equal(myDisasm.repr(), 'cvttss2si esp, dword ptr [rax]')

        # F3 REX.W 0F 2C /r
        # CVTTSS2SI r64, xmm1/m32

        myREX = REX()
        myREX.W = 1
        Buffer = bytes.fromhex('f3{:02x}0f2c20'.format(myREX.byte()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0xf2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'cvttss2si')
        assert_equal(myDisasm.repr(), 'cvttss2si rsp, dword ptr [rax]')

        # VEX.LIG.F3.0F.W0 2C /r 1
        # VCVTTSS2SI r32, xmm1/m32

        myVEX = VEX('VEX.LIG.F3.0F.W0')
        Buffer = bytes.fromhex('{}2c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttss2si')
        assert_equal(myDisasm.repr(), 'vcvttss2si r10d, dword ptr [r8]')

        # VEX.LIG.F3.0F.W1 2C /r 1
        # VCVTTSS2SI r64, xmm1/m32

        myVEX = VEX('VEX.LIG.F3.0F.W1')
        Buffer = bytes.fromhex('{}2c10'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttss2si')
        assert_equal(myDisasm.repr(), 'vcvttss2si r10, dword ptr [r8]')

        # EVEX.LIG.F3.0F.W0 2C /r
        # VCVTTSS2SI r32, xmm1/m32{sae}

        myEVEX = EVEX('EVEX.LIG.F3.0F.W0')
        myEVEX.Rprime = 1
        myEVEX.R = 0
        Buffer = bytes.fromhex('{}2c16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttss2si')
        assert_equal(myDisasm.repr(), 'vcvttss2si r10d, dword ptr [r14]')

        # EVEX.LIG.F3.0F.W1 2C /r
        # VCVTTSS2SI r64, xmm1/m32{sae}

        myEVEX = EVEX('EVEX.LIG.F3.0F.W1')
        myEVEX.Rprime = 1
        myEVEX.R = 0
        Buffer = bytes.fromhex('{}2c16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'vcvttss2si')
        assert_equal(myDisasm.repr(), 'vcvttss2si r10, dword ptr [r14]')

        # VEX.vvvv and EVEX.vvvv are reserved and must be 1111b, otherwise instructions will #UD.

        myEVEX = EVEX('EVEX.LIG.F2.0F.W0')
        myEVEX.vvvv = 0b1000
        Buffer = bytes.fromhex('{}2c16'.format(myEVEX.prefix()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)

        myVEX = VEX('VEX.LIG.F2.0F.W0')
        myVEX.vvvv = 0b1000
        Buffer = bytes.fromhex('{}2c16'.format(myVEX.c4()))
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x2c)
        assert_equal(myDisasm.infos.Reserved_.ERROR_OPCODE, UD_)
