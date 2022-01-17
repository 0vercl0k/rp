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

        # tests from
        # Axel Tillequin @bdcht
        # Rump SSTIC 2014

        # 0F 58 /r
        # ADDPS xmm1, xmm2/m128

        Buffer = bytes.fromhex('0f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addps')
        assert_equal(myDisasm.repr(), 'addps xmm6, xmmword ptr [rax]')


        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('f20f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm6, qword ptr [rax]')
        assert_equal(myDisasm.infos.Operand2.OpSize, 64)

        # F3 0F 58 /r
        # ADDSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('f30f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addss')
        assert_equal(myDisasm.repr(), 'addss xmm6, dword ptr [rax]')


        # 66 0F 58 /r
        # ADDPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('660f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addpd')
        assert_equal(myDisasm.repr(), 'addpd xmm6, xmmword ptr [rax]')
        assert_equal(myDisasm.infos.Operand2.OpSize, 128)

        # 66 0F 58 /r
        # ADDPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('66670f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addpd')
        assert_equal(myDisasm.repr(), 'addpd xmm6, xmmword ptr [eax]')

        # 66 0F 58 /r
        # ADDPD xmm1, xmm2/m128

        Buffer = bytes.fromhex('662e0f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addpd')
        assert_equal(myDisasm.repr(), 'addpd xmm6, xmmword ptr [rax]')

        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('f2670f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm6, qword ptr [eax]')

        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('f2660f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm6, qword ptr [rax]')

        # F3 0F 58 /r
        # ADDSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('f3660f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addss')
        assert_equal(myDisasm.repr(), 'addss xmm6, dword ptr [rax]')

        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('66f20f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm6, qword ptr [rax]')

        # F3 0F 58 /r
        # ADDSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('66f30f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addss')
        assert_equal(myDisasm.repr(), 'addss xmm6, dword ptr [rax]')


        # F3 0F 58 /r
        # ADDSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('f2f30f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addss')
        assert_equal(myDisasm.repr(), 'addss xmm6, dword ptr [rax]')

        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('f3f20f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm6, qword ptr [rax]')

        # F3 0F 58 /r
        # ADDSS xmm1, xmm2/m32

        Buffer = bytes.fromhex('f2f3660f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addss')
        assert_equal(myDisasm.repr(), 'addss xmm6, dword ptr [rax]')

        # F2 0F 58 /r
        # ADDSD xmm1, xmm2/m64

        Buffer = bytes.fromhex('f3f2660f5830')
        myDisasm = Disasm(Buffer)
        myDisasm.read()
        assert_equal(myDisasm.infos.Instruction.Opcode, 0x0f58)
        assert_equal(myDisasm.infos.Instruction.Mnemonic, b'addsd')
        assert_equal(myDisasm.repr(), 'addsd xmm6, qword ptr [rax]')
