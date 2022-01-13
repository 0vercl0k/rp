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

    def verifyRegopcodeForMod(self, MOD, registers, instr, archi):

        for REGOPCODE in range(0, 8):
            for RM in range(0, 8):
                MODRM = (MOD << 6) + (REGOPCODE << 3) + RM
                Buffer = bytes.fromhex(instr.format(MODRM))
                myDisasm = Disasm(Buffer)
                myDisasm.infos.Archi = archi
                myDisasm.read()
                #print(myDisasm.repr())
                #print(myDisasm.infos.Reserved_.Register_)
                assert_equal(myDisasm.infos.Operand2.OpMnemonic, registers[REGOPCODE].encode())

    def verifyRegopcodeArg1ForMod(self, MOD, registers, instr, archi):

        for REGOPCODE in range(0, 8):
            for RM in range(0, 8):
                MODRM = (MOD << 6) + (REGOPCODE << 3) + RM
                Buffer = bytes.fromhex(instr.format(MODRM))
                myDisasm = Disasm(Buffer)
                myDisasm.infos.Archi = archi
                myDisasm.read()
                print(myDisasm.repr())
                assert_equal(myDisasm.infos.Operand1.OpMnemonic, registers[REGOPCODE].encode())

    def test_RegOpcode(self):

        # bndcl GvEv

        archi = 64
        registers = ['bnd0', 'bnd1', 'bnd2', 'bnd3', 'bnd4?', 'bnd5?', 'bnd6?', 'bnd7?']
        for mod in range(0, 3):
            self.verifyRegopcodeArg1ForMod(mod, registers, 'f30f1a{:02x}', archi)

        # mov EvGv

        archi = 64
        registers = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '89{:02x}', archi)

        registers = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '6689{:02x}', archi)

        archi = 32
        registers = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '89{:02x}', archi)

        registers = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '6689{:02x}', archi)

        archi = 16
        registers = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '89{:02x}', archi)

        registers = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '6689{:02x}', archi)

        # mov EbGb

        archi = 64
        registers = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '88{:02x}', archi)

        registers = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '6688{:02x}', archi)

        # movapd ExGx

        archi = 64
        regs = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, regs, '660f29{:02x}', archi)

        # movntq ExGx

        regs = ['mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, regs, '0fe7{:02x}', archi)

    def test_RegOpcode_VEX(self):

        # vaddpd GxEx

        archi = 64
        regs = ['ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15']
        for mod in range(0, 3):
            self.verifyRegopcodeArg1ForMod(mod, regs, 'c4010558{:02x}', archi)

        regs = ['ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7']
        for mod in range(0, 3):
            self.verifyRegopcodeArg1ForMod(mod, regs, 'c4e10558{:02x}', archi)

    def test_RegOpcode_REX(self):

        # movapd ExGx

        archi = 64
        regs = ['xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, regs, '66440f29{:02x}', archi)

        # mov EvGv

        archi = 64
        registers = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '4089{:02x}', archi)

        regs = ['r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, regs, '4489{:02x}', archi)

        registers = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '4989{:02x}', archi)

        registers = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '4c89{:02x}', archi)

        registers = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '664089{:02x}', archi)

        regs = ['r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, regs, '664489{:02x}', archi)

        # mov EbGb

        registers = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, registers, '4088{:02x}', archi)

        regs = ['r8L', 'r9L', 'r10L', 'r11L', 'r12L', 'r13L', 'r14L', 'r15L']
        for mod in range(0, 3):
            self.verifyRegopcodeForMod(mod, regs, '4488{:02x}', archi)

# @TODO ZMM registers
# @TODO FPU
# @TODO DR & CR registers
# @TODO Vector SIB Memory Addressing
