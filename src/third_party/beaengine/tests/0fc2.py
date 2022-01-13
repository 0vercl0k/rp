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

        compare = [
            'eq', 'lt', 'le', 'unord', 'neq', 'nlt', 'nle', 'ord',
            "eq_uq", "nge", "ngt", "false", "neq_oq",  "ge", "gt",
            "true", "eq_os", "lt_oq", "le_oq", "unord_s", "neq_us",
            "nlt_uq", "nle_uq", "ord_s", "eq_us", "nge_uq", "ngt_uq",
            "false_os", "neq_os", "ge_oq", "gt_oq", "true_us"
        ]

        # 66 0F C2 /r ib
        # CMPPD xmm1, xmm2/m128, imm8

        for i in range(0,8):
            Buffer = bytes.fromhex('660fc220{:02x}'.format(i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc2')
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'cmp{}pd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'cmp{}pd xmm4, xmmword ptr [rax], {:02x}h'.format(compare[i], i))

        # VEX.NDS.128.66.0F.WIG C2 /r ib
        # VCMPPD xmm1, xmm2, xmm3/m128, imm8

        for i in range(0,0x20):
            myVEX = VEX('VEX.NDS.128.66.0F.WIG')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myVEX.c4(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}pd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}pd xmm12, xmm15, xmmword ptr [r8], {:02X}h'.format(compare[i], i))


        # VEX.NDS.256.66.0F.WIG C2 /r ib
        # VCMPPD ymm1, ymm2, ymm3/m256, imm8

        for i in range(0,0x20):
            myVEX = VEX('VEX.NDS.256.66.0F.WIG')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myVEX.c4(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}pd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}pd ymm12, ymm15, ymmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.128.66.0F.W1 C2 /r ib
        # VCMPPD k1 {k2}, xmm2, xmm3/m128/m64bcst, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.128.66.0F.W1')
            myEVEX.R = 0
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}pd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}pd k?, xmm31, xmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.256.66.0F.W1 C2 /r ib
        # VCMPPD k1 {k2}, ymm2, ymm3/m256/m64bcst, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.256.66.0F.W1')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}pd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}pd k?, ymm31, ymmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.512.66.0F.W1 C2 /r ib
        # VCMPPD k1 {k2}, zmm2, zmm3/m512/m64bcst{sae}, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.512.66.0F.W1')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}pd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}pd k?, zmm31, zmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # NP 0F C2 /r ib
        # CMPPS xmm1, xmm2/m128, imm8

        for i in range(0,8):
            Buffer = bytes.fromhex('0fc220{:02x}'.format(i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc2')
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'cmp{}ps'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'cmp{}ps xmm4, xmmword ptr [rax], {:02x}h'.format(compare[i], i))

        # VEX.NDS.128.0F.WIG C2 /r ib
        # VCMPPS xmm1, xmm2, xmm3/m128, imm8

        for i in range(0,0x20):
            myVEX = VEX('VEX.NDS.128.0F.WIG')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myVEX.c4(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ps'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ps xmm12, xmm15, xmmword ptr [r8], {:02X}h'.format(compare[i], i))


        # VEX.NDS.256.0F.WIG C2 /r ib
        # VCMPPS ymm1, ymm2, ymm3/m256, imm8

        for i in range(0,0x20):
            myVEX = VEX('VEX.NDS.256.0F.WIG')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myVEX.c4(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ps'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ps ymm12, ymm15, ymmword ptr [r8], {:02X}h'.format(compare[i], i))


        # EVEX.NDS.128.0F.W0 C2 /r ib
        # VCMPPS k1 {k2}, xmm2, xmm3/m128/m32bcst, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.128.0F.W0')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ps'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ps k?, xmm31, xmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.256.0F.W0 C2 /r ib
        # VCMPPS k1 {k2}, ymm2, ymm3/m256/m32bcst, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.256.0F.W0')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ps'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ps k?, ymm31, ymmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.512.0F.W0 C2 /r ib
        # VCMPPS k1 {k2}, zmm2, zmm3/m512/m32bcst{sae}, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.512.0F.W0')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ps'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ps k?, zmm31, zmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # F2 0F C2 /r ib
        # CMPSD xmm1, xmm2/m64, imm8

        for i in range(0,8):
            Buffer = bytes.fromhex('f20fc220{:02x}'.format(i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc2')
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'cmp{}sd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'cmp{}sd xmm4, qword ptr [rax], {:02x}h'.format(compare[i], i))


        # VEX.NDS.LIG.F2.0F.WIG C2 /r ib
        # VCMPSD xmm1, xmm2, xmm3/m64, imm8

        for i in range(0,0x20):
            myVEX = VEX('VEX.NDS.LIG.F2.0F.WIG')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myVEX.c4(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}sd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}sd xmm12, xmm15, xmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.LIG.F2.0F.W1 C2 /r ib
        # VCMPSD k1 {k2}, xmm2, xmm3/m64{sae}, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.LIG.F2.0F.W1')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}sd'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}sd k?, xmm31, xmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # F3 0F C2 /r ib
        # CMPSS xmm1, xmm2/m32, imm8

        for i in range(0,8):
            Buffer = bytes.fromhex('f30fc220{:02x}'.format(i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(hex(myDisasm.infos.Instruction.Opcode), '0xfc2')
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'cmp{}ss'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'cmp{}ss xmm4, dword ptr [rax], {:02x}h'.format(compare[i], i))

        # VEX.NDS.LIG.F3.0F.WIG C2 /r ib
        # VCMPSS xmm1, xmm2, xmm3/m32, imm8

        for i in range(0,0x20):
            myVEX = VEX('VEX.NDS.LIG.F3.0F.WIG')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myVEX.c4(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ss'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ss xmm12, xmm15, xmmword ptr [r8], {:02X}h'.format(compare[i], i))

        # EVEX.NDS.LIG.F3.0F.W0 C2 /r ib
        # VCMPSS k1 {k2}, xmm2, xmm3/m32{sae}, imm8

        for i in range(0,0x20):
            myEVEX = EVEX('EVEX.NDS.LIG.F3.0F.W0')
            Buffer = bytes.fromhex('{}c220{:02x}'.format(myEVEX.prefix(), i))
            myDisasm = Disasm(Buffer)
            myDisasm.read()
            assert_equal(myDisasm.infos.Instruction.Opcode, 0xc2)
            assert_equal(myDisasm.infos.Instruction.Mnemonic, 'vcmp{}ss'.format(compare[i]).encode())
            assert_equal(myDisasm.repr(), 'vcmp{}ss k?, xmm31, xmmword ptr [r8], {:02X}h'.format(compare[i], i))
