// ====================================================================
//
//  Delphi Static lib for BeaEngine 5.x
//
//  upDate: 2010-Jan-9
//  v0.4 support Delphi7 - Delphi2010
// ====================================================================
//  BeaEngine.pas convert by Vince
// ====================================================================
// [+] BranchTaken,BranchNotTaken added in TPREFIXINFO v3.1.0
unit BeaEngineDelphi64;
// ====================================================================
// Default link type is static lib
// comment below line to switch link with DLL
// ====================================================================
//{$DEFINE USEDLL}
// ====================================================================
// Copyright 2006-2020, BeatriX
// File coded by BeatriX
//
// This file is part of BeaEngine.
//
//    BeaEngine is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    BeaEngine is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with BeaEngine.  If not, see <http://www.gnu.org/licenses/>.

interface

uses Windows,SysUtils;

  const
     INSTRUCT_LENGTH = 80;


  type

     TREX_Struct = packed record
          W_ : BYTE;
          R_ : BYTE;
          X_ : BYTE;
          B_ : BYTE;
          state : BYTE;
       end;

  type

     TPREFIXINFO = packed record
          Number : longint;
          NbUndefined : longint;
          LockPrefix : BYTE;
          OperandSize : BYTE;
          AddressSize : BYTE;
          RepnePrefix : BYTE;
          RepPrefix : BYTE;
          FSPrefix : BYTE;
          SSPrefix : BYTE;
          GSPrefix : BYTE;
          ESPrefix : BYTE;
          CSPrefix : BYTE;
          DSPrefix : BYTE;
          BranchTaken : BYTE;     //v3.1.0 added 2009-11-05
          BranchNotTaken : BYTE;  //v3.1.0 added 2009-11-05
          REX : TREX_Struct;
		  alignment : array[0..1] of AnsiChar;
       end;

  type

     TEFLStruct = packed record
          OF_ : BYTE;
          SF_ : BYTE;
          ZF_ : BYTE;
          AF_ : BYTE;
          PF_ : BYTE;
          CF_ : BYTE;
          TF_ : BYTE;
          IF_ : BYTE;
          DF_ : BYTE;
          NT_ : BYTE;
          RF_ : BYTE;
          alignment : BYTE;
       end;

  type

     TMEMORYTYPE = packed record
          BaseRegister : int64;
          IndexRegister : int64;
          Scale : longint;
          Displacement : int64;
       end;

  type

     TREGISTERTYPE = packed record
          type : int64;
          gpr : int64;
          mmx : int64;
          xmm : int64;
          ymm : int64;
          zmm : int64;
          special : int64;
          cr : int64;
          dr : int64;
          mem_management : int64;
          mpx : int64;
          opmask : int64;
          segment : int64;
          fpu : int64;
          tmm : int64;

       end;


  type

     TINSTRTYPE = packed record
          Category : longint;
          Opcode : longint;
          Mnemonic : array[0..23] of AnsiChar;
          BranchType : longint;
          Flags : TEFLStruct;
          AddrValue : int64;
          Immediat : int64;
          ImplicitModifiedRegs : TREGISTERTYPE;
          ImplicitUsedRegs : TREGISTERTYPE;
       end;

  type

     TOPTYPE = packed record
          OpMnemonic : array[0..23] of AnsiChar;
          OpType : int64;
          OpSize : longint;
          OpPosition : longint;
          AccessMode : longint;
          Memory : TMEMORYTYPE;
          Registers : TREGISTERTYPE;
          SegmentReg : longint;
       end;

  type

     _Disasm = packed record
          EIP : int64;
          VirtualAddr : int64;
          SecurityBlock : longint;
          CompleteInstr : array[0..(INSTRUCT_LENGTH)-1] of AnsiChar;
          Archi : longint;
          Options : int64;
          Instruction : TINSTRTYPE;
          Operand1 : TOPTYPE;
          Operand2 : TOPTYPE;
          Operand3 : TOPTYPE;
          Operand4 : TOPTYPE;
          Operand5 : TOPTYPE;
          Operand6 : TOPTYPE;
          Operand7 : TOPTYPE;
          Operand8 : TOPTYPE;
          Operand9 : TOPTYPE;
          Prefix : TPREFIXINFO;
          Error : longint;
          Reserved_ : array[0..48] of longint;
       end;
     TDISASM = _Disasm;
     PDISASM = ^_Disasm;
     LPDISASM = ^_Disasm;

  const
      ESReg = 0x1;
      DSReg = 0x2;
      FSReg = 0x4;
      GSReg = 0x8;
      CSReg = 0x10;
      SSReg = 0x20;
      InvalidPrefix = 4;
      SuperfluousPrefix = 2;
      NotUsedPrefix = 0;
      MandatoryPrefix = 8;
      InUsePrefix = 1;


  type
     INSTRUCTION_TYPE =  Longint;
     Const
       GENERAL_PURPOSE_INSTRUCTION   =           $10000;
       FPU_INSTRUCTION               =           $20000;
       MMX_INSTRUCTION               =           $30000;
       SSE_INSTRUCTION               =           $40000;
       SSE2_INSTRUCTION              =           $50000;
       SSE3_INSTRUCTION              =           $60000;
       SSSE3_INSTRUCTION             =           $70000;
       SSE41_INSTRUCTION             =           $80000;
       SSE42_INSTRUCTION             =           $90000;
       SYSTEM_INSTRUCTION            =           $a0000;
       VM_INSTRUCTION                =           $b0000;
       UNDOCUMENTED_INSTRUCTION      =           $c0000;
       AMD_INSTRUCTION               =           $d0000;
       ILLEGAL_INSTRUCTION           =           $e0000;
       AES_INSTRUCTION               =           $f0000;
       CLMUL_INSTRUCTION             =          $100000;
       AVX_INSTRUCTION               =          $110000;
       AVX2_INSTRUCTION              =          $120000;
       MPX_INSTRUCTION               =          $130000;
       AVX512_INSTRUCTION            =          $140000;
       SHA_INSTRUCTION               =          $150000;
       BMI2_INSTRUCTION              =          $160000;
       CET_INSTRUCTION               =          $170000;
       BMI1_INSTRUCTION              =          $180000;
       XSAVEOPT_INSTRUCTION          =          $190000;
       FSGSBASE_INSTRUCTION          =          $1a0000;
       CLWB_INSTRUCTION              =          $1b0000;
       CLFLUSHOPT_INSTRUCTION        =          $1c0000;
       FXSR_INSTRUCTION              =          $1d0000;
       XSAVE_INSTRUCTION             =          $1e0000;
       SGX_INSTRUCTION               =          $1f0000;
       PCONFIG_INSTRUCTION           =          $200000;
       UINTR_INSTRUCTION             =          $210000;
       KL_INSTRUCTION                =          $220000;
       AMX_INSTRUCTION               =          $230000;
       DATA_TRANSFER = $1;
       ARITHMETIC_INSTRUCTION = 2;
       LOGICAL_INSTRUCTION = 3;
       SHIFT_ROTATE = 4;
       BIT_BYTE = 5;
       CONTROL_TRANSFER = 6;
       STRING_INSTRUCTION = 7;
       InOutINSTRUCTION = 8;
       ENTER_LEAVE_INSTRUCTION = 9;
       FLAG_CONTROL_INSTRUCTION = 10;
       SEGMENT_REGISTER = 11;
       MISCELLANEOUS_INSTRUCTION = 12;
       COMPARISON_INSTRUCTION = 13;
       LOGARITHMIC_INSTRUCTION = 14;
       TRIGONOMETRIC_INSTRUCTION = 15;
       UNSUPPORTED_INSTRUCTION = 16;
       LOAD_CONSTANTS = 17;
       FPUCONTROL = 18;
       STATE_MANAGEMENT = 19;
       CONVERSION_INSTRUCTION = 20;
       SHUFFLE_UNPACK = 21;
       PACKED_SINGLE_PRECISION = 22;
       SIMD128bits = 23;
       SIMD64bits = 24;
       CACHEABILITY_CONTROL = 25;
       FP_INTEGER_CONVERSION = 26;
       SPECIALIZED_128bits = 27;
       SIMD_FP_PACKED = 28;
       SIMD_FP_HORIZONTAL = 29;
       AGENT_SYNCHRONISATION = 30;
       PACKED_ALIGN_RIGHT = 31;
       PACKED_SIGN = 32;
       PACKED_BLENDING_INSTRUCTION = 33;
       PACKED_TEST = 34;
       PACKED_MINMAX = 35;
       HORIZONTAL_SEARCH = 36;
       PACKED_EQUALITY = 37;
       STREAMING_LOAD = 38;
       INSERTION_EXTRACTION = 39;
       DOT_PRODUCT = 40;
       SAD_INSTRUCTION = 41;
       ACCELERATOR_INSTRUCTION = 42; //   crc32, popcnt (sse4.2)
       ROUND_INSTRUCTION = 43;


  type
     EFLAGS_STATES =  Longint;
     Const
       TE_ = 1;
       MO_ = 2;
       RE_ = 4;
       SE_ = 8;
       UN_ = $10;
       PR_ = $20;


  type
     BRANCH_TYPE =  Longint;
     Const
       JO = 1;
       JC = 2;
       JE = 3;
       JA = 4;
       JS = 5;
       JP = 6;
       JL = 7;
       JG = 8;
       JB = 2;
       JECXZ = 10;
       JmpType = 11;
       CallType = 12;
       RetType = 13;
       JNO = -(1);
       JNC = -(2);
       JNE = -(3);
       JNA = -(4);
       JNS = -(5);
       JNP = -(6);
       JNL = -(7);
       JNG = -(8);
       JNB = -(2);


  type
     ARGUMENTS_TYPE =  Longint;
     Const
       NO_ARGUMENT = $10000;
       REGISTER_TYPE = $20000;
       MEMORY_TYPE = $30000;
       CONSTANT_TYPE = $40000;

       GENERAL_REG =               $1;
       MMX_REG =                   $2;
       SSE_REG =                   $4;
       AVX_REG =                   $8;
       AVX512_REG =                $10;
       SPECIAL_REG =               $20;
       CR_REG =                    $40;
       DR_REG =                    $80;
       MEMORY_MANAGEMENT_REG =     $100;
       MPX_REG =                   $200;
       OPMASK_REG =                $400;
       SEGMENT_REG =               $800;
       FPU_REG =                   $1000;
       TMM_REG =                   $2000;

       RELATIVE_ = $4000000;
       ABSOLUTE_ = $8000000;

       READ = $1;
       WRITE = $2;

       REG0 = $1;
       REG1 = $2;
       REG2 = $4;
       REG3 = $8;
       REG4 = $10;
       REG5 = $20;
       REG6 = $40;
       REG7 = $80;
       REG8 = $100;
       REG9 = $200;
       REG10 = $400;
       REG11 = $800;
       REG12 = $1000;
       REG13 = $2000;
       REG14 = $4000;
       REG15 = $8000;
       REG16 = $10000;
       REG17 = $20000;
       REG18 = $40000;
       REG19 = $80000;
       REG20 = $100000;
       REG21 = $200000;
       REG22 = $400000;
       REG23 = $800000;
       REG24 = $1000000;
       REG25 = $2000000;
       REG26 = $4000000;
       REG27 = $8000000;
       REG28 = $10000000;
       REG29 = $20000000;
       REG30 = $40000000;
       REG31 = $80000000;

  type
     SPECIAL_INFO =  Longint;
     Const
       UNKNOWN_OPCODE = -(1);
       OUT_OF_BLOCK = -(2);
  { === mask = 0xff }
       NoTabulation = $00000000;
       Tabulation = $00000001;
  { === mask = 0xff00 }
       MasmSyntax = $00000000;
       GoAsmSyntax = $00000100;
       NasmSyntax = $00000200;
       ATSyntax = $00000400;
       IntrinsicMemSyntax = $00000800;
  { === mask = 0xff0000 }
       PrefixedNumeral = $00010000;
       SuffixedNumeral = $00000000;
  { === mask = 0xff000000 }
       ShowSegmentRegs = $01000000;
       ShowEVEXMasking = $02000000;
	   LowPosition = 0;
	   HighPosition = 1;


  function Disasm(var aDisAsm:TDISASM):longint;stdcall;


implementation
{$IFNDEF USEDLL}
{$L BeaEngineLib.obj}
{$ENDIF}

function _strcpy(dest, src: PAnsiChar): PAnsiChar;cdecl;
begin
  Result := SysUtils.StrCopy(dest, src);
end;

function _strlen(s: PAnsiChar): Cardinal; cdecl;
begin
  Result := SysUtils.StrLen(s);
end;

function _memset(Destination: Pointer; C: Integer; Count: Cardinal): Pointer; cdecl;
begin
  FillMemory(Destination, Count, C);
  Result := Destination;
end;

function _sprintf(Buffer, Format: PAnsiChar):longint; varargs;  cdecl; external 'User32.DLL' name 'wsprintfA';

{$IFDEF USEDLL}
function Disasm(var aDisAsm:TDISASM):longint;stdcall;external 'BeaEngine.DLL' index 3;
function BeaEngineVersion:longint;stdcall;external 'BeaEngine.DLL' index 2;
function BeaEngineRevision:longint;stdcall;external 'BeaEngine.DLL' index 1;
{$ELSE}
function _Disasm(var aDisAsm:TDISASM):longint;stdcall;external;
function _BeaEngineVersion:longint;stdcall;external;
function _BeaEngineRevision:longint;stdcall;external;
function Disasm(var aDisAsm:TDISASM):longint;stdcall;
begin
result := _Disasm(aDisAsm);
end;
function BeaEngineVersion:longint;stdcall;
begin
result := _BeaEngineVersion;
end;
function BeaEngineRevision:longint;stdcall;
begin
result := _BeaEngineRevision;
end;
{$ENDIF}

end.
