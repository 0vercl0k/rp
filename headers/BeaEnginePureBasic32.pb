;- Simple Test BeaEngine 32-Bit, no Prototypes
;- "Helle" Klaus Helbing, 04.01.2010

;Header for BeaEngine 5.x (PureBasic 32 bits)

Structure REX_Struct
  W_.b
  R_.b
  X_.b
  B_.b
  state.b
EndStructure
Global Rex_Struct.REX_Struct

Structure PREFIXINFO
  Number.l
  NbUndefined.l
  LockPrefix.b
  OperandSize.b
  AddressSize.b
  RepnePrefix.b
  RepPrefix.b
  FSPrefix.b
  SSPrefix.b
  GSPrefix.b
  ESPrefix.b
  CSPrefix.b
  DSPrefix.b
  BranchTaken.b
  BranchNotTaken.b
  REX.REX_Struct
  AL1_.b                      ;alignment
  AL2_.b                      ;alignment
EndStructure
Global Prefixinfo.PREFIXINFO

Structure EFLStruct
  OF_.b                      ;(bit 11)
  SF_.b                      ;(bit 7)
  ZF_.b                      ;(bit 6)
  AF_.b                      ;(bit 4)
  PF_.b                      ;(bit 2)
  CF_.b                      ;(bit 0)
  TF_.b                      ;(bit 8)
  IF_.b                      ;(bit 9)
  DF_.b                      ;(bit 10)
  NT_.b                      ;(bit 14)
  RF_.b                      ;(bit 16)
  AL_.b                      ;alignment
EndStructure
Global Eflstruct.EFLStruct

Structure MEMORYTYPE
  BaseRegister.q
  IndexRegister.q
  Scale.l
  Displacement.q
EndStructure
Global Memorytype.MEMORYTYPE

Structure REGISTERTYPE
   type.q
   gpr.q
   mmx.q
   xmm.q
   ymm.q
   zmm.q
   special.q
   cr.q
   dr.q
   mem_management.q
   mpx.q
   opmask.q
   segment.q
   fpu.q
   tmm.q
EndStructure
Global Registertype.REGISTERTYPE

Structure INSTRTYPE
  Category.l
  Opcode.l
  Mnemonic.b[24]
  BranchType.l
  Flags.EFLStruct
  AddrValue.q
  Immediat.q
  ImplicitModifiedRegs.REGISTERTYPE
  ImplicitUsedRegs.REGISTERTYPE
EndStructure
Global Instrtype.INSTRTYPE

Structure OPTYPE
  OpMnemonic.b[24]
  OpType.q
  OpSize.l
  OpPosition.l
  AccessMode.l
  Memory.MEMORYTYPE
  Registers.REGISTERTYPE
  SegmentReg.l
EndStructure
Global Argtype.OPTYPE

Structure _Disasm
  EIP.l
  VirtualAddr.q
  SecurityBlock.l
  CompleteInstr.b[80]
  Archi.l
  Options.q
  Instruction.INSTRTYPE
  Operand1.OPTYPE
  Operand2.OPTYPE
  Operand3.OPTYPE
  Operand4.OPTYPE
  Operand5.OPTYPE
  Operand6.OPTYPE
  Operand7.OPTYPE
  Operand8.OPTYPE
  Operand9.OPTYPE
  Prefix.PREFIXINFO
  Error.l
  Reserved_.l[48]
EndStructure
Global MyDisasm._Disasm

#LowPosition = 0
#HighPosition = 1

#ESReg = $1
#DSReg = $2
#FSReg = $4
#GSReg = $8
#CSReg = $10
#SSReg = $20

; ********** Prefixes
#InvalidPrefix      = 4
#InUsePrefix        = 1
#SuperfluousPrefix  = 2
#NotUsedPrefix      = 0
#MandatoryPrefix    = 8

; ********** EFLAGS states
#TE_ = 1                     ;test
#MO_ = 2                     ;modify
#RE_ = 4                     ;reset
#SE_ = 8                     ;set
#UN_ = 16                    ;undefined
#PR_ = 32                    ;restore prior value

; __________________________________________________________________________________________________________
;
;                                       INSTRUCTION_TYPE
; __________________________________________________________________________________________________________

#GENERAL_PURPOSE_INSTRUCTION   =           $10000
#FPU_INSTRUCTION               =           $20000
#MMX_INSTRUCTION               =           $30000
#SSE_INSTRUCTION               =           $40000
#SSE2_INSTRUCTION              =           $50000
#SSE3_INSTRUCTION              =           $60000
#SSSE3_INSTRUCTION             =           $70000
#SSE41_INSTRUCTION             =           $80000
#SSE42_INSTRUCTION             =           $90000
#SYSTEM_INSTRUCTION            =           $a0000
#VM_INSTRUCTION                =           $b0000
#UNDOCUMENTED_INSTRUCTION      =           $c0000
#AMD_INSTRUCTION               =           $d0000
#ILLEGAL_INSTRUCTION           =           $e0000
#AES_INSTRUCTION               =           $f0000
#CLMUL_INSTRUCTION             =          $100000
#AVX_INSTRUCTION               =          $110000
#AVX2_INSTRUCTION              =          $120000
#MPX_INSTRUCTION               =          $130000
#AVX512_INSTRUCTION            =          $140000
#SHA_INSTRUCTION               =          $150000
#BMI2_INSTRUCTION              =          $160000
#CET_INSTRUCTION               =          $170000
#BMI1_INSTRUCTION              =          $180000
#XSAVEOPT_INSTRUCTION          =          $190000
#FSGSBASE_INSTRUCTION          =          $1a0000
#CLWB_INSTRUCTION              =          $1b0000
#CLFLUSHOPT_INSTRUCTION        =          $1c0000
#FXSR_INSTRUCTION              =          $1d0000
#XSAVE_INSTRUCTION             =          $1e0000
#SGX_INSTRUCTION               =          $1f0000
#PCONFIG_INSTRUCTION           =          $200000
#UINTR_INSTRUCTION             =          $210000
#KL_INSTRUCTION                =          $220000
#AMX_INSTRUCTION               =          $230000

#DATA_TRANSFER               = 1
#ARITHMETIC_INSTRUCTION      = 2
#LOGICAL_INSTRUCTION         = 3
#SHIFT_ROTATE                = 4
#BIT_BYTE                    = 5
#CONTROL_TRANSFER            = 6
#STRING_INSTRUCTION          = 7
#InOutINSTRUCTION            = 8
#ENTER_LEAVE_INSTRUCTION     = 9
#FLAG_CONTROL_INSTRUCTION    = 10
#SEGMENT_REGISTER            = 11
#MISCELLANEOUS_INSTRUCTION   = 12

#COMPARISON_INSTRUCTION      = 13
#LOGARITHMIC_INSTRUCTION     = 14
#TRIGONOMETRIC_INSTRUCTION   = 15
#UNSUPPORTED_INSTRUCTION     = 16

#LOAD_CONSTANTS              = 17
#FPUCONTROL                  = 18
#STATE_MANAGEMENT            = 19

#CONVERSION_INSTRUCTION      = 20

#SHUFFLE_UNPACK              = 21
#PACKED_SINGLE_PRECISION     = 22
#SIMD128bits                 = 23
#SIMD64bits                  = 24
#CACHEABILITY_CONTROL        = 25

#FP_INTEGER_CONVERSION       = 26
#SPECIALIZED_128bits         = 27
#SIMD_FP_PACKED              = 28
#SIMD_FP_HORIZONTAL          = 29
#AGENT_SYNCHRONISATION       = 30

#PACKED_ALIGN_RIGHT          = 31
#PACKED_SIGN                 = 32

; ****************************************** SSE4

#PACKED_BLENDING_INSTRUCTION = 33
#PACKED_TEST                 = 34

; CONVERSION_INSTRUCTION -> Packed Integer Format Conversions et Dword Packing With Unsigned Saturation
; COMPARISON -> Packed Comparison SIMD Integer Instruction
; ARITHMETIC_INSTRUCTION -> Dword Multiply Instruction
; DATA_TRANSFER -> POPCNT

#PACKED_MINMAX               = 35
#HORIZONTAL_SEARCH           = 36
#PACKED_EQUALITY             = 37
#STREAMING_LOAD              = 38
#INSERTION_EXTRACTION        = 39
#DOT_PRODUCT                 = 40
#SAD_INSTRUCTION             = 41
#ACCELERATOR_INSTRUCTION     = 42
#ROUND_INSTRUCTION           = 43

; __________________________________________________________________________________________________________
;
;                                       BranchTYPE
; __________________________________________________________________________________________________________

#Jo_                         = 1
#Jno_                        = -1
#Jc_                         = 2
#Jnc_                        = -2
#Je_                         = 3
#Jne_                        = -3
#Ja_                         = 4
#Jna_                        = -4
#Js_                         = 5
#Jns_                        = -5
#Jp_                         = 6
#Jnp_                        = -6
#Jl_                         = 7
#Jnl_                        = -7
#Jg_                         = 8
#Jng_                        = -8
#Jb_                         = 2
#Jnb_                        = -2
#Jecxz_                      = 10
#JmpType                     = 11
#CallType                    = 12
#RetType                     = 13

; __________________________________________________________________________________________________________
;
;                                       ARGUMENTS_TYPE
; __________________________________________________________________________________________________________

#NO_ARGUMENT                 = $10000
#REGISTER_TYPE               = $20000
#MEMORY_TYPE                 = $30000
#CONSTANT_TYPE               = $40000


#GENERAL_REG                 = $1
#MMX_REG                     = $2
#SSE_REG                     = $4
#AVX_REG                     = $8
#AVX512_REG                  = $10
#SPECIAL_REG                 = $20       ; MXCSR (REG1)
#CR_REG                      = $40
#DR_REG                      = $80
#MEMORY_MANAGEMENT_REG       = $100      ; GDTR (REG0), LDTR (REG1), IDTR (REG2), TR (REG3)
#MPX_REG                     = $200
#OPMASK_REG                  = $400
#SEGMENT_REG                 = $800      ; ES (REG0), CS (REG1), SS (REG2), DS (REG3), FS (REG4), GS (REG5)
#FPU_REG                     = $1000
#TMM_REG                     = $2000


#RELATIVE_                   = $04000000
#ABSOLUTE_                   = $08000000

#Read                        = 1
#WRITE                       = 2
; ************ Regs
#REG0                        = 1   ; 30h
#REG1                        = 2   ; 31h
#REG2                        = 4   ; 32h
#REG3                        = 8   ; 33h
#REG4                        = $10 ; 34h
#REG5                        = $20 ; 35h
#REG6                        = $40 ; 36h
#REG7                        = $80 ; 37h
#REG8                        = $100; 38h
#REG9                        = $200; 39h
#REG10                       = $400    ; 3Ah
#REG11                       = $800    ; 3Bh
#REG12                       = $1000   ; 3Ch
#REG13                       = $2000   ; 3Dh
#REG14                       = $4000   ; 3Eh
#REG15                       = $8000   ; 3Fh
#REG16 = $10000
#REG17 = $20000
#REG18 = $40000
#REG19 = $80000
#REG20 = $100000
#REG21 = $200000
#REG22 = $400000
#REG23 = $800000
#REG24 = $1000000
#REG25 = $2000000
#REG26 = $4000000
#REG27 = $8000000
#REG28 = $10000000
#REG29 = $20000000
#REG30 = $40000000
#REG31 = $80000000

; ************ SPECIAL_REG
#UNKNOWN_OPCODE              = -1
#OUT_OF_BLOCK                = -2
#NoTabulation                = 0
#Tabulation                  = 1
#MasmSyntax                  = 0
#GoAsmSyntax                 = $100
#NasmSyntax                  = $200
#ATSyntax                    = $400
#IntrinsicMemSyntax          = $800
#PrefixedNumeral             = $10000
#SuffixedNumeral             = 0
#ShowSegmentRegs             = $01000000
#ShowEVEXMasking             = $02000000
;------- End Header
