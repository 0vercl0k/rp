; *****************************************
;
;
;   Header for BeaEngine 5.x (nasm 64 bits)
;
;
; *****************************************

STRUC REX_Struct
    W_:      resb    1
    R_:      resb    1
    X_:      resb    1
    B_:      resb    1
    state:   resb    1
ENDSTRUC



STRUC PREFIXINFO
  Number:          resd   1
  NbUndefined:     resd   1
  LockPrefix:     resb    1
  OperandSize:     resb    1
  AddressSize:     resb    1
  RepnePrefix:     resb    1
  RepPrefix:       resb    1
  FSPrefix:        resb    1
  SSPrefix:        resb    1
  GSPrefix:        resb    1
  ESPrefix:        resb    1
  CSPrefix:        resb    1
  DSPrefix:        resb    1
  BranchTaken:     resb    1
  BranchNotTaken   resb    1
  REX:             resb    REX_Struct_size
				   resb    1 ; alignment
				   resb    1 ; alignment
ENDSTRUC



STRUC EFLStruct
    OF_:     resb    1 ;(bit 11)
    SF_:     resb    1 ;(bit 7)
    ZF_:     resb    1 ;(bit 6)
    AF_:     resb    1 ;(bit 4)
    PF_:     resb    1 ;(bit 2)
    CF_:     resb    1 ;(bit 0)
    TF_:     resb    1 ;(bit 8)
    IF_:     resb    1 ;(bit 9)
    DF_:     resb    1 ;(bit 10)
    NT_:     resb    1 ;(bit 14)
    RF_:     resb    1 ;(bit 16)
            resb    1 ; alignment
ENDSTRUC


STRUC  MEMORYTYPE
   BaseRegister:    resq   1
   IndexRegister:   resq   1
   Scale:           resd   1
   Displacement:    resq   1
ENDSTRUC

STRUC REGISTERTYPE
   type: resq 1
   gpr: resq 1
   mmx: resq 1
   xmm: resq 1
   ymm: resq 1
   zmm: resq 1
   special: resq 1
   cr: resq 1
   dr: resq 1
   mem_management: resq 1
   mpx: resq 1
   opmask: resq 1
   segment: resq 1
   fpu: resq 1
   tmm: resq 1
ENDSTRUC

STRUC INSTRTYPE
    Category:                resd   1
    Opcode:                  resd   1
    Mnemonic:                resb   24
    BranchType:              resd   1
    Flags:                   resb   EFLStruct_size
    AddrValue:               resq   1
    Immediat:                resq   1
    ImplicitModifiedRegs:    resb   REGISTERTYPE_size
    ImplicitUsedRegs:        resb   REGISTERTYPE_size
ENDSTRUC

STRUC OPTYPE
    OpMnemonic:     resb   24
    OpType:         resq   1
    OpSize:         resd   1
    OpPosition:     resd   1
    AccessMode:      resd   1
    Memory:          resb   MEMORYTYPE_size
    Registers:       resb   REGISTERTYPE_size
    SegmentReg:      resd   1
ENDSTRUC


; ************************************** Define structure
STRUC _Disasm
    EIP:             resq   1
    VirtualAddr:     resq   1
    SecurityBlock:   resd   1
    CompleteInstr:   resb   80
    Archi:           resd   1
    Options:         resq   1
    Instruction:     resb   INSTRTYPE_size
    Operand1:       resb   OPTYPE_size
    Operand2:       resb   OPTYPE_size
    Operand3:       resb   OPTYPE_size
    Operand4:       resb   OPTYPE_size
    Operand5:       resb   OPTYPE_size
    Operand6:       resb   OPTYPE_size
    Operand7:       resb   OPTYPE_size
    Operand8:       resb   OPTYPE_size
    Operand9:       resb   OPTYPE_size
    Prefix:          resb   PREFIXINFO_size
    Error:          resd   1
    Reserved_        resd   48
ENDSTRUC

	LowPosition		equ		0
	HighPosition	equ		1
  ESReg   equ 1
  DSReg   equ 2
  FSReg   equ 4h
  GSReg   equ 8h
  CSReg   equ 10h
  SSReg   equ 20h


 ; ********** Prefixes

    InvalidPrefix               equ 4
    InUsePrefix                 equ 1
    SuperfluousPrefix           equ 2
    NotUsedPrefix               equ 0
    MandatoryPrefix             equ 8

 ; ********** EFLAGS states

    TE_      equ 1   ; test
    MO_      equ 2   ; modify
    RE_      equ 4   ; reset
    SE_      equ 8   ; set
    UN_      equ 10h   ; undefined
    PR_      equ 20h   ; restore prior value


; __________________________________________________________________________________________________________
;
;                                       INSTRUCTION_TYPE
; __________________________________________________________________________________________________________

    GENERAL_PURPOSE_INSTRUCTION   equ           10000h
    FPU_INSTRUCTION               equ           20000h
    MMX_INSTRUCTION               equ           30000h
    SSE_INSTRUCTION               equ           40000h
    SSE2_INSTRUCTION              equ           50000h
    SSE3_INSTRUCTION              equ           60000h
    SSSE3_INSTRUCTION             equ           70000h
    SSE41_INSTRUCTION             equ           80000h
    SSE42_INSTRUCTION             equ           90000h
    SYSTEM_INSTRUCTION            equ           a0000h
    VM_INSTRUCTION                equ           b0000h
    UNDOCUMENTED_INSTRUCTION      equ           c0000h
    AMD_INSTRUCTION               equ           d0000h
    ILLEGAL_INSTRUCTION           equ           e0000h
    AES_INSTRUCTION               equ           f0000h
    CLMUL_INSTRUCTION             equ          100000h
    AVX_INSTRUCTION               equ          110000h
    AVX2_INSTRUCTION              equ          120000h
    MPX_INSTRUCTION               equ          130000h
    AVX512_INSTRUCTION            equ          140000h
    SHA_INSTRUCTION               equ          150000h
    BMI2_INSTRUCTION              equ          160000h
    CET_INSTRUCTION               equ          170000h
    BMI1_INSTRUCTION              equ          180000h
    XSAVEOPT_INSTRUCTION          equ          190000h
    FSGSBASE_INSTRUCTION          equ          1a0000h
    CLWB_INSTRUCTION              equ          1b0000h
    CLFLUSHOPT_INSTRUCTION        equ          1c0000h
    FXSR_INSTRUCTION              equ          1d0000h
    XSAVE_INSTRUCTION             equ          1e0000h
    SGX_INSTRUCTION               equ          1f0000h
    PCONFIG_INSTRUCTION           equ          200000h
    UINTR_INSTRUCTION             equ          210000h
    KL_INSTRUCTION                equ          220000h
    AMX_INSTRUCTION               equ          230000h

    DATA_TRANSFER               equ 1
    ARITHMETIC_INSTRUCTION      equ 2
    LOGICAL_INSTRUCTION         equ 3
    SHIFT_ROTATE                equ 4
    BIT_BYTE                    equ 5
    CONTROL_TRANSFER            equ 6
    STRING_INSTRUCTION          equ 7
    InOutINSTRUCTION            equ 8
    ENTER_LEAVE_INSTRUCTION     equ 9
    FLAG_CONTROL_INSTRUCTION    equ 10
    SEGMENT_REGISTER            equ 11
    MISCELLANEOUS_INSTRUCTION   equ 12

    COMPARISON_INSTRUCTION      equ 13
    LOGARITHMIC_INSTRUCTION     equ 14
    TRIGONOMETRIC_INSTRUCTION   equ 15
    UNSUPPORTED_INSTRUCTION     equ 16

    LOAD_CONSTANTS              equ 17
    FPUCONTROL                  equ 18
    STATE_MANAGEMENT            equ 19

    CONVERSION_INSTRUCTION      equ 20

    SHUFFLE_UNPACK              equ 21
    PACKED_SINGLE_PRECISION     equ 22
    SIMD128bits                 equ 23
    SIMD64bits                  equ 24
    CACHEABILITY_CONTROL        equ 25

    FP_INTEGER_CONVERSION       equ 26
    SPECIALIZED_128bits         equ 27
    SIMD_FP_PACKED              equ 28
    SIMD_FP_HORIZONTAL          equ 29
    AGENT_SYNCHRONISATION       equ 30

    PACKED_ALIGN_RIGHT          equ 31
    PACKED_SIGN                 equ 32

    ; ****************************************** SSE4

    PACKED_BLENDING_INSTRUCTION equ 33
    PACKED_TEST                 equ 34

    ; CONVERSION_INSTRUCTION -> Packed Integer Format Conversions et Dword Packing With Unsigned Saturation
    ; COMPARISON -> Packed Comparison SIMD Integer Instruction
    ; ARITHMETIC_INSTRUCTION -> Dword Multiply Instruction
    ; DATA_TRANSFER -> POPCNT

    PACKED_MINMAX               equ 35
    HORIZONTAL_SEARCH           equ 36
    PACKED_EQUALITY             equ 37
    STREAMING_LOAD              equ 38
    INSERTION_EXTRACTION        equ 39
    DOT_PRODUCT                 equ 40
    SAD_INSTRUCTION             equ 41
    ACCELERATOR_INSTRUCTION     equ 42
    ROUND_INSTRUCTION           equ 43

; __________________________________________________________________________________________________________
;
;                                       BranchTYPE
; __________________________________________________________________________________________________________

    Jo_                         equ 1
    Jno_                        equ -1
    Jc_                         equ 2
    Jnc_                        equ -2
    Je_                         equ 3
    Jne_                        equ -3
    Ja_                         equ 4
    Jna_                        equ -4
    Js_                         equ 5
    Jns_                        equ -5
    Jp_                         equ 6
    Jnp_                        equ -6
    Jl_                         equ 7
    Jnl_                        equ -7
    Jg_                         equ 8
    Jng_                        equ -8
    Jb_                         equ 2
    Jnb_                        equ -2
    Jecxz_                      equ 10
    JmpType                     equ 11
    CallType                    equ 12
    RetType                     equ 13

; __________________________________________________________________________________________________________
;
;                                       ARGUMENTS_TYPE
; __________________________________________________________________________________________________________

    NO_ARGUMENT                 equ 10000h
    REGISTER_TYPE               equ 20000h
    MEMORY_TYPE                 equ 30000h
    CONSTANT_TYPE               equ 40000h

    GENERAL_REG                 equ 1h
    MMX_REG                     equ 2h
    SSE_REG                     equ 4h
    AVX_REG                     equ 8h
    AVX512_REG                  equ 10h
    SPECIAL_REG                 equ 20h       ; MXCSR (REG1)
    CR_REG                      equ 40h
    DR_REG                      equ 80h
    MEMORY_MANAGEMENT_REG       equ 100h      ; GDTR (REG0), LDTR (REG1), IDTR (REG2), TR (REG3)
    MPX_REG                     equ 200h
    OPMASK_REG                  equ 400h
    SEGMENT_REG                 equ 800h      ; ES (REG0), CS (REG1), SS (REG2), DS (REG3), FS (REG4), GS (REG5)
    FPU_REG                     equ 1000h
    TMM_REG                     equ 2000h

    RELATIVE_                   equ 04000000h
    ABSOLUTE_                   equ 08000000h

    READ                        equ 1
    WRITE                       equ 2
    ; ************ Regs

    REG0                        equ 1   ; 30h
    REG1                        equ 2   ; 31h
    REG2                        equ 4   ; 32h
    REG3                        equ 8   ; 33h
    REG4                        equ 10h ; 34h
    REG5                        equ 20h ; 35h
    REG6                        equ 40h ; 36h
    REG7                        equ 80h ; 37h
    REG8                        equ 100h; 38h
    REG9                        equ 200h; 39h
    REG10                       equ 400h    ; 3Ah
    REG11                       equ 800h    ; 3Bh
    REG12                       equ 1000h   ; 3Ch
    REG13                       equ 2000h   ; 3Dh
    REG14                       equ 4000h   ; 3Eh
    REG15                       equ 8000h   ; 3Fh
    REG16                       equ 10000h
    REG17                       equ 20000h
    REG18                       equ 40000h
    REG19                       equ 80000h
    REG20                       equ 100000h
    REG21                       equ 200000h
    REG22                       equ 400000h
    REG23                       equ 800000h
    REG24                       equ 1000000h
    REG25                       equ 2000000h
    REG26                       equ 4000000h
    REG27                       equ 8000000h
    REG28                       equ 10000000h
    REG29                       equ 20000000h
    REG30                       equ 40000000h
    REG31                       equ 80000000h

    ; ************ SPECIAL_REG

    UNKNOWN_OPCODE              equ -1
    OUT_OF_BLOCK                equ -2
    NoTabulation                equ 0
    Tabulation                  equ 1
    MasmSyntax                  equ 0
    GoAsmSyntax                 equ 100h
    NasmSyntax                  equ 200h
    ATSyntax                    equ 400h
    IntrinsicMemSyntax          equ 800h
    PrefixedNumeral             equ 10000h
    SuffixedNumeral             equ 0
    ShowSegmentRegs             equ 01000000h
    ShowEVEXMasking             equ 02000000h
