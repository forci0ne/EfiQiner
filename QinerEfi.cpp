////////// Settings \\\\\\\\\\

#define NUMBER_OF_MINING_PROCESSORS 1
#define AVX512 0
#define NUMBER_OF_NEURONS 19000
#define PORT 21841
#define SOLUTION_THRESHOLD 28
#define VERSION_A 1
#define VERSION_B 74
#define VERSION_C 0

static unsigned char miningSeeds[][55 + 1] = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

static const unsigned char ownAddress[4] = { 0, 0, 0, 0 };
static const unsigned char ownMask[4] = { 255, 255, 255, 0 };
static const unsigned char defaultRouteAddress[4] = { 0, 0, 0, 0 };
static const unsigned char defaultRouteMask[4] = { 0, 0, 0, 0 };
static const unsigned char defaultRouteGateway[4] = { 0, 0, 0, 0 };
static const unsigned char ownPublicAddress[4] = { 0, 0, 0, 0 };

static const unsigned char knownPublicPeers[][4] = {

    {},

};

////////// UEFI \\\\\\\\\\

#define FALSE ((BOOLEAN)0)
#define IN
#define OPTIONAL
#define OUT
#define TRUE ((BOOLEAN)1)

#define EFI_SUCCESS 0
#define EFI_LOAD_ERROR (1 | 0x8000000000000000)
#define EFI_INVALID_PARAMETER (2 | 0x8000000000000000)
#define EFI_UNSUPPORTED (3 | 0x8000000000000000)
#define EFI_BAD_BUFFER_SIZE (4 | 0x8000000000000000)
#define EFI_BUFFER_TOO_SMALL (5 | 0x8000000000000000)
#define EFI_NOT_READY (6 | 0x8000000000000000)
#define EFI_DEVICE_ERROR (7 | 0x8000000000000000)
#define EFI_WRITE_PROTECTED (8 | 0x8000000000000000)
#define EFI_OUT_OF_RESOURCES (9 | 0x8000000000000000)
#define EFI_VOLUME_CORRUPTED (10 | 0x8000000000000000)
#define EFI_VOLUME_FULL (11 | 0x8000000000000000)
#define EFI_NO_MEDIA (12 | 0x8000000000000000)
#define EFI_MEDIA_CHANGED (13 | 0x8000000000000000)
#define EFI_NOT_FOUND (14 | 0x8000000000000000)
#define EFI_ACCESS_DENIED (15 | 0x8000000000000000)
#define EFI_NO_RESPONSE (16 | 0x8000000000000000)
#define EFI_NO_MAPPING (17 | 0x8000000000000000)
#define EFI_TIMEOUT (18 | 0x8000000000000000)
#define EFI_NOT_STARTED (19 | 0x8000000000000000)
#define EFI_ALREADY_STARTED (20 | 0x8000000000000000)
#define EFI_ABORTED (21 | 0x8000000000000000)
#define EFI_ICMP_ERROR (22 | 0x8000000000000000)
#define EFI_TFTP_ERROR (23 | 0x8000000000000000)
#define EFI_PROTOCOL_ERROR (24 | 0x8000000000000000)
#define EFI_INCOMPATIBLE_VERSION (25 | 0x8000000000000000)
#define EFI_SECURITY_VIOLATION (26 | 0x8000000000000000)
#define EFI_CRC_ERROR (27 | 0x8000000000000000)
#define EFI_END_OF_MEDIA (28 | 0x8000000000000000)
#define EFI_END_OF_FILE (31 | 0x8000000000000000)
#define EFI_INVALID_LANGUAGE (32 | 0x8000000000000000)
#define EFI_COMPROMISED_DATA (33 | 0x8000000000000000)
#define EFI_IP_ADDRESS_CONFLICT (34 | 0x8000000000000000)
#define EFI_HTTP_ERROR (35 | 0x8000000000000000)
#define EFI_NETWORK_UNREACHABLE (100 | 0x8000000000000000)
#define EFI_HOST_UNREACHABLE (101 | 0x8000000000000000)
#define EFI_PROTOCOL_UNREACHABLE (102 | 0x8000000000000000)
#define EFI_PORT_UNREACHABLE (103 | 0x8000000000000000)
#define EFI_CONNECTION_FIN (104 | 0x8000000000000000)
#define EFI_CONNECTION_RESET (105 | 0x8000000000000000)
#define EFI_CONNECTION_REFUSED (106 | 0x8000000000000000)

#define EFI_DEBUG_SUPPORT_PROTOCOL_GUID {0x2755590C, 0x6F3C, 0x42FA, {0x9E, 0xA4, 0xA3, 0xBA, 0x54, 0x3C, 0xDA, 0x25}}
#define EFI_FILE_SYSTEM_INFO_ID {0x09576e93, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID {0x9042a9de, 0x23dc, 0x4a38, {0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a}}
#define EFI_MP_SERVICES_PROTOCOL_GUID {0x3fdda605, 0xa76e, 0x4f46, {0xad, 0x29, 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08}}
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID {0x0964e5b22, 0x6459, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
#define EFI_TCP4_PROTOCOL_GUID {0x65530BC7, 0xA359, 0x410f, {0xB0, 0x10, 0x5A, 0xAD, 0xC7, 0xEC, 0x2B, 0x62}}
#define EFI_TCP4_SERVICE_BINDING_PROTOCOL_GUID {0x00720665, 0x67EB, 0x4a99, {0xBA, 0xF7, 0xD3, 0xC3, 0x3A, 0x1C, 0x7C, 0xC9}}
#define EFI_UDP4_PROTOCOL_GUID {0x3ad9df29, 0x4501, 0x478d, {0xb1, 0xf8, 0x7f, 0x7f, 0xe7, 0x0e, 0x50, 0xf3}}
#define EFI_UDP4_SERVICE_BINDING_PROTOCOL_GUID {0x83f01464, 0x99bd, 0x45e5, {0xb3, 0x83, 0xaf, 0x63, 0x05, 0xd8, 0xe9, 0xe6}}

#define EFI_FILE_MODE_READ 0x0000000000000001
#define EFI_FILE_MODE_WRITE 0x0000000000000002
#define EFI_FILE_MODE_CREATE 0x8000000000000000
#define EFI_FILE_READ_ONLY 0x0000000000000001
#define EFI_FILE_HIDDEN 0x0000000000000002
#define EFI_FILE_SYSTEM 0x0000000000000004
#define EFI_FILE_RESERVED 0x0000000000000008
#define EFI_FILE_DIRECTORY 0x0000000000000010
#define EFI_FILE_ARCHIVE 0x0000000000000020
#define EFI_FILE_VALID_ATTR 0x0000000000000037
#define EFI_FILE_PROTOCOL_REVISION 0x00010000
#define EFI_FILE_PROTOCOL_REVISION2 0x00020000
#define EFI_FILE_PROTOCOL_LATEST_REVISION EFI_FILE_PROTOCOL_REVISION2
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER 0x00000008
#define EFI_OPEN_PROTOCOL_BY_DRIVER 0x00000010
#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL 0x00000001
#define EFI_OPEN_PROTOCOL_EXCLUSIVE 0x00000020
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL 0x00000002
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL 0x00000004
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION 0x00010000
#define EFI_UNSPECIFIED_TIMEZONE 0x07FF
#define END_OF_CPU_LIST 0xFFFFFFFF
#define EVT_NOTIFY_SIGNAL 0x00000200
#define EVT_NOTIFY_WAIT 0x00000100
#define EVT_RUNTIME 0x40000000
#define EVT_SIGNAL_EXIT_BOOT_SERVICES 0x00000201
#define EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE 0x60000202
#define EVT_TIMER 0x80000000
#define EXCEPT_X64_DIVIDE_ERROR 0
#define MAX_MCAST_FILTER_CNT 16
#define PROCESSOR_AS_BSP_BIT 0x00000001
#define PROCESSOR_ENABLED_BIT 0x00000002
#define PROCESSOR_HEALTH_STATUS_BIT 0x00000004
#define TPL_APPLICATION 4
#define TPL_CALLBACK 8
#define TPL_HIGH_LEVEL 31
#define TPL_NOTIFY 16

typedef unsigned char BOOLEAN;
typedef unsigned short CHAR16;
typedef void* EFI_EVENT;
typedef void* EFI_HANDLE;
typedef unsigned long long EFI_PHYSICAL_ADDRESS;
typedef unsigned long long EFI_STATUS;
typedef unsigned long long EFI_TPL;
typedef unsigned long long EFI_VIRTUAL_ADDRESS;

typedef enum
{
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
    MaxAllocateType
} EFI_ALLOCATE_TYPE;

typedef enum
{
    EfiBltVideoFill,
    EfiBltVideoToBltBuffer,
    EfiBltBufferToVideo,
    EfiBltVideoToVideo,
    EfiGraphicsOutputBltOperationMax
} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;

typedef enum
{
    PixelRedGreenBlueReserved8BitPerColor,
    PixelBlueGreenRedReserved8BitPerColor,
    PixelBitMask,
    PixelBltOnly,
    PixelFormatMax
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef enum
{
    IsaIa32 = 0x014C,
    IsaX64 = 0x8664,
    IsaIpf = 0x0200,
    IsaEbc = 0x0EBC,
    IsaArm = 0x1C2,
    IsaAArch64 = 0xAA64,
    IsaRISCV32 = 0x5032,
    IsaRISCV64 = 0x5064,
    IsaRISCV128 = 0x5128
} EFI_INSTRUCTION_SET_ARCHITECTURE;

typedef enum
{
    EFI_NATIVE_INTERFACE
} EFI_INTERFACE_TYPE;

typedef enum
{
    AllHandles,
    ByRegisterNotify,
    ByProtocol
} EFI_LOCATE_SEARCH_TYPE;

typedef enum
{
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiUnacceptedMemoryType,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef enum
{
    EfiResetCold,
    EfiResetWarm,
    EfiResetShutdown,
    EfiResetPlatformSpecific
} EFI_RESET_TYPE;

typedef enum
{
    Tcp4StateClosed = 0,
    Tcp4StateListen = 1,
    Tcp4StateSynSent = 2,
    Tcp4StateSynReceived = 3,
    Tcp4StateEstablished = 4,
    Tcp4StateFinWait1 = 5,
    Tcp4StateFinWait2 = 6,
    Tcp4StateClosing = 7,
    Tcp4StateTimeWait = 8,
    Tcp4StateCloseWait = 9,
    Tcp4StateLastAck = 10
} EFI_TCP4_CONNECTION_STATE;

typedef enum
{
    TimerCancel,
    TimerPeriodic,
    TimerRelative
} EFI_TIMER_DELAY;

typedef struct
{
    unsigned long long R0, R1, R2, R3, R4, R5, R6, R7;
    unsigned long long Flags;
    unsigned long long ControlFlags;
    unsigned long long Ip;
} EFI_SYSTEM_CONTEXT_EBC;

typedef struct
{
    unsigned short Fcw;
    unsigned short Fsw;
    unsigned short Ftw;
    unsigned short Opcode;
    unsigned int Eip;
    unsigned short Cs;
    unsigned short Reserved1;
    unsigned int DataOffset;
    unsigned short Ds;
    unsigned char Reserved2[10];
    unsigned char St0Mm0[10], Reserved3[6];
    unsigned char St1Mm1[10], Reserved4[6];
    unsigned char St2Mm2[10], Reserved5[6];
    unsigned char St3Mm3[10], Reserved6[6];
    unsigned char St4Mm4[10], Reserved7[6];
    unsigned char St5Mm5[10], Reserved8[6];
    unsigned char St6Mm6[10], Reserved9[6];
    unsigned char St7Mm7[10], Reserved10[6];
    unsigned char Xmm0[16];
    unsigned char Xmm1[16];
    unsigned char Xmm2[16];
    unsigned char Xmm3[16];
    unsigned char Xmm4[16];
    unsigned char Xmm5[16];
    unsigned char Xmm6[16];
    unsigned char Xmm7[16];
    unsigned char Reserved11[14 * 16];
} EFI_FX_SAVE_STATE_IA32;

typedef struct
{
    unsigned int ExceptionData;
    EFI_FX_SAVE_STATE_IA32 FxSaveState;
    unsigned int Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    unsigned int Cr0, Cr1 /* Reserved */, Cr2, Cr3, Cr4;
    unsigned int Eflags;
    unsigned int Ldtr, Tr;
    unsigned int Gdtr[2], Idtr[2];
    unsigned int Eip;
    unsigned int Gs, Fs, Es, Ds, Cs, Ss;
    unsigned int Edi, Esi, Ebp, Esp, Ebx, Edx, Ecx, Eax;
} EFI_SYSTEM_CONTEXT_IA32;

typedef struct
{
    unsigned short Fcw;
    unsigned short Fsw;
    unsigned short Ftw;
    unsigned short Opcode;
    unsigned long long Rip;
    unsigned long long DataOffset;
    unsigned char Reserved1[8];
    unsigned char St0Mm0[10], Reserved2[6];
    unsigned char St1Mm1[10], Reserved3[6];
    unsigned char St2Mm2[10], Reserved4[6];
    unsigned char St3Mm3[10], Reserved5[6];
    unsigned char St4Mm4[10], Reserved6[6];
    unsigned char St5Mm5[10], Reserved7[6];
    unsigned char St6Mm6[10], Reserved8[6];
    unsigned char St7Mm7[10], Reserved9[6];
    unsigned char Xmm0[16];
    unsigned char Xmm1[16];
    unsigned char Xmm2[16];
    unsigned char Xmm3[16];
    unsigned char Xmm4[16];
    unsigned char Xmm5[16];
    unsigned char Xmm6[16];
    unsigned char Xmm7[16];
    unsigned char Reserved11[14 * 16];
} EFI_FX_SAVE_STATE_X64;

typedef struct
{
    unsigned long long ExceptionData;
    EFI_FX_SAVE_STATE_X64 FxSaveState;
    unsigned long long Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    unsigned long long Cr0, Cr1 /* Reserved */, Cr2, Cr3, Cr4, Cr8;
    unsigned long long Rflags;
    unsigned long long Ldtr, Tr;
    unsigned long long Gdtr[2], Idtr[2];
    unsigned long long Rip;
    unsigned long long Gs, Fs, Es, Ds, Cs, Ss;
    unsigned long long Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
    unsigned long long R8, R9, R10, R11, R12, R13, R14, R15;
} EFI_SYSTEM_CONTEXT_X64;

typedef struct
{
    unsigned long long Reserved;

    unsigned long long R1, R2, R3, R4, R5, R6, R7, R8, R9, R10,
        R11, R12, R13, R14, R15, R16, R17, R18, R19, R20,
        R21, R22, R23, R24, R25, R26, R27, R28, R29, R30,
        R31;

    unsigned long long F2[2], F3[2], F4[2], F5[2], F6[2],
        F7[2], F8[2], F9[2], F10[2], F11[2],
        F12[2], F13[2], F14[2], F15[2], F16[2],
        F17[2], F18[2], F19[2], F20[2], F21[2],
        F22[2], F23[2], F24[2], F25[2], F26[2],
        F27[2], F28[2], F29[2], F30[2], F31[2];

    unsigned long long Pr;

    unsigned long long B0, B1, B2, B3, B4, B5, B6, B7;

    // application registers
    unsigned long long ArRsc, ArBsp, ArBspstore, ArRnat;
    unsigned long long ArFcr;
    unsigned long long ArEflag, ArCsd, ArSsd, ArCflg;
    unsigned long long ArFsr, ArFir, ArFdr;
    unsigned long long ArCcv;
    unsigned long long ArUnat;
    unsigned long long ArFpsr;
    unsigned long long ArPfs, ArLc, ArEc;

    // control registers
    unsigned long long CrDcr, CrItm, CrIva, CrPta, CrIpsr, CrIsr;
    unsigned long long CrIip, CrIfa, CrItir, CrIipa, CrIfs, CrIim;
    unsigned long long CrIha;

    // debug registers
    unsigned long long Dbr0, Dbr1, Dbr2, Dbr3, Dbr4, Dbr5, Dbr6, Dbr7;
    unsigned long long Ibr0, Ibr1, Ibr2, Ibr3, Ibr4, Ibr5, Ibr6, Ibr7;

    // virtual registers
    unsigned long long IntNat; // nat bits for R1-R31

} EFI_SYSTEM_CONTEXT_IPF;

typedef struct
{
    unsigned int R0;
    unsigned int R1;
    unsigned int R2;
    unsigned int R3;
    unsigned int R4;
    unsigned int R5;
    unsigned int R6;
    unsigned int R7;
    unsigned int R8;
    unsigned int R9;
    unsigned int R10;
    unsigned int R11;
    unsigned int R12;
    unsigned int SP;
    unsigned int LR;
    unsigned int PC;
    unsigned int CPSR;
    unsigned int DFSR;
    unsigned int DFAR;
    unsigned int IFSR;
} EFI_SYSTEM_CONTEXT_ARM;

typedef struct
{
    // General Purpose Registers
    unsigned long long X0;
    unsigned long long X1;
    unsigned long long X2;
    unsigned long long X3;
    unsigned long long X4;
    unsigned long long X5;
    unsigned long long X6;
    unsigned long long X7;
    unsigned long long X8;
    unsigned long long X9;
    unsigned long long X10;
    unsigned long long X11;
    unsigned long long X12;
    unsigned long long X13;
    unsigned long long X14;
    unsigned long long X15;
    unsigned long long X16;
    unsigned long long X17;
    unsigned long long X18;
    unsigned long long X19;
    unsigned long long X20;
    unsigned long long X21;
    unsigned long long X22;
    unsigned long long X23;
    unsigned long long X24;
    unsigned long long X25;
    unsigned long long X26;
    unsigned long long X27;
    unsigned long long X28;
    unsigned long long FP; // x29 - Frame Pointer
    unsigned long long LR; // x30 - Link Register
    unsigned long long SP; // x31 - Stack Pointer
    // FP/SIMD Registers
    unsigned long long V0[2];
    unsigned long long V1[2];
    unsigned long long V2[2];
    unsigned long long V3[2];
    unsigned long long V4[2];
    unsigned long long V5[2];
    unsigned long long V6[2];
    unsigned long long V7[2];
    unsigned long long V8[2];
    unsigned long long V9[2];
    unsigned long long V10[2];
    unsigned long long V11[2];
    unsigned long long V12[2];
    unsigned long long V13[2];
    unsigned long long V14[2];
    unsigned long long V15[2];
    unsigned long long V16[2];
    unsigned long long V17[2];
    unsigned long long V18[2];
    unsigned long long V19[2];
    unsigned long long V20[2];
    unsigned long long V21[2];
    unsigned long long V22[2];
    unsigned long long V23[2];
    unsigned long long V24[2];
    unsigned long long V25[2];
    unsigned long long V26[2];
    unsigned long long V27[2];
    unsigned long long V28[2];
    unsigned long long V29[2];
    unsigned long long V30[2];
    unsigned long long V31[2];
    unsigned long long ELR; // Exception Link Register
    unsigned long long SPSR; // Saved Processor Status Register
    unsigned long long FPSR; // Floating Point Status Register
    unsigned long long ESR; // Exception syndrome register
    unsigned long long FAR; // Fault Address Register
} EFI_SYSTEM_CONTEXT_AARCH64;

typedef struct
{
    // Integer registers
    unsigned int Zero, Ra, Sp, Gp, Tp, T0, T1, T2;
    unsigned int S0FP, S1, A0, A1, A2, A3, A4, A5, A6, A7;
    unsigned int S2, S3, S4, S5, S6, S7, S8, S9, S10, S11;
    unsigned int T3, T4, T5, T6;
    // Floating registers for F, D and Q Standard Extensions
    __m128i Ft0, Ft1, Ft2, Ft3, Ft4, Ft5, Ft6, Ft7;
    __m128i Fs0, Fs1, Fa0, Fa1, Fa2, Fa3, Fa4, Fa5, Fa6, Fa7;
    __m128i Fs2, Fs3, Fs4, Fs5, Fs6, Fs7, Fs8, Fs9, Fs10, Fs11;
    __m128i Ft8, Ft9, Ft10, Ft11;
} EFI_SYSTEM_CONTEXT_RISCV32;

typedef struct
{
    // Integer registers
    unsigned long long Zero, Ra, Sp, Gp, Tp, T0, T1, T2;
    unsigned long long S0FP, S1, A0, A1, A2, A3, A4, A5, A6, A7;
    unsigned long long S2, S3, S4, S5, S6, S7, S8, S9, S10, S11;
    unsigned long long T3, T4, T5, T6;
    // Floating registers for F, D and Q Standard Extensions
    __m128i Ft0, Ft1, Ft2, Ft3, Ft4, Ft5, Ft6, Ft7;
    __m128i Fs0, Fs1, Fa0, Fa1, Fa2, Fa3, Fa4, Fa5, Fa6, Fa7;
    __m128i Fs2, Fs3, Fs4, Fs5, Fs6, Fs7, Fs8, Fs9, Fs10, Fs11;
    __m128i Ft8, Ft9, Ft10, Ft11;
} EFI_SYSTEM_CONTEXT_RISCV64;

typedef struct
{
    // Integer registers
    __m128i Zero, Ra, Sp, Gp, Tp, T0, T1, T2;
    __m128i S0FP, S1, A0, A1, A2, A3, A4, A5, A6, A7;
    __m128i S2, S3, S4, S5, S6, S7, S8, S9, S10, S11;
    __m128i T3, T4, T5, T6;
    // Floating registers for F, D and Q Standard Extensions
    __m128i Ft0, Ft1, Ft2, Ft3, Ft4, Ft5, Ft6, Ft7;
    __m128i Fs0, Fs1, Fa0, Fa1, Fa2, Fa3, Fa4, Fa5, Fa6, Fa7;
    __m128i Fs2, Fs3, Fs4, Fs5, Fs6, Fs7, Fs8, Fs9, Fs10, Fs11;
    __m128i Ft8, Ft9, Ft10, Ft11;
} EFI_SYSTEM_CONTEXT_RISCV128;

typedef union
{
    EFI_SYSTEM_CONTEXT_EBC* SystemContextEbc;
    EFI_SYSTEM_CONTEXT_IA32* SystemContextIa32;
    EFI_SYSTEM_CONTEXT_X64* SystemContextX64;
    EFI_SYSTEM_CONTEXT_IPF* SystemContextIpf;
    EFI_SYSTEM_CONTEXT_ARM* SystemContextArm;
    EFI_SYSTEM_CONTEXT_AARCH64* SystemContextAArch64;
    EFI_SYSTEM_CONTEXT_RISCV32* SystemContextRiscV32;
    EFI_SYSTEM_CONTEXT_RISCV64* SystemContextRiscV64;
    EFI_SYSTEM_CONTEXT_RISCV128* SystemContextRiscv128;
} EFI_SYSTEM_CONTEXT;

typedef struct
{
    unsigned int Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
} EFI_GUID;

typedef struct
{
    EFI_GUID CapsuleGuid;
    unsigned int HeaderSize;
    unsigned int Flags;
    unsigned int CapsuleImageSize;
} EFI_CAPSULE_HEADER;

typedef struct
{
    unsigned int Package;
    unsigned int Core;
    unsigned int Thread;
} EFI_CPU_PHYSICAL_LOCATION;

typedef struct
{
    unsigned char Type;
    unsigned char SubType;
    unsigned char Length[2];
} EFI_DEVICE_PATH_PROTOCOL;

typedef struct
{
    EFI_EVENT Event;
    EFI_STATUS Status;
    unsigned long long BufferSize;
    void* Buffer;
} EFI_FILE_IO_TOKEN;

typedef struct
{
    unsigned long long Size;
    BOOLEAN ReadOnly;
    unsigned long long VolumeSize;
    unsigned long long FreeSpace;
    unsigned int BlockSize;
    CHAR16 VolumeLabel[256];
} EFI_FILE_SYSTEM_INFO;

typedef struct
{
    unsigned char Blue;
    unsigned char Green;
    unsigned char Red;
    unsigned char Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

typedef struct
{
    unsigned int RedMask;
    unsigned int GreenMask;
    unsigned int BlueMask;
    unsigned int ReservedMask;
} EFI_PIXEL_BITMASK;

typedef struct
{
    unsigned int Version;
    unsigned int HorizontalResolution;
    unsigned int VerticalResolution;
    EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
    EFI_PIXEL_BITMASK PixelInformation;
    unsigned int PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct
{
    unsigned int MaxMode;
    unsigned int Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* Info;
    unsigned long long SizeOfInfo;
    EFI_PHYSICAL_ADDRESS FrameBufferBase;
    unsigned long long FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct
{
    unsigned short ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

typedef struct
{
    unsigned char Addr[4];
} EFI_IPv4_ADDRESS;

typedef struct
{
    unsigned char DefaultProtocol;
    BOOLEAN AcceptAnyProtocol;
    BOOLEAN AcceptIcmpErrors;
    BOOLEAN AcceptBroadcast;
    BOOLEAN AcceptPromiscuous;
    BOOLEAN UseDefaultAddress;
    EFI_IPv4_ADDRESS StationAddress;
    EFI_IPv4_ADDRESS SubnetMask;
    unsigned char TypeOfService;
    unsigned char TimeToLive;
    BOOLEAN DoNotFragment;
    BOOLEAN RawData;
    unsigned int ReceiveTimeout;
    unsigned int TransmitTimeout;
} EFI_IP4_CONFIG_DATA;

typedef struct
{
    unsigned char Type;
    unsigned char Code;
} EFI_IP4_ICMP_TYPE;

typedef struct
{
    EFI_IPv4_ADDRESS SubnetAddress;
    EFI_IPv4_ADDRESS SubnetMask;
    EFI_IPv4_ADDRESS GatewayAddress;
} EFI_IP4_ROUTE_TABLE;

typedef struct
{
    BOOLEAN IsStarted;
    unsigned int MaxPacketSize;
    EFI_IP4_CONFIG_DATA ConfigData;
    BOOLEAN IsConfigured;
    unsigned int GroupCount;
    EFI_IPv4_ADDRESS* GroupTable;
    unsigned int RouteCount;
    EFI_IP4_ROUTE_TABLE* RouteTable;
    unsigned int IcmpTypeCount;
    EFI_IP4_ICMP_TYPE* IcmpTypeList;
} EFI_IP4_MODE_DATA;

typedef struct
{
    unsigned char Addr[32];
} EFI_MAC_ADDRESS;

typedef struct
{
    unsigned int ReceivedQueueTimeoutValue;
    unsigned int TransmitQueueTimeoutValue;
    unsigned short ProtocolTypeFilter;
    BOOLEAN EnableUnicastReceive;
    BOOLEAN EnableMulticastReceive;
    BOOLEAN EnableBroadcastReceive;
    BOOLEAN EnablePromiscuousReceive;
    BOOLEAN FlushQueuesOnReset;
    BOOLEAN EnableReceiveTimestamps;
    BOOLEAN DisableBackgroundPolling;
} EFI_MANAGED_NETWORK_CONFIG_DATA;

typedef struct
{
    unsigned int Type;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    EFI_VIRTUAL_ADDRESS VirtualStart;
    unsigned long long NumberOfPages;
    unsigned long long Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct
{
    EFI_HANDLE AgentHandle;
    EFI_HANDLE ControllerHandle;
    unsigned int Attributes;
    unsigned int OpenCount;
} EFI_OPEN_PROTOCOL_INFORMATION_ENTRY;

typedef struct
{
    unsigned long long ProcessorId;
    unsigned int StatusFlag;
    EFI_CPU_PHYSICAL_LOCATION Location;
} EFI_PROCESSOR_INFORMATION;

typedef struct
{
    unsigned int State;
    unsigned int HwAddressSize;
    unsigned int MediaHeaderSize;
    unsigned int MaxPacketSize;
    unsigned int NvRamSize;
    unsigned int NvRamAccessSize;
    unsigned int ReceiveFilterMask;
    unsigned int ReceiveFilterSetting;
    unsigned int MaxMCastFilterCount;
    unsigned int MCastFilterCount;
    EFI_MAC_ADDRESS MCastFilter[MAX_MCAST_FILTER_CNT];
    EFI_MAC_ADDRESS CurrentAddress;
    EFI_MAC_ADDRESS BroadcastAddress;
    EFI_MAC_ADDRESS PermanentAddress;
    unsigned char IfType;
    BOOLEAN MacAddressChangeable;
    BOOLEAN MultipleTxSupported;
    BOOLEAN MediaPresentSupported;
    BOOLEAN MediaPresent;
} EFI_SIMPLE_NETWORK_MODE;

typedef struct
{
    unsigned long long Signature;
    unsigned int Revision;
    unsigned int HeaderSize;
    unsigned int CRC32;
    unsigned int Reserved;
} EFI_TABLE_HEADER;

typedef struct
{
    BOOLEAN UseDefaultAddress;
    EFI_IPv4_ADDRESS StationAddress;
    EFI_IPv4_ADDRESS SubnetMask;
    unsigned short StationPort;
    EFI_IPv4_ADDRESS RemoteAddress;
    unsigned short RemotePort;
    BOOLEAN ActiveFlag;
} EFI_TCP4_ACCESS_POINT;

typedef struct
{
    EFI_EVENT Event;
    EFI_STATUS Status;
} EFI_TCP4_COMPLETION_TOKEN;

typedef struct
{
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
    BOOLEAN AbortOnClose;
} EFI_TCP4_CLOSE_TOKEN;

typedef struct
{
    unsigned int ReceiveBufferSize;
    unsigned int SendBufferSize;
    unsigned int MaxSynBackLog;
    unsigned int ConnectionTimeout;
    unsigned int DataRetries;
    unsigned int FinTimeout;
    unsigned int TimeWaitTimeout;
    unsigned int KeepAliveProbes;
    unsigned int KeepAliveTime;
    unsigned int KeepAliveInterval;
    BOOLEAN EnableNagle;
    BOOLEAN EnableTimeStamp;
    BOOLEAN EnableWindowScaling;
    BOOLEAN EnableSelectiveAck;
    BOOLEAN EnablePathMtuDiscovery;
} EFI_TCP4_OPTION;

typedef struct
{
    unsigned char TypeOfService;
    unsigned char TimeToLive;
    EFI_TCP4_ACCESS_POINT AccessPoint;
    EFI_TCP4_OPTION* ControlOption;
} EFI_TCP4_CONFIG_DATA;

typedef struct
{
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
} EFI_TCP4_CONNECTION_TOKEN;

typedef struct
{
    unsigned int FragmentLength;
    void* FragmentBuffer;
} EFI_TCP4_FRAGMENT_DATA;

typedef struct
{
    BOOLEAN UrgentFlag;
    unsigned int DataLength;
    unsigned int FragmentCount;
    EFI_TCP4_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP4_RECEIVE_DATA;

typedef struct
{
    BOOLEAN Push;
    BOOLEAN Urgent;
    unsigned int DataLength;
    unsigned int FragmentCount;
    EFI_TCP4_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP4_TRANSMIT_DATA;

typedef struct
{
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
    union
    {
        EFI_TCP4_RECEIVE_DATA* RxData;
        EFI_TCP4_TRANSMIT_DATA* TxData;
    } Packet;
} EFI_TCP4_IO_TOKEN;

typedef struct
{
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
    EFI_HANDLE NewChildHandle;
} EFI_TCP4_LISTEN_TOKEN;

typedef struct
{
    unsigned short Year;
    unsigned char Month;
    unsigned char Day;
    unsigned char Hour;
    unsigned char Minute;
    unsigned char Second;
    unsigned char Pad1;
    unsigned int Nanosecond;
    short TimeZone;
    unsigned char Daylight;
    unsigned char Pad2;
} EFI_TIME;

typedef struct
{
    unsigned int Resolution;
    unsigned int Accuracy;
    BOOLEAN SetsToZero;
} EFI_TIME_CAPABILITIES;

typedef struct
{
    EFI_IPv4_ADDRESS SourceAddress;
    unsigned short SourcePort;
    EFI_IPv4_ADDRESS DestinationAddress;
    unsigned short DestinationPort;
} EFI_UDP4_SESSION_DATA;

typedef struct
{
    unsigned int FragmentLength;
    void* FragmentBuffer;
} EFI_UDP4_FRAGMENT_DATA;

typedef struct
{
    EFI_TIME TimeStamp;
    EFI_EVENT RecycleSignal;
    EFI_UDP4_SESSION_DATA UdpSession;
    unsigned int DataLength;
    unsigned int FragmentCount;
    EFI_UDP4_FRAGMENT_DATA FragmentTable[1];
} EFI_UDP4_RECEIVE_DATA;

typedef struct
{
    EFI_UDP4_SESSION_DATA* UdpSessionData;
    EFI_IPv4_ADDRESS* GatewayAddress;
    unsigned int DataLength;
    unsigned int FragmentCount;
    EFI_UDP4_FRAGMENT_DATA FragmentTable[1];
} EFI_UDP4_TRANSMIT_DATA;

typedef struct
{
    EFI_EVENT Event;
    EFI_STATUS Status;
    union
    {
        EFI_UDP4_RECEIVE_DATA* RxData;
        EFI_UDP4_TRANSMIT_DATA* TxData;
    } Packet;
} EFI_UDP4_COMPLETION_TOKEN;

typedef struct
{
    BOOLEAN AcceptBroadcast;
    BOOLEAN AcceptPromiscuous;
    BOOLEAN AcceptAnyPort;
    BOOLEAN AllowDuplicatePort;
    unsigned char TypeOfService;
    unsigned char TimeToLive;
    BOOLEAN DoNotFragment;
    unsigned int ReceiveTimeout;
    unsigned int TransmitTimeout;
    BOOLEAN UseDefaultAddress;
    EFI_IPv4_ADDRESS StationAddress;
    EFI_IPv4_ADDRESS SubnetMask;
    unsigned short StationPort;
    EFI_IPv4_ADDRESS RemoteAddress;
    unsigned short RemotePort;
} EFI_UDP4_CONFIG_DATA;

typedef struct
{
    int MaxMode;
    int Mode;
    int Attribute;
    int CursorColumn;
    int CursorRow;
    BOOLEAN CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef EFI_STATUS(__cdecl* EFI_ALLOCATE_PAGES) (IN EFI_ALLOCATE_TYPE Type, IN EFI_MEMORY_TYPE MemoryType, IN unsigned long long Pages, IN OUT EFI_PHYSICAL_ADDRESS* Memory);
typedef EFI_STATUS(__cdecl* EFI_ALLOCATE_POOL) (IN EFI_MEMORY_TYPE PoolType, IN unsigned long long Size, OUT void** Buffer);
typedef void(__cdecl* EFI_AP_PROCEDURE) (IN void* ProcedureArgument);
typedef EFI_STATUS(__cdecl* EFI_CALCULATE_CRC32) (IN void* Data, IN unsigned long long DataSize, OUT unsigned int* Crc32);
typedef EFI_STATUS(__cdecl* EFI_CHECK_EVENT) (IN EFI_EVENT Event);
typedef EFI_STATUS(__cdecl* EFI_CLOSE_EVENT) (IN EFI_EVENT Event);
typedef EFI_STATUS(__cdecl* EFI_CLOSE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID* Protocol, IN EFI_HANDLE AgentHandle, IN EFI_HANDLE ControllerHandle);
typedef EFI_STATUS(__cdecl* EFI_CONNECT_CONTROLLER) (IN EFI_HANDLE ControllerHandle, IN EFI_HANDLE* DriverImageHandle OPTIONAL, IN EFI_DEVICE_PATH_PROTOCOL* RemainingDevicePath OPTIONAL, IN BOOLEAN Recursive);
typedef EFI_STATUS(__cdecl* EFI_CONVERT_POINTER) (IN unsigned long long DebugDisposition, IN OUT void** Address);
typedef void(__cdecl* EFI_COPY_MEM) (IN void* Destination, IN void* Source, IN unsigned long long Length);
typedef EFI_STATUS(__cdecl* EFI_CREATE_EVENT) (IN unsigned int Type, IN EFI_TPL NotifyTpl, IN void* NotifyFunction, OPTIONAL IN void* NotifyContext, OPTIONAL OUT EFI_EVENT* Event);
typedef EFI_STATUS(__cdecl* EFI_CREATE_EVENT_EX) (IN unsigned int Type, IN EFI_TPL NotifyTpl, IN void* NotifyFunction OPTIONAL, IN const void* NotifyContext OPTIONAL, IN const EFI_GUID* EventGroup OPTIONAL, OUT EFI_EVENT* Event);
typedef EFI_STATUS(__cdecl* EFI_DISCONNECT_CONTROLLER) (IN EFI_HANDLE ControllerHandle, IN EFI_HANDLE DriverImageHandle OPTIONAL, IN EFI_HANDLE ChildHandle OPTIONAL);
typedef void(__cdecl* EFI_EVENT_NOTIFY) (IN EFI_EVENT Event, IN void* Context);
typedef void(*EFI_EXCEPTION_CALLBACK) (IN long long ExceptionType, IN OUT EFI_SYSTEM_CONTEXT SystemContext);
typedef EFI_STATUS(__cdecl* EFI_EXIT) (IN EFI_HANDLE ImageHandle, IN EFI_STATUS ExitStatus, IN unsigned long long ExitDataSize, IN CHAR16* ExitData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_EXIT_BOOT_SERVICES) (IN EFI_HANDLE ImageHandle, IN unsigned long long MapKey);
typedef EFI_STATUS(__cdecl* EFI_FILE_CLOSE) (IN void* This);
typedef EFI_STATUS(__cdecl* EFI_FILE_DELETE) (IN void* This);
typedef EFI_STATUS(__cdecl* EFI_FILE_FLUSH) (IN void* This);
typedef EFI_STATUS(__cdecl* EFI_FILE_FLUSH_EX) (IN void* This, IN OUT EFI_FILE_IO_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_FILE_GET_INFO) (IN void* This, IN EFI_GUID* InformationType, IN OUT unsigned long long* BufferSize, OUT void* Buffer);
typedef EFI_STATUS(__cdecl* EFI_FILE_GET_POSITION) (IN void* This, OUT unsigned long long* Position);
typedef EFI_STATUS(__cdecl* EFI_FILE_OPEN) (IN void* This, OUT void** NewHandle, IN CHAR16* FileName, IN unsigned long long OpenMode, IN unsigned long long Attributes);
typedef EFI_STATUS(__cdecl* EFI_FILE_OPEN_EX) (IN void* This, OUT void** NewHandle, IN CHAR16* FileName, IN unsigned long long OpenMode, IN unsigned long long Attributes, IN OUT EFI_FILE_IO_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_FILE_READ) (IN void* This, IN OUT unsigned long long* BufferSize, OUT void* Buffer);
typedef EFI_STATUS(__cdecl* EFI_FILE_READ_EX) (IN void* This, IN OUT EFI_FILE_IO_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_FILE_SET_INFO) (IN void* This, IN EFI_GUID* InformationType, IN unsigned long long BufferSize, IN void* Buffer);
typedef EFI_STATUS(__cdecl* EFI_FILE_SET_POSITION) (IN void* This, IN unsigned long long Position);
typedef EFI_STATUS(__cdecl* EFI_FILE_WRITE) (IN void* This, IN OUT unsigned long long* BufferSize, IN void* Buffer);
typedef EFI_STATUS(__cdecl* EFI_FILE_WRITE_EX) (IN void* This, IN OUT EFI_FILE_IO_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_FREE_PAGES) (IN EFI_PHYSICAL_ADDRESS Memory, IN unsigned long long Pages);
typedef EFI_STATUS(__cdecl* EFI_FREE_POOL) (IN void* Buffer);
typedef EFI_STATUS(__cdecl* EFI_GET_MAXIMUM_PROCESSOR_INDEX) (IN void* This, OUT unsigned long long* MaxProcessorIndex);
typedef EFI_STATUS(__cdecl* EFI_GET_MEMORY_MAP) (IN OUT unsigned long long* MemoryMapSize, OUT EFI_MEMORY_DESCRIPTOR* MemoryMap, OUT unsigned long long* MapKey, OUT unsigned long long* DescriptorSize, OUT unsigned int* DescriptorVersion);
typedef EFI_STATUS(__cdecl* EFI_GET_NEXT_HIGH_MONO_COUNT) (OUT unsigned int* HighCount);
typedef EFI_STATUS(__cdecl* EFI_GET_NEXT_MONOTONIC_COUNT) (OUT unsigned long long* Count);
typedef EFI_STATUS(__cdecl* EFI_GET_NEXT_VARIABLE_NAME) (IN OUT unsigned long long* VariableNameSize, IN OUT CHAR16* VariableName, IN OUT EFI_GUID* VendorGuid);
typedef EFI_STATUS(__cdecl* EFI_GET_TIME) (OUT EFI_TIME* Time, OUT EFI_TIME_CAPABILITIES* Capabilities OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_GET_VARIABLE) (IN CHAR16* VariableName, IN EFI_GUID* VendorGuid, OUT unsigned int* Attributes OPTIONAL, IN OUT unsigned long long* DataSize, OUT void* Data);
typedef EFI_STATUS(__cdecl* EFI_GET_WAKEUP_TIME) (OUT BOOLEAN* Enabled, OUT BOOLEAN* Pending, OUT EFI_TIME* Time);
typedef EFI_STATUS(__cdecl* EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT) (IN void* This, IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL* BltBuffer, OPTIONAL IN EFI_GRAPHICS_OUTPUT_BLT_OPERATION BltOperation, IN unsigned long long SourceX, IN unsigned long long SourceY, IN unsigned long long DestinationX, IN unsigned long long DestinationY, IN unsigned long long Width, IN unsigned long long Height, IN unsigned long long Delta OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE) (IN void* This, IN unsigned int ModeNumber, OUT unsigned long long* SizeOfInfo, OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION** Info);
typedef EFI_STATUS(__cdecl* EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE) (IN void* This, IN unsigned int ModeNumber);
typedef EFI_STATUS(__cdecl* EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID* Protocol, OUT void** Interface);
typedef EFI_STATUS(__cdecl* EFI_IMAGE_LOAD) (IN BOOLEAN BootPolicy, IN EFI_HANDLE ParentImageHandle, IN EFI_DEVICE_PATH_PROTOCOL* DevicePath, IN void* SourceBuffer OPTIONAL, IN unsigned long long SourceSize, OUT EFI_HANDLE* ImageHandle);
typedef EFI_STATUS(__cdecl* EFI_IMAGE_START) (IN EFI_HANDLE ImageHandle, OUT unsigned long long* ExitDataSize, OUT CHAR16** ExitData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_IMAGE_UNLOAD) (IN EFI_HANDLE ImageHandle);
typedef EFI_STATUS(__cdecl* EFI_INPUT_READ_KEY) (IN void* This, OUT EFI_INPUT_KEY* Key);
typedef EFI_STATUS(__cdecl* EFI_INPUT_RESET) (IN void* This, IN BOOLEAN ExtendedVerification);
typedef EFI_STATUS(__cdecl* EFI_INSTALL_CONFIGURATION_TABLE) (IN EFI_GUID* Guid, IN void* Table);
typedef EFI_STATUS(__cdecl* EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN OUT EFI_HANDLE* Handle, ...);
typedef EFI_STATUS(__cdecl* EFI_INSTALL_PROTOCOL_INTERFACE) (IN OUT EFI_HANDLE* Handle, IN EFI_GUID* Protocol, IN EFI_INTERFACE_TYPE InterfaceType, IN void* Interface);
typedef EFI_STATUS(__cdecl* EFI_INVALIDATE_INSTRUCTION_CACHE) (IN void* This, IN unsigned long long ProcessorIndex, IN void* Start, IN unsigned long long Length);
typedef EFI_STATUS(__cdecl* EFI_LOCATE_DEVICE_PATH) (IN EFI_GUID* Protocol, IN OUT EFI_DEVICE_PATH_PROTOCOL** DevicePath, OUT EFI_HANDLE* Device);
typedef EFI_STATUS(__cdecl* EFI_LOCATE_HANDLE) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID* Protocol OPTIONAL, IN void* SearchKey OPTIONAL, IN OUT unsigned long long* BufferSize, OUT EFI_HANDLE* Buffer);
typedef EFI_STATUS(__cdecl* EFI_LOCATE_HANDLE_BUFFER) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID* Protocol OPTIONAL, IN void* SearchKey OPTIONAL, OUT unsigned long long* NoHandles, OUT EFI_HANDLE** Buffer);
typedef EFI_STATUS(__cdecl* EFI_LOCATE_PROTOCOL) (IN EFI_GUID* Protocol, IN void* Registration OPTIONAL, OUT void** Interface);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_ENABLEDISABLEAP) (IN void* This, IN unsigned long long ProcessorNumber, IN BOOLEAN EnableAP, IN unsigned int* HealthFlag OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS) (IN void* This, OUT unsigned long long* NumberOfProcessors, OUT unsigned long long* NumberOfEnabledProcessors);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_GET_PROCESSOR_INFO) (IN void* This, IN unsigned long long ProcessorNumber, OUT EFI_PROCESSOR_INFORMATION* ProcessorInfoBuffer);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_STARTUP_ALL_APS) (IN void* This, IN EFI_AP_PROCEDURE Procedure, IN BOOLEAN SingleThread, IN EFI_EVENT WaitEvent OPTIONAL, IN unsigned long long TimeoutInMicroSeconds, IN void* ProcedureArgument OPTIONAL, OUT unsigned long long** FailedCpuList OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_STARTUP_THIS_AP) (IN void* This, IN EFI_AP_PROCEDURE Procedure, IN unsigned long long ProcessorNumber, IN EFI_EVENT WaitEvent OPTIONAL, IN unsigned long long TimeoutInMicroseconds, IN void* ProcedureArgument OPTIONAL, OUT BOOLEAN* Finished OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_SWITCH_BSP) (IN void* This, IN unsigned long long ProcessorNumber, IN BOOLEAN EnableOldBSP);
typedef EFI_STATUS(__cdecl* EFI_MP_SERVICES_WHOAMI) (IN void* This, OUT unsigned long long* ProcessorNumber);
typedef EFI_STATUS(__cdecl* EFI_OPEN_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID* Protocol, OUT void** Interface OPTIONAL, IN EFI_HANDLE AgentHandle, IN EFI_HANDLE ControllerHandle, IN unsigned int Attributes);
typedef EFI_STATUS(__cdecl* EFI_OPEN_PROTOCOL_INFORMATION) (IN EFI_HANDLE Handle, IN EFI_GUID* Protocol, OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY** EntryBuffer, OUT unsigned long long* EntryCount);
typedef void(*EFI_PERIODIC_CALLBACK) (IN OUT EFI_SYSTEM_CONTEXT SystemContext);
typedef EFI_STATUS(__cdecl* EFI_PROTOCOLS_PER_HANDLE) (IN EFI_HANDLE Handle, OUT EFI_GUID*** ProtocolBuffer, OUT unsigned long long* ProtocolBufferCount);
typedef EFI_STATUS(__cdecl* EFI_QUERY_CAPSULE_CAPABILITIES) (IN EFI_CAPSULE_HEADER** CapsuleHeaderArray, IN unsigned long long CapsuleCount, OUT unsigned long long* MaximumCapsuleSize, OUT EFI_RESET_TYPE* ResetType);
typedef EFI_STATUS(__cdecl* EFI_QUERY_VARIABLE_INFO) (IN unsigned int Attributes, OUT unsigned long long* MaximumVariableStorageSize, OUT unsigned long long* RemainingVariableStorageSize, OUT unsigned long long* MaximumVariableSize);
typedef EFI_TPL(__cdecl* EFI_RAISE_TPL) (IN EFI_TPL NewTpl);
typedef EFI_STATUS(__cdecl* EFI_REGISTER_EXCEPTION_CALLBACK) (IN void* This, IN unsigned long long ProcessorIndex, IN EFI_EXCEPTION_CALLBACK ExceptionCallback, IN long long ExceptionType);
typedef EFI_STATUS(__cdecl* EFI_REGISTER_PERIODIC_CALLBACK) (IN void* This, IN unsigned long long ProcessorIndex, IN EFI_PERIODIC_CALLBACK PeriodicCallback);
typedef EFI_STATUS(__cdecl* EFI_REGISTER_PROTOCOL_NOTIFY) (IN EFI_GUID* Protocol, IN EFI_EVENT Event, OUT void** Registration);
typedef EFI_STATUS(__cdecl* EFI_REINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE Handle, IN EFI_GUID* Protocol, IN void* OldInterface, IN void* NewInterface);
typedef EFI_STATUS(__cdecl* EFI_RESET_SYSTEM) (IN EFI_RESET_TYPE ResetType, IN EFI_STATUS ResetStatus, IN unsigned long long DataSize, IN CHAR16* ResetData OPTIONAL);
typedef void(__cdecl* EFI_RESTORE_TPL) (IN EFI_TPL OldTpl);
typedef EFI_STATUS(__cdecl* EFI_SERVICE_BINDING_CREATE_CHILD) (IN void* This, IN OUT EFI_HANDLE* ChildHandle);
typedef EFI_STATUS(__cdecl* EFI_SERVICE_BINDING_DESTROY_CHILD) (IN void* This, IN EFI_HANDLE ChildHandle);
typedef void(__cdecl* EFI_SET_MEM) (IN void* Buffer, IN unsigned long long Size, IN unsigned char Value);
typedef EFI_STATUS(__cdecl* EFI_SET_TIME) (IN EFI_TIME* Time);
typedef EFI_STATUS(__cdecl* EFI_SET_TIMER) (IN EFI_EVENT Event, IN EFI_TIMER_DELAY Type, IN unsigned long long TriggerTime);
typedef EFI_STATUS(__cdecl* EFI_SET_VARIABLE) (IN CHAR16* VariableName, IN EFI_GUID* VendorGuid, IN unsigned int Attributes, IN unsigned long long DataSize, IN void* Data);
typedef EFI_STATUS(__cdecl* EFI_SET_VIRTUAL_ADDRESS_MAP) (IN unsigned long long MemoryMapSize, IN unsigned long long DescriptorSize, IN unsigned int DescriptorVersion, IN EFI_MEMORY_DESCRIPTOR* VirtualMap);
typedef EFI_STATUS(__cdecl* EFI_SET_WAKEUP_TIME) (IN BOOLEAN Enable, IN EFI_TIME* Time OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_SET_WATCHDOG_TIMER) (IN unsigned long long Timeout, IN unsigned long long WatchdogCode, IN unsigned long long DataSize, IN CHAR16* WatchdogData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_SIGNAL_EVENT) (IN EFI_EVENT Event);
typedef EFI_STATUS(__cdecl* EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME) (IN void* This, OUT void** Root);
typedef EFI_STATUS(__cdecl* EFI_STALL) (IN unsigned long long Microseconds);
typedef EFI_STATUS(__cdecl* EFI_TCP4_ACCEPT) (IN void* This, IN EFI_TCP4_LISTEN_TOKEN* ListenToken);
typedef EFI_STATUS(__cdecl* EFI_TCP4_CANCEL)(IN void* This, IN EFI_TCP4_COMPLETION_TOKEN* Token OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_TCP4_CLOSE)(IN void* This, IN EFI_TCP4_CLOSE_TOKEN* CloseToken);
typedef EFI_STATUS(__cdecl* EFI_TCP4_CONFIGURE) (IN void* This, IN EFI_TCP4_CONFIG_DATA* TcpConfigData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_TCP4_CONNECT) (IN void* This, IN EFI_TCP4_CONNECTION_TOKEN* ConnectionToken);
typedef EFI_STATUS(__cdecl* EFI_TCP4_GET_MODE_DATA) (IN void* This, OUT EFI_TCP4_CONNECTION_STATE* Tcp4State OPTIONAL, OUT EFI_TCP4_CONFIG_DATA* Tcp4ConfigData OPTIONAL, OUT EFI_IP4_MODE_DATA* Ip4ModeData OPTIONAL, OUT EFI_MANAGED_NETWORK_CONFIG_DATA* MnpConfigData OPTIONAL, OUT EFI_SIMPLE_NETWORK_MODE* SnpModeData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_TCP4_POLL) (IN void* This);
typedef EFI_STATUS(__cdecl* EFI_TCP4_RECEIVE) (IN void* This, IN EFI_TCP4_IO_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_TCP4_ROUTES) (IN void* This, IN BOOLEAN DeleteRoute, IN EFI_IPv4_ADDRESS* SubnetAddress, IN EFI_IPv4_ADDRESS* SubnetMask, IN EFI_IPv4_ADDRESS* GatewayAddress);
typedef EFI_STATUS(__cdecl* EFI_TCP4_TRANSMIT) (IN void* This, IN EFI_TCP4_IO_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_TEXT_CLEAR_SCREEN) (IN void* This);
typedef EFI_STATUS(__cdecl* EFI_TEXT_ENABLE_CURSOR) (IN void* This, IN BOOLEAN Visible);
typedef EFI_STATUS(__cdecl* EFI_TEXT_QUERY_MODE) (IN void* This, IN unsigned long long ModeNumber, OUT unsigned long long* Columns, OUT unsigned long long* Rows);
typedef EFI_STATUS(__cdecl* EFI_TEXT_RESET) (IN void* This, IN BOOLEAN ExtendedVerification);
typedef EFI_STATUS(__cdecl* EFI_TEXT_SET_ATTRIBUTE) (IN void* This, IN unsigned long long Attribute);
typedef EFI_STATUS(__cdecl* EFI_TEXT_SET_CURSOR_POSITION) (IN void* This, IN unsigned long long Column, IN unsigned long long Row);
typedef EFI_STATUS(__cdecl* EFI_TEXT_SET_MODE) (IN void* This, IN unsigned long long ModeNumber);
typedef EFI_STATUS(__cdecl* EFI_TEXT_STRING) (IN void* This, IN CHAR16* String);
typedef EFI_STATUS(__cdecl* EFI_TEXT_TEST_STRING) (IN void* This, IN CHAR16* String);
typedef EFI_STATUS(__cdecl* EFI_UDP4_CANCEL)(IN void* This, IN EFI_UDP4_COMPLETION_TOKEN* Token OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_UDP4_CONFIGURE) (IN void* This, IN EFI_UDP4_CONFIG_DATA* UdpConfigData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_UDP4_GET_MODE_DATA) (IN void* This, OUT EFI_UDP4_CONFIG_DATA* Udp4ConfigData OPTIONAL, OUT EFI_IP4_MODE_DATA* Ip4ModeData OPTIONAL, OUT EFI_MANAGED_NETWORK_CONFIG_DATA* MnpConfigData OPTIONAL, OUT EFI_SIMPLE_NETWORK_MODE* SnpModeData OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_UDP4_GROUPS) (IN void* This, IN BOOLEAN JoinFlag, IN EFI_IPv4_ADDRESS* MulticastAddress OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_UDP4_POLL) (IN void* This);
typedef EFI_STATUS(__cdecl* EFI_UDP4_RECEIVE) (IN void* This, IN EFI_UDP4_COMPLETION_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_UDP4_ROUTES) (IN void* This, IN BOOLEAN DeleteRoute, IN EFI_IPv4_ADDRESS* SubnetAddress, IN EFI_IPv4_ADDRESS* SubnetMask, IN EFI_IPv4_ADDRESS* GatewayAddress);
typedef EFI_STATUS(__cdecl* EFI_UDP4_TRANSMIT) (IN void* This, IN EFI_UDP4_COMPLETION_TOKEN* Token);
typedef EFI_STATUS(__cdecl* EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN EFI_HANDLE Handle, ...);
typedef EFI_STATUS(__cdecl* EFI_UNINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE Handle, IN EFI_GUID* Protocol, IN void* Interface);
typedef EFI_STATUS(__cdecl* EFI_UPDATE_CAPSULE) (IN EFI_CAPSULE_HEADER** CapsuleHeaderArray, IN unsigned long long CapsuleCount, IN EFI_PHYSICAL_ADDRESS ScatterGatherList OPTIONAL);
typedef EFI_STATUS(__cdecl* EFI_WAIT_FOR_EVENT) (IN unsigned long long NumberOfEvents, IN EFI_EVENT* Event, OUT unsigned long long* Index);

typedef struct
{
    EFI_TABLE_HEADER Hdr;
    EFI_RAISE_TPL RaiseTPL;
    EFI_RESTORE_TPL RestoreTPL;
    EFI_ALLOCATE_PAGES AllocatePages;
    EFI_FREE_PAGES FreePages;
    EFI_GET_MEMORY_MAP GetMemoryMap;
    EFI_ALLOCATE_POOL AllocatePool;
    EFI_FREE_POOL FreePool;
    EFI_CREATE_EVENT CreateEvent;
    EFI_SET_TIMER SetTimer;
    EFI_WAIT_FOR_EVENT WaitForEvent;
    EFI_SIGNAL_EVENT SignalEvent;
    EFI_CLOSE_EVENT CloseEvent;
    EFI_CHECK_EVENT CheckEvent;
    EFI_INSTALL_PROTOCOL_INTERFACE InstallProtocolInterface;
    EFI_REINSTALL_PROTOCOL_INTERFACE ReinstallProtocolInterface;
    EFI_UNINSTALL_PROTOCOL_INTERFACE UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL HandleProtocol;
    void* Reserved;
    EFI_REGISTER_PROTOCOL_NOTIFY RegisterProtocolNotify;
    EFI_LOCATE_HANDLE LocateHandle;
    EFI_LOCATE_DEVICE_PATH LocateDevicePath;
    EFI_INSTALL_CONFIGURATION_TABLE InstallConfigurationTable;
    EFI_IMAGE_LOAD LoadImage;
    EFI_IMAGE_START StartImage;
    EFI_EXIT Exit;
    EFI_IMAGE_UNLOAD UnloadImage;
    EFI_EXIT_BOOT_SERVICES ExitBootServices;
    EFI_GET_NEXT_MONOTONIC_COUNT GetNextMonotonicCount;
    EFI_STALL Stall;
    EFI_SET_WATCHDOG_TIMER SetWatchdogTimer;
    EFI_CONNECT_CONTROLLER ConnectController;
    EFI_DISCONNECT_CONTROLLER DisconnectController;
    EFI_OPEN_PROTOCOL OpenProtocol;
    EFI_CLOSE_PROTOCOL CloseProtocol;
    EFI_OPEN_PROTOCOL_INFORMATION OpenProtocolInformation;
    EFI_PROTOCOLS_PER_HANDLE ProtocolsPerHandle;
    EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
    EFI_LOCATE_PROTOCOL LocateProtocol;
    EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES InstallMultipleProtocolInterfaces;
    EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES UninstallMultipleProtocolInterfaces;
    EFI_CALCULATE_CRC32 CalculateCrc32;
    EFI_COPY_MEM CopyMem;
    EFI_SET_MEM SetMem;
    EFI_CREATE_EVENT_EX CreateEventEx;
} EFI_BOOT_SERVICES;

typedef struct
{
    EFI_GUID VendorGuid;
    void* VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct
{
    EFI_INSTRUCTION_SET_ARCHITECTURE Isa;
    EFI_GET_MAXIMUM_PROCESSOR_INDEX GetMaximumProcessorIndex;
    EFI_REGISTER_PERIODIC_CALLBACK RegisterPeriodicCallback;
    EFI_REGISTER_EXCEPTION_CALLBACK RegisterExceptionCallback;
    EFI_INVALIDATE_INSTRUCTION_CACHE InvalidateInstructionCache;
} EFI_DEBUG_SUPPORT_PROTOCOL;

typedef struct
{
    unsigned long long Revision;
    EFI_FILE_OPEN Open;
    EFI_FILE_CLOSE Close;
    EFI_FILE_DELETE Delete;
    EFI_FILE_READ Read;
    EFI_FILE_WRITE Write;
    EFI_FILE_GET_POSITION GetPosition;
    EFI_FILE_SET_POSITION SetPosition;
    EFI_FILE_GET_INFO GetInfo;
    EFI_FILE_SET_INFO SetInfo;
    EFI_FILE_FLUSH Flush;
    EFI_FILE_OPEN_EX OpenEx;
    EFI_FILE_READ_EX ReadEx;
    EFI_FILE_WRITE_EX WriteEx;
    EFI_FILE_FLUSH_EX FlushEx;
} EFI_FILE_PROTOCOL;

typedef struct
{
    EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE QueryMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE SetMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT Blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE* Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

typedef struct
{
    EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS GetNumberOfProcessors;
    EFI_MP_SERVICES_GET_PROCESSOR_INFO GetProcessorInfo;
    EFI_MP_SERVICES_STARTUP_ALL_APS StartupAllAPs;
    EFI_MP_SERVICES_STARTUP_THIS_AP StartupThisAP;
    EFI_MP_SERVICES_SWITCH_BSP SwitchBSP;
    EFI_MP_SERVICES_ENABLEDISABLEAP EnableDisableAP;
    EFI_MP_SERVICES_WHOAMI WhoAmI;
} EFI_MP_SERVICES_PROTOCOL;

typedef struct
{
    EFI_TABLE_HEADER Hdr;
    EFI_GET_TIME GetTime;
    EFI_SET_TIME SetTime;
    EFI_GET_WAKEUP_TIME GetWakeupTime;
    EFI_SET_WAKEUP_TIME SetWakeupTime;
    EFI_SET_VIRTUAL_ADDRESS_MAP SetVirtualAddressMap;
    EFI_CONVERT_POINTER ConvertPointer;
    EFI_GET_VARIABLE GetVariable;
    EFI_GET_NEXT_VARIABLE_NAME GetNextVariableName;
    EFI_SET_VARIABLE SetVariable;
    EFI_GET_NEXT_HIGH_MONO_COUNT GetNextHighMonotonicCount;
    EFI_RESET_SYSTEM ResetSystem;
    EFI_UPDATE_CAPSULE UpdateCapsule;
    EFI_QUERY_CAPSULE_CAPABILITIES QueryCapsuleCapabilities;
    EFI_QUERY_VARIABLE_INFO QueryVariableInfo;
} EFI_RUNTIME_SERVICES;

typedef struct
{
    EFI_SERVICE_BINDING_CREATE_CHILD CreateChild;
    EFI_SERVICE_BINDING_DESTROY_CHILD DestroyChild;
} EFI_SERVICE_BINDING_PROTOCOL;

typedef struct
{
    unsigned long long Revision;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME OpenVolume;
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

typedef struct
{
    EFI_INPUT_RESET Reset;
    EFI_INPUT_READ_KEY ReadKeyStroke;
    EFI_EVENT WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

typedef struct
{
    EFI_TEXT_RESET Reset;
    EFI_TEXT_STRING OutputString;
    EFI_TEXT_TEST_STRING TestString;
    EFI_TEXT_QUERY_MODE QueryMode;
    EFI_TEXT_SET_MODE SetMode;
    EFI_TEXT_SET_ATTRIBUTE SetAttribute;
    EFI_TEXT_CLEAR_SCREEN ClearScreen;
    EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;
    EFI_TEXT_ENABLE_CURSOR EnableCursor;
    SIMPLE_TEXT_OUTPUT_MODE* Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef struct
{
    EFI_TABLE_HEADER Hdr;
    CHAR16* FirmwareVendor;
    unsigned int FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL* ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* ConOut;
    EFI_HANDLE StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* StdErr;
    EFI_RUNTIME_SERVICES* RuntimeServices;
    EFI_BOOT_SERVICES* BootServices;
    unsigned long long NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE* ConfigurationTable;
} EFI_SYSTEM_TABLE;

typedef struct
{
    EFI_TCP4_GET_MODE_DATA GetModeData;
    EFI_TCP4_CONFIGURE Configure;
    EFI_TCP4_ROUTES Routes;
    EFI_TCP4_CONNECT Connect;
    EFI_TCP4_ACCEPT Accept;
    EFI_TCP4_TRANSMIT Transmit;
    EFI_TCP4_RECEIVE Receive;
    EFI_TCP4_CLOSE Close;
    EFI_TCP4_CANCEL Cancel;
    EFI_TCP4_POLL Poll;
} EFI_TCP4_PROTOCOL;

typedef struct
{
    EFI_UDP4_GET_MODE_DATA GetModeData;
    EFI_UDP4_CONFIGURE Configure;
    EFI_UDP4_GROUPS Groups;
    EFI_UDP4_ROUTES Routes;
    EFI_UDP4_TRANSMIT Transmit;
    EFI_UDP4_RECEIVE Receive;
    EFI_UDP4_CANCEL Cancel;
    EFI_UDP4_POLL Poll;
} EFI_UDP4_PROTOCOL;

static EFI_HANDLE ih;
static EFI_SYSTEM_TABLE* st;
static EFI_RUNTIME_SERVICES* rs;
static EFI_BOOT_SERVICES* bs;

////////// KangarooTwelve \\\\\\\\\\

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#else
#define ROL64(a, offset) ((((unsigned long long)a) << offset) ^ (((unsigned long long)a) >> (64 - offset)))
#endif

#if AVX512
static __m512i zero, moveThetaPrev, moveThetaNext, rhoB, rhoG, rhoK, rhoM, rhoS, pi1B, pi1G, pi1K, pi1M, pi1S, pi2S1, pi2S2, pi2BG, pi2KM, pi2S3, padding;
static __m512i K12RoundConst0, K12RoundConst1, K12RoundConst2, K12RoundConst3, K12RoundConst4, K12RoundConst5, K12RoundConst6, K12RoundConst7, K12RoundConst8, K12RoundConst9, K12RoundConst10, K12RoundConst11;

#else

#define KeccakF1600RoundConstant0   0x000000008000808bULL
#define KeccakF1600RoundConstant1   0x800000000000008bULL
#define KeccakF1600RoundConstant2   0x8000000000008089ULL
#define KeccakF1600RoundConstant3   0x8000000000008003ULL
#define KeccakF1600RoundConstant4   0x8000000000008002ULL
#define KeccakF1600RoundConstant5   0x8000000000000080ULL
#define KeccakF1600RoundConstant6   0x000000000000800aULL
#define KeccakF1600RoundConstant7   0x800000008000000aULL
#define KeccakF1600RoundConstant8   0x8000000080008081ULL
#define KeccakF1600RoundConstant9   0x8000000000008080ULL
#define KeccakF1600RoundConstant10  0x0000000080000001ULL

#define declareABCDE \
    unsigned long long Aba, Abe, Abi, Abo, Abu; \
    unsigned long long Aga, Age, Agi, Ago, Agu; \
    unsigned long long Aka, Ake, Aki, Ako, Aku; \
    unsigned long long Ama, Ame, Ami, Amo, Amu; \
    unsigned long long Asa, Ase, Asi, Aso, Asu; \
    unsigned long long Bba, Bbe, Bbi, Bbo, Bbu; \
    unsigned long long Bga, Bge, Bgi, Bgo, Bgu; \
    unsigned long long Bka, Bke, Bki, Bko, Bku; \
    unsigned long long Bma, Bme, Bmi, Bmo, Bmu; \
    unsigned long long Bsa, Bse, Bsi, Bso, Bsu; \
    unsigned long long Ca, Ce, Ci, Co, Cu; \
    unsigned long long Da, De, Di, Do, Du; \
    unsigned long long Eba, Ebe, Ebi, Ebo, Ebu; \
    unsigned long long Ega, Ege, Egi, Ego, Egu; \
    unsigned long long Eka, Eke, Eki, Eko, Eku; \
    unsigned long long Ema, Eme, Emi, Emo, Emu; \
    unsigned long long Esa, Ese, Esi, Eso, Esu; \

#define thetaRhoPiChiIotaPrepareTheta(i, A, E) \
    Da = Cu^ROL64(Ce, 1); \
    De = Ca^ROL64(Ci, 1); \
    Di = Ce^ROL64(Co, 1); \
    Do = Ci^ROL64(Cu, 1); \
    Du = Co^ROL64(Ca, 1); \
    A##ba ^= Da; \
    Bba = A##ba; \
    A##ge ^= De; \
    Bbe = ROL64(A##ge, 44); \
    A##ki ^= Di; \
    Bbi = ROL64(A##ki, 43); \
    A##mo ^= Do; \
    Bbo = ROL64(A##mo, 21); \
    A##su ^= Du; \
    Bbu = ROL64(A##su, 14); \
    E##ba =   Bba ^((~Bbe)&  Bbi ); \
    E##ba ^= KeccakF1600RoundConstant##i; \
    Ca = E##ba; \
    E##be =   Bbe ^((~Bbi)&  Bbo ); \
    Ce = E##be; \
    E##bi =   Bbi ^((~Bbo)&  Bbu ); \
    Ci = E##bi; \
    E##bo =   Bbo ^((~Bbu)&  Bba ); \
    Co = E##bo; \
    E##bu =   Bbu ^((~Bba)&  Bbe ); \
    Cu = E##bu; \
    A##bo ^= Do; \
    Bga = ROL64(A##bo, 28); \
    A##gu ^= Du; \
    Bge = ROL64(A##gu, 20); \
    A##ka ^= Da; \
    Bgi = ROL64(A##ka, 3); \
    A##me ^= De; \
    Bgo = ROL64(A##me, 45); \
    A##si ^= Di; \
    Bgu = ROL64(A##si, 61); \
    E##ga =   Bga ^((~Bge)&  Bgi ); \
    Ca ^= E##ga; \
    E##ge =   Bge ^((~Bgi)&  Bgo ); \
    Ce ^= E##ge; \
    E##gi =   Bgi ^((~Bgo)&  Bgu ); \
    Ci ^= E##gi; \
    E##go =   Bgo ^((~Bgu)&  Bga ); \
    Co ^= E##go; \
    E##gu =   Bgu ^((~Bga)&  Bge ); \
    Cu ^= E##gu; \
    A##be ^= De; \
    Bka = ROL64(A##be, 1); \
    A##gi ^= Di; \
    Bke = ROL64(A##gi, 6); \
    A##ko ^= Do; \
    Bki = ROL64(A##ko, 25); \
    A##mu ^= Du; \
    Bko = ROL64(A##mu, 8); \
    A##sa ^= Da; \
    Bku = ROL64(A##sa, 18); \
    E##ka =   Bka ^((~Bke)&  Bki ); \
    Ca ^= E##ka; \
    E##ke =   Bke ^((~Bki)&  Bko ); \
    Ce ^= E##ke; \
    E##ki =   Bki ^((~Bko)&  Bku ); \
    Ci ^= E##ki; \
    E##ko =   Bko ^((~Bku)&  Bka ); \
    Co ^= E##ko; \
    E##ku =   Bku ^((~Bka)&  Bke ); \
    Cu ^= E##ku; \
    A##bu ^= Du; \
    Bma = ROL64(A##bu, 27); \
    A##ga ^= Da; \
    Bme = ROL64(A##ga, 36); \
    A##ke ^= De; \
    Bmi = ROL64(A##ke, 10); \
    A##mi ^= Di; \
    Bmo = ROL64(A##mi, 15); \
    A##so ^= Do; \
    Bmu = ROL64(A##so, 56); \
    E##ma =   Bma ^((~Bme)&  Bmi ); \
    Ca ^= E##ma; \
    E##me =   Bme ^((~Bmi)&  Bmo ); \
    Ce ^= E##me; \
    E##mi =   Bmi ^((~Bmo)&  Bmu ); \
    Ci ^= E##mi; \
    E##mo =   Bmo ^((~Bmu)&  Bma ); \
    Co ^= E##mo; \
    E##mu =   Bmu ^((~Bma)&  Bme ); \
    Cu ^= E##mu; \
    A##bi ^= Di; \
    Bsa = ROL64(A##bi, 62); \
    A##go ^= Do; \
    Bse = ROL64(A##go, 55); \
    A##ku ^= Du; \
    Bsi = ROL64(A##ku, 39); \
    A##ma ^= Da; \
    Bso = ROL64(A##ma, 41); \
    A##se ^= De; \
    Bsu = ROL64(A##se, 2); \
    E##sa =   Bsa ^((~Bse)&  Bsi ); \
    Ca ^= E##sa; \
    E##se =   Bse ^((~Bsi)&  Bso ); \
    Ce ^= E##se; \
    E##si =   Bsi ^((~Bso)&  Bsu ); \
    Ci ^= E##si; \
    E##so =   Bso ^((~Bsu)&  Bsa ); \
    Co ^= E##so; \
    E##su =   Bsu ^((~Bsa)&  Bse ); \
    Cu ^= E##su;

#define copyFromState(state) \
    Aba = state[ 0]; \
    Abe = state[ 1]; \
    Abi = state[ 2]; \
    Abo = state[ 3]; \
    Abu = state[ 4]; \
    Aga = state[ 5]; \
    Age = state[ 6]; \
    Agi = state[ 7]; \
    Ago = state[ 8]; \
    Agu = state[ 9]; \
    Aka = state[10]; \
    Ake = state[11]; \
    Aki = state[12]; \
    Ako = state[13]; \
    Aku = state[14]; \
    Ama = state[15]; \
    Ame = state[16]; \
    Ami = state[17]; \
    Amo = state[18]; \
    Amu = state[19]; \
    Asa = state[20]; \
    Ase = state[21]; \
    Asi = state[22]; \
    Aso = state[23]; \
    Asu = state[24];

#define copyToState(state) \
    state[ 0] = Aba; \
    state[ 1] = Abe; \
    state[ 2] = Abi; \
    state[ 3] = Abo; \
    state[ 4] = Abu; \
    state[ 5] = Aga; \
    state[ 6] = Age; \
    state[ 7] = Agi; \
    state[ 8] = Ago; \
    state[ 9] = Agu; \
    state[10] = Aka; \
    state[11] = Ake; \
    state[12] = Aki; \
    state[13] = Ako; \
    state[14] = Aku; \
    state[15] = Ama; \
    state[16] = Ame; \
    state[17] = Ami; \
    state[18] = Amo; \
    state[19] = Amu; \
    state[20] = Asa; \
    state[21] = Ase; \
    state[22] = Asi; \
    state[23] = Aso; \
    state[24] = Asu;

#define rounds12 \
    Ca = Aba^Aga^Aka^Ama^Asa; \
    Ce = Abe^Age^Ake^Ame^Ase; \
    Ci = Abi^Agi^Aki^Ami^Asi; \
    Co = Abo^Ago^Ako^Amo^Aso; \
    Cu = Abu^Agu^Aku^Amu^Asu; \
    thetaRhoPiChiIotaPrepareTheta(0, A, E) \
    thetaRhoPiChiIotaPrepareTheta(1, E, A) \
    thetaRhoPiChiIotaPrepareTheta(2, A, E) \
    thetaRhoPiChiIotaPrepareTheta(3, E, A) \
    thetaRhoPiChiIotaPrepareTheta(4, A, E) \
    thetaRhoPiChiIotaPrepareTheta(5, E, A) \
    thetaRhoPiChiIotaPrepareTheta(6, A, E) \
    thetaRhoPiChiIotaPrepareTheta(7, E, A) \
    thetaRhoPiChiIotaPrepareTheta(8, A, E) \
    thetaRhoPiChiIotaPrepareTheta(9, E, A) \
    thetaRhoPiChiIotaPrepareTheta(10, A, E) \
    Da = Cu^ROL64(Ce, 1); \
    De = Ca^ROL64(Ci, 1); \
    Di = Ce^ROL64(Co, 1); \
    Do = Ci^ROL64(Cu, 1); \
    Du = Co^ROL64(Ca, 1); \
    Eba ^= Da; \
    Bba = Eba; \
    Ege ^= De; \
    Bbe = ROL64(Ege, 44); \
    Eki ^= Di; \
    Bbi = ROL64(Eki, 43); \
    Emo ^= Do; \
    Bbo = ROL64(Emo, 21); \
    Esu ^= Du; \
    Bbu = ROL64(Esu, 14); \
    Aba =   Bba ^((~Bbe)&  Bbi ); \
    Aba ^= 0x8000000080008008ULL; \
    Abe =   Bbe ^((~Bbi)&  Bbo ); \
    Abi =   Bbi ^((~Bbo)&  Bbu ); \
    Abo =   Bbo ^((~Bbu)&  Bba ); \
    Abu =   Bbu ^((~Bba)&  Bbe ); \
    Ebo ^= Do; \
    Bga = ROL64(Ebo, 28); \
    Egu ^= Du; \
    Bge = ROL64(Egu, 20); \
    Eka ^= Da; \
    Bgi = ROL64(Eka, 3); \
    Eme ^= De; \
    Bgo = ROL64(Eme, 45); \
    Esi ^= Di; \
    Bgu = ROL64(Esi, 61); \
    Aga =   Bga ^((~Bge)&  Bgi ); \
    Age =   Bge ^((~Bgi)&  Bgo ); \
    Agi =   Bgi ^((~Bgo)&  Bgu ); \
    Ago =   Bgo ^((~Bgu)&  Bga ); \
    Agu =   Bgu ^((~Bga)&  Bge ); \
    Ebe ^= De; \
    Bka = ROL64(Ebe, 1); \
    Egi ^= Di; \
    Bke = ROL64(Egi, 6); \
    Eko ^= Do; \
    Bki = ROL64(Eko, 25); \
    Emu ^= Du; \
    Bko = ROL64(Emu, 8); \
    Esa ^= Da; \
    Bku = ROL64(Esa, 18); \
    Aka =   Bka ^((~Bke)&  Bki ); \
    Ake =   Bke ^((~Bki)&  Bko ); \
    Aki =   Bki ^((~Bko)&  Bku ); \
    Ako =   Bko ^((~Bku)&  Bka ); \
    Aku =   Bku ^((~Bka)&  Bke ); \
    Ebu ^= Du; \
    Bma = ROL64(Ebu, 27); \
    Ega ^= Da; \
    Bme = ROL64(Ega, 36); \
    Eke ^= De; \
    Bmi = ROL64(Eke, 10); \
    Emi ^= Di; \
    Bmo = ROL64(Emi, 15); \
    Eso ^= Do; \
    Bmu = ROL64(Eso, 56); \
    Ama =   Bma ^((~Bme)&  Bmi ); \
    Ame =   Bme ^((~Bmi)&  Bmo ); \
    Ami =   Bmi ^((~Bmo)&  Bmu ); \
    Amo =   Bmo ^((~Bmu)&  Bma ); \
    Amu =   Bmu ^((~Bma)&  Bme ); \
    Ebi ^= Di; \
    Bsa = ROL64(Ebi, 62); \
    Ego ^= Do; \
    Bse = ROL64(Ego, 55); \
    Eku ^= Du; \
    Bsi = ROL64(Eku, 39); \
    Ema ^= Da; \
    Bso = ROL64(Ema, 41); \
    Ese ^= De; \
    Bsu = ROL64(Ese, 2); \
    Asa =   Bsa ^((~Bse)&  Bsi ); \
    Ase =   Bse ^((~Bsi)&  Bso ); \
    Asi =   Bsi ^((~Bso)&  Bsu ); \
    Aso =   Bso ^((~Bsu)&  Bsa ); \
    Asu =   Bsu ^((~Bsa)&  Bse );
#endif

#define K12_security        128
#define K12_capacity        (2 * K12_security)
#define K12_capacityInBytes (K12_capacity / 8)
#define K12_rateInBytes     ((1600 - K12_capacity) / 8)
#define K12_chunkSize       8192
#define K12_suffixLeaf      0x0B

typedef struct
{
    unsigned char state[200];
    unsigned char byteIOIndex;

} KangarooTwelve_F;

static void KeccakP1600_Permute_12rounds(unsigned char* state)
{
#if AVX512
    __m512i Baeiou = _mm512_maskz_loadu_epi64(0x1F, state);
    __m512i Gaeiou = _mm512_maskz_loadu_epi64(0x1F, state + 40);
    __m512i Kaeiou = _mm512_maskz_loadu_epi64(0x1F, state + 80);
    __m512i Maeiou = _mm512_maskz_loadu_epi64(0x1F, state + 120);
    __m512i Saeiou = _mm512_maskz_loadu_epi64(0x1F, state + 160);
    __m512i b0, b1, b2, b3, b4, b5;

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst0);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst1);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst2);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst3);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst4);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst5);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst6);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst7);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst8);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst9);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst10);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst11);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    _mm512_mask_storeu_epi64(state, 0x1F, Baeiou);
    _mm512_mask_storeu_epi64(state + 40, 0x1F, Gaeiou);
    _mm512_mask_storeu_epi64(state + 80, 0x1F, Kaeiou);
    _mm512_mask_storeu_epi64(state + 120, 0x1F, Maeiou);
    _mm512_mask_storeu_epi64(state + 160, 0x1F, Saeiou);
#else
    declareABCDE
        unsigned long long* stateAsLanes = (unsigned long long*)state;
    copyFromState(stateAsLanes)
        rounds12
        copyToState(stateAsLanes)
#endif
}

static void KangarooTwelve_F_Absorb(KangarooTwelve_F* instance, unsigned char* data, unsigned long long dataByteLen)
{
    unsigned long long i = 0;
    while (i < dataByteLen)
    {
        if (!instance->byteIOIndex && dataByteLen >= i + K12_rateInBytes)
        {
#if AVX512
            __m512i Baeiou = _mm512_maskz_loadu_epi64(0x1F, instance->state);
            __m512i Gaeiou = _mm512_maskz_loadu_epi64(0x1F, instance->state + 40);
            __m512i Kaeiou = _mm512_maskz_loadu_epi64(0x1F, instance->state + 80);
            __m512i Maeiou = _mm512_maskz_loadu_epi64(0x1F, instance->state + 120);
            __m512i Saeiou = _mm512_maskz_loadu_epi64(0x1F, instance->state + 160);
#else
            declareABCDE
                unsigned long long* stateAsLanes = (unsigned long long*)instance->state;
            copyFromState(stateAsLanes)
#endif
                unsigned long long modifiedDataByteLen = dataByteLen - i;
            while (modifiedDataByteLen >= K12_rateInBytes)
            {
#if AVX512
                Baeiou = _mm512_xor_si512(Baeiou, _mm512_maskz_loadu_epi64(0x1F, data));
                Gaeiou = _mm512_xor_si512(Gaeiou, _mm512_maskz_loadu_epi64(0x1F, data + 40));
                Kaeiou = _mm512_xor_si512(Kaeiou, _mm512_maskz_loadu_epi64(0x1F, data + 80));
                Maeiou = _mm512_xor_si512(Maeiou, _mm512_maskz_loadu_epi64(0x1F, data + 120));
                Saeiou = _mm512_xor_si512(Saeiou, _mm512_maskz_loadu_epi64(0x01, data + 160));
                __m512i b0, b1, b2, b3, b4, b5;

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst0);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst1);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst2);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst3);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst4);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst5);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst6);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst7);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst8);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst9);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst10);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

                b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
                b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
                b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
                b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
                b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
                b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
                b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
                b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
                Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst11);
                Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
                Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
                Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
                Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
                b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
                b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
                b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
                b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
                Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
                Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
                Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
                Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
                Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);
#else
                Aba ^= ((unsigned long long*)data)[0];
                Abe ^= ((unsigned long long*)data)[1];
                Abi ^= ((unsigned long long*)data)[2];
                Abo ^= ((unsigned long long*)data)[3];
                Abu ^= ((unsigned long long*)data)[4];
                Aga ^= ((unsigned long long*)data)[5];
                Age ^= ((unsigned long long*)data)[6];
                Agi ^= ((unsigned long long*)data)[7];
                Ago ^= ((unsigned long long*)data)[8];
                Agu ^= ((unsigned long long*)data)[9];
                Aka ^= ((unsigned long long*)data)[10];
                Ake ^= ((unsigned long long*)data)[11];
                Aki ^= ((unsigned long long*)data)[12];
                Ako ^= ((unsigned long long*)data)[13];
                Aku ^= ((unsigned long long*)data)[14];
                Ama ^= ((unsigned long long*)data)[15];
                Ame ^= ((unsigned long long*)data)[16];
                Ami ^= ((unsigned long long*)data)[17];
                Amo ^= ((unsigned long long*)data)[18];
                Amu ^= ((unsigned long long*)data)[19];
                Asa ^= ((unsigned long long*)data)[20];
                rounds12
#endif
                    data += K12_rateInBytes;
                modifiedDataByteLen -= K12_rateInBytes;
            }
#if AVX512
            _mm512_mask_storeu_epi64(instance->state, 0x1F, Baeiou);
            _mm512_mask_storeu_epi64(instance->state + 40, 0x1F, Gaeiou);
            _mm512_mask_storeu_epi64(instance->state + 80, 0x1F, Kaeiou);
            _mm512_mask_storeu_epi64(instance->state + 120, 0x1F, Maeiou);
            _mm512_mask_storeu_epi64(instance->state + 160, 0x1F, Saeiou);
#else
            copyToState(stateAsLanes)
#endif
                i = dataByteLen - modifiedDataByteLen;
        }
        else
        {
            unsigned char partialBlock;
            if ((dataByteLen - i) + instance->byteIOIndex > K12_rateInBytes)
            {
                partialBlock = K12_rateInBytes - instance->byteIOIndex;
            }
            else
            {
                partialBlock = (unsigned char)(dataByteLen - i);
            }
            i += partialBlock;

            if (!instance->byteIOIndex)
            {
                unsigned int j = 0;
                for (; (j + 8) <= (unsigned int)(partialBlock >> 3); j += 8)
                {
                    ((unsigned long long*)instance->state)[j + 0] ^= ((unsigned long long*)data)[j + 0];
                    ((unsigned long long*)instance->state)[j + 1] ^= ((unsigned long long*)data)[j + 1];
                    ((unsigned long long*)instance->state)[j + 2] ^= ((unsigned long long*)data)[j + 2];
                    ((unsigned long long*)instance->state)[j + 3] ^= ((unsigned long long*)data)[j + 3];
                    ((unsigned long long*)instance->state)[j + 4] ^= ((unsigned long long*)data)[j + 4];
                    ((unsigned long long*)instance->state)[j + 5] ^= ((unsigned long long*)data)[j + 5];
                    ((unsigned long long*)instance->state)[j + 6] ^= ((unsigned long long*)data)[j + 6];
                    ((unsigned long long*)instance->state)[j + 7] ^= ((unsigned long long*)data)[j + 7];
                }
                for (; (j + 4) <= (unsigned int)(partialBlock >> 3); j += 4)
                {
                    ((unsigned long long*)instance->state)[j + 0] ^= ((unsigned long long*)data)[j + 0];
                    ((unsigned long long*)instance->state)[j + 1] ^= ((unsigned long long*)data)[j + 1];
                    ((unsigned long long*)instance->state)[j + 2] ^= ((unsigned long long*)data)[j + 2];
                    ((unsigned long long*)instance->state)[j + 3] ^= ((unsigned long long*)data)[j + 3];
                }
                for (; (j + 2) <= (unsigned int)(partialBlock >> 3); j += 2)
                {
                    ((unsigned long long*)instance->state)[j + 0] ^= ((unsigned long long*)data)[j + 0];
                    ((unsigned long long*)instance->state)[j + 1] ^= ((unsigned long long*)data)[j + 1];
                }
                if (j < (unsigned int)(partialBlock >> 3))
                {
                    ((unsigned long long*)instance->state)[j + 0] ^= ((unsigned long long*)data)[j + 0];
                }
                if (partialBlock & 7)
                {
                    unsigned long long lane = 0;
                    bs->CopyMem(&lane, data + (partialBlock & 0xFFFFFFF8), partialBlock & 7);
                    ((unsigned long long*)instance->state)[partialBlock >> 3] ^= lane;
                }
            }
            else
            {
                unsigned int _sizeLeft = partialBlock;
                unsigned int _lanePosition = instance->byteIOIndex >> 3;
                unsigned int _offsetInLane = instance->byteIOIndex & 7;
                const unsigned char* _curData = data;
                while (_sizeLeft > 0)
                {
                    unsigned int _bytesInLane = 8 - _offsetInLane;
                    if (_bytesInLane > _sizeLeft)
                    {
                        _bytesInLane = _sizeLeft;
                    }
                    if (_bytesInLane)
                    {
                        unsigned long long lane = 0;
                        bs->CopyMem(&lane, (void*)_curData, _bytesInLane);
                        ((unsigned long long*)instance->state)[_lanePosition] ^= (lane << (_offsetInLane << 3));
                    }
                    _sizeLeft -= _bytesInLane;
                    _lanePosition++;
                    _offsetInLane = 0;
                    _curData += _bytesInLane;
                }
            }

            data += partialBlock;
            instance->byteIOIndex += partialBlock;
            if (instance->byteIOIndex == K12_rateInBytes)
            {
                KeccakP1600_Permute_12rounds(instance->state);
                instance->byteIOIndex = 0;
            }
        }
    }
}

static void KangarooTwelve(unsigned char* input, unsigned int inputByteLen, unsigned char* output, unsigned int outputByteLen)
{
    KangarooTwelve_F queueNode;
    KangarooTwelve_F finalNode;
    unsigned int blockNumber, queueAbsorbedLen;

    bs->SetMem(&finalNode, sizeof(KangarooTwelve_F), 0);
    const unsigned int len = inputByteLen ^ ((K12_chunkSize ^ inputByteLen) & -(K12_chunkSize < inputByteLen));
    KangarooTwelve_F_Absorb(&finalNode, input, len);
    input += len;
    inputByteLen -= len;
    if (len == K12_chunkSize && inputByteLen)
    {
        blockNumber = 1;
        queueAbsorbedLen = 0;
        finalNode.state[finalNode.byteIOIndex] ^= 0x03;
        if (++finalNode.byteIOIndex == K12_rateInBytes)
        {
            KeccakP1600_Permute_12rounds(finalNode.state);
            finalNode.byteIOIndex = 0;
        }
        else
        {
            finalNode.byteIOIndex = (finalNode.byteIOIndex + 7) & ~7;
        }

        while (inputByteLen > 0)
        {
            const unsigned int len = K12_chunkSize ^ ((inputByteLen ^ K12_chunkSize) & -(inputByteLen < K12_chunkSize));
            bs->SetMem(&queueNode, sizeof(KangarooTwelve_F), 0);
            KangarooTwelve_F_Absorb(&queueNode, input, len);
            input += len;
            inputByteLen -= len;
            if (len == K12_chunkSize)
            {
                ++blockNumber;
                queueNode.state[queueNode.byteIOIndex] ^= K12_suffixLeaf;
                queueNode.state[K12_rateInBytes - 1] ^= 0x80;
                KeccakP1600_Permute_12rounds(queueNode.state);
                queueNode.byteIOIndex = K12_capacityInBytes;
                KangarooTwelve_F_Absorb(&finalNode, queueNode.state, K12_capacityInBytes);
            }
            else
            {
                queueAbsorbedLen = len;
            }
        }

        if (queueAbsorbedLen)
        {
            if (++queueNode.byteIOIndex == K12_rateInBytes)
            {
                KeccakP1600_Permute_12rounds(queueNode.state);
                queueNode.byteIOIndex = 0;
            }
            if (++queueAbsorbedLen == K12_chunkSize)
            {
                ++blockNumber;
                queueAbsorbedLen = 0;
                queueNode.state[queueNode.byteIOIndex] ^= K12_suffixLeaf;
                queueNode.state[K12_rateInBytes - 1] ^= 0x80;
                KeccakP1600_Permute_12rounds(queueNode.state);
                queueNode.byteIOIndex = K12_capacityInBytes;
                KangarooTwelve_F_Absorb(&finalNode, queueNode.state, K12_capacityInBytes);
            }
        }
        else
        {
            bs->SetMem(queueNode.state, sizeof(queueNode.state), 0);
            queueNode.byteIOIndex = 1;
            queueAbsorbedLen = 1;
        }
    }
    else
    {
        if (len == K12_chunkSize)
        {
            blockNumber = 1;
            finalNode.state[finalNode.byteIOIndex] ^= 0x03;
            if (++finalNode.byteIOIndex == K12_rateInBytes)
            {
                KeccakP1600_Permute_12rounds(finalNode.state);
                finalNode.byteIOIndex = 0;
            }
            else
            {
                finalNode.byteIOIndex = (finalNode.byteIOIndex + 7) & ~7;
            }

            bs->SetMem(queueNode.state, sizeof(queueNode.state), 0);
            queueNode.byteIOIndex = 1;
            queueAbsorbedLen = 1;
        }
        else
        {
            blockNumber = 0;
            if (++finalNode.byteIOIndex == K12_rateInBytes)
            {
                KeccakP1600_Permute_12rounds(finalNode.state);
                finalNode.state[0] ^= 0x07;
            }
            else
            {
                finalNode.state[finalNode.byteIOIndex] ^= 0x07;
            }
        }
    }

    if (blockNumber)
    {
        if (queueAbsorbedLen)
        {
            blockNumber++;
            queueNode.state[queueNode.byteIOIndex] ^= K12_suffixLeaf;
            queueNode.state[K12_rateInBytes - 1] ^= 0x80;
            KeccakP1600_Permute_12rounds(queueNode.state);
            KangarooTwelve_F_Absorb(&finalNode, queueNode.state, K12_capacityInBytes);
        }
        unsigned int n = 0;
        for (unsigned long long v = --blockNumber; v && (n < sizeof(unsigned long long)); ++n, v >>= 8)
        {
        }
        unsigned char encbuf[sizeof(unsigned long long) + 1 + 2];
        for (unsigned int i = 1; i <= n; ++i)
        {
            encbuf[i - 1] = (unsigned char)(blockNumber >> (8 * (n - i)));
        }
        encbuf[n] = (unsigned char)n;
        encbuf[++n] = 0xFF;
        encbuf[++n] = 0xFF;
        KangarooTwelve_F_Absorb(&finalNode, encbuf, ++n);
        finalNode.state[finalNode.byteIOIndex] ^= 0x06;
    }
    finalNode.state[K12_rateInBytes - 1] ^= 0x80;
    KeccakP1600_Permute_12rounds(finalNode.state);
    bs->CopyMem(output, finalNode.state, outputByteLen);
}

static void KangarooTwelve64To32(unsigned char* input, unsigned char* output)
{
#if AVX512
    __m512i Baeiou = _mm512_maskz_loadu_epi64(0x1F, input);
    __m512i Gaeiou = _mm512_set_epi64(0, 0, 0, 0, 0x0700, ((unsigned long long*)input)[7], ((unsigned long long*)input)[6], ((unsigned long long*)input)[5]);

    __m512i b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, zero, 0x96), zero, padding, 0x96);
    __m512i b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    __m512i b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(zero, b0, b1, 0x96), rhoK));
    __m512i b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(zero, b0, b1, 0x96), rhoM));
    __m512i b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(padding, b0, b1, 0x96), rhoS));
    __m512i b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst0);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    __m512i Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    __m512i Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    __m512i Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst1);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst2);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst3);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst4);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst5);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst6);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst7);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst8);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst9);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));
    Baeiou = _mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst10);
    Gaeiou = _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2);
    Kaeiou = _mm512_ternarylogic_epi64(b2, b3, b4, 0xD2);
    Maeiou = _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2);
    Saeiou = _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2);
    b0 = _mm512_permutex2var_epi64(_mm512_unpacklo_epi64(Baeiou, Gaeiou), pi2S1, Saeiou);
    b2 = _mm512_permutex2var_epi64(_mm512_unpackhi_epi64(Baeiou, Gaeiou), pi2S2, Saeiou);
    b1 = _mm512_unpacklo_epi64(Kaeiou, Maeiou);
    b3 = _mm512_unpackhi_epi64(Kaeiou, Maeiou);
    Baeiou = _mm512_permutex2var_epi64(b0, pi2BG, b1);
    Gaeiou = _mm512_permutex2var_epi64(b2, pi2BG, b3);
    Kaeiou = _mm512_permutex2var_epi64(b0, pi2KM, b1);
    Maeiou = _mm512_permutex2var_epi64(b2, pi2KM, b3);
    Saeiou = _mm512_mask_blend_epi64(0x10, _mm512_permutex2var_epi64(b0, pi2S3, b1), Saeiou);

    b0 = _mm512_ternarylogic_epi64(_mm512_ternarylogic_epi64(Baeiou, Gaeiou, Kaeiou, 0x96), Maeiou, Saeiou, 0x96);
    b1 = _mm512_permutexvar_epi64(moveThetaPrev, b0);
    b0 = _mm512_rol_epi64(_mm512_permutexvar_epi64(moveThetaNext, b0), 1);
    b2 = _mm512_permutexvar_epi64(pi1K, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Kaeiou, b0, b1, 0x96), rhoK));
    b3 = _mm512_permutexvar_epi64(pi1M, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Maeiou, b0, b1, 0x96), rhoM));
    b4 = _mm512_permutexvar_epi64(pi1S, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Saeiou, b0, b1, 0x96), rhoS));
    b5 = _mm512_permutexvar_epi64(pi1G, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Gaeiou, b0, b1, 0x96), rhoG));
    b0 = _mm512_permutexvar_epi64(pi1B, _mm512_rolv_epi64(_mm512_ternarylogic_epi64(Baeiou, b0, b1, 0x96), rhoB));

    _mm512_mask_storeu_epi64(output, 0xF, _mm512_permutex2var_epi64(_mm512_permutex2var_epi64(_mm512_unpacklo_epi64(_mm512_xor_si512(_mm512_ternarylogic_epi64(b0, b5, b2, 0xD2), K12RoundConst11), _mm512_ternarylogic_epi64(b5, b2, b3, 0xD2)), pi2S1, _mm512_ternarylogic_epi64(b4, b0, b5, 0xD2)), pi2BG, _mm512_unpacklo_epi64(_mm512_ternarylogic_epi64(b2, b3, b4, 0xD2), _mm512_ternarylogic_epi64(b3, b4, b0, 0xD2))));
#else
    unsigned long long Aba, Abe, Abi, Abo, Abu;
    unsigned long long Aga, Age, Agi, Ago, Agu;
    unsigned long long Aka, Ake, Aki, Ako, Aku;
    unsigned long long Ama, Ame, Ami, Amo, Amu;
    unsigned long long Asa, Ase, Asi, Aso, Asu;
    unsigned long long Bba, Bbe, Bbi, Bbo, Bbu;
    unsigned long long Bga, Bge, Bgi, Bgo, Bgu;
    unsigned long long Bka, Bke, Bki, Bko, Bku;
    unsigned long long Bma, Bme, Bmi, Bmo, Bmu;
    unsigned long long Bsa, Bse, Bsi, Bso, Bsu;
    unsigned long long Ca, Ce, Ci, Co, Cu;
    unsigned long long Da, De, Di, Do, Du;
    unsigned long long Eba, Ebe, Ebi, Ebo, Ebu;
    unsigned long long Ega, Ege, Egi, Ego, Egu;
    unsigned long long Eka, Eke, Eki, Eko, Eku;
    unsigned long long Ema, Eme, Emi, Emo, Emu;
    unsigned long long Esa, Ese, Esi, Eso, Esu;

    Ca = ((unsigned long long*)input)[0] ^ ((unsigned long long*)input)[5] ^ 0x8000000000000000;
    Ce = ((unsigned long long*)input)[1] ^ ((unsigned long long*)input)[6];
    Ci = ((unsigned long long*)input)[2] ^ ((unsigned long long*)input)[7];
    Co = ((unsigned long long*)input)[3] ^ 0x0700;

    Da = ((unsigned long long*)input)[4] ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(((unsigned long long*)input)[4], 1);
    Du = Co ^ ROL64(Ca, 1);
    Aba = ((unsigned long long*)input)[0] ^ Da;
    Bbe = ROL64(((unsigned long long*)input)[6] ^ De, 44);
    Bbi = ROL64(Di, 43);
    Bbo = ROL64(Do, 21);
    Bbu = ROL64(Du, 14);
    Eba = Aba ^ _andn_u64(Bbe, Bbi) ^ 0x000000008000808bULL;
    Ebe = Bbe ^ _andn_u64(Bbi, Bbo);
    Ebi = Bbi ^ _andn_u64(Bbo, Bbu);
    Ebo = Bbo ^ _andn_u64(Bbu, Aba);
    Ebu = Bbu ^ _andn_u64(Aba, Bbe);
    Bga = ROL64(((unsigned long long*)input)[3] ^ Do, 28);
    Bge = ROL64(Du, 20);
    Bgi = ROL64(Da, 3);
    Bgo = ROL64(De, 45);
    Bgu = ROL64(Di, 61);
    Ega = Bga ^ _andn_u64(Bge, Bgi);
    Ege = Bge ^ _andn_u64(Bgi, Bgo);
    Egi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ego = Bgo ^ _andn_u64(Bgu, Bga);
    Egu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(((unsigned long long*)input)[1] ^ De, 1);
    Bke = ROL64(((unsigned long long*)input)[7] ^ Di, 6);
    Bki = ROL64(Do, 25);
    Bko = ROL64(Du, 8);
    Bku = ROL64(Da ^ 0x8000000000000000, 18);
    Eka = Bka ^ _andn_u64(Bke, Bki);
    Eke = Bke ^ _andn_u64(Bki, Bko);
    Eki = Bki ^ _andn_u64(Bko, Bku);
    Eko = Bko ^ _andn_u64(Bku, Bka);
    Eku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(((unsigned long long*)input)[4] ^ Du, 27);
    Bme = ROL64(((unsigned long long*)input)[5] ^ Da, 36);
    Bmi = ROL64(De, 10);
    Bmo = ROL64(Di, 15);
    Bmu = ROL64(Do, 56);
    Ema = Bma ^ _andn_u64(Bme, Bmi);
    Eme = Bme ^ _andn_u64(Bmi, Bmo);
    Emi = Bmi ^ _andn_u64(Bmo, Bmu);
    Emo = Bmo ^ _andn_u64(Bmu, Bma);
    Emu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(((unsigned long long*)input)[2] ^ Di, 62);
    Bse = ROL64(Do ^ 0x0700, 55);
    Bsi = ROL64(Du, 39);
    Bso = ROL64(Da, 41);
    Bsu = ROL64(De, 2);
    Esa = Bsa ^ _andn_u64(Bse, Bsi);
    Ese = Bse ^ _andn_u64(Bsi, Bso);
    Esi = Bsi ^ _andn_u64(Bso, Bsu);
    Eso = Bso ^ _andn_u64(Bsu, Bsa);
    Esu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Eba ^= Da;
    Bbe = ROL64(Ege ^ De, 44);
    Bbi = ROL64(Eki ^ Di, 43);
    Bbo = ROL64(Emo ^ Do, 21);
    Bbu = ROL64(Esu ^ Du, 14);
    Aba = Eba ^ _andn_u64(Bbe, Bbi) ^ 0x800000000000008bULL;
    Abe = Bbe ^ _andn_u64(Bbi, Bbo);
    Abi = Bbi ^ _andn_u64(Bbo, Bbu);
    Abo = Bbo ^ _andn_u64(Bbu, Eba);
    Abu = Bbu ^ _andn_u64(Eba, Bbe);
    Bga = ROL64(Ebo ^ Do, 28);
    Bge = ROL64(Egu ^ Du, 20);
    Bgi = ROL64(Eka ^ Da, 3);
    Bgo = ROL64(Eme ^ De, 45);
    Bgu = ROL64(Esi ^ Di, 61);
    Aga = Bga ^ _andn_u64(Bge, Bgi);
    Age = Bge ^ _andn_u64(Bgi, Bgo);
    Agi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ago = Bgo ^ _andn_u64(Bgu, Bga);
    Agu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Ebe ^ De, 1);
    Bke = ROL64(Egi ^ Di, 6);
    Bki = ROL64(Eko ^ Do, 25);
    Bko = ROL64(Emu ^ Du, 8);
    Bku = ROL64(Esa ^ Da, 18);
    Aka = Bka ^ _andn_u64(Bke, Bki);
    Ake = Bke ^ _andn_u64(Bki, Bko);
    Aki = Bki ^ _andn_u64(Bko, Bku);
    Ako = Bko ^ _andn_u64(Bku, Bka);
    Aku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Ebu ^ Du, 27);
    Bme = ROL64(Ega ^ Da, 36);
    Bmi = ROL64(Eke ^ De, 10);
    Bmo = ROL64(Emi ^ Di, 15);
    Bmu = ROL64(Eso ^ Do, 56);
    Ama = Bma ^ _andn_u64(Bme, Bmi);
    Ame = Bme ^ _andn_u64(Bmi, Bmo);
    Ami = Bmi ^ _andn_u64(Bmo, Bmu);
    Amo = Bmo ^ _andn_u64(Bmu, Bma);
    Amu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Ebi ^ Di, 62);
    Bse = ROL64(Ego ^ Do, 55);
    Bsi = ROL64(Eku ^ Du, 39);
    Bso = ROL64(Ema ^ Da, 41);
    Bsu = ROL64(Ese ^ De, 2);
    Asa = Bsa ^ _andn_u64(Bse, Bsi);
    Ase = Bse ^ _andn_u64(Bsi, Bso);
    Asi = Bsi ^ _andn_u64(Bso, Bsu);
    Aso = Bso ^ _andn_u64(Bsu, Bsa);
    Asu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Aba ^= Da;
    Bbe = ROL64(Age ^ De, 44);
    Bbi = ROL64(Aki ^ Di, 43);
    Bbo = ROL64(Amo ^ Do, 21);
    Bbu = ROL64(Asu ^ Du, 14);
    Eba = Aba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000000008089ULL;
    Ebe = Bbe ^ _andn_u64(Bbi, Bbo);
    Ebi = Bbi ^ _andn_u64(Bbo, Bbu);
    Ebo = Bbo ^ _andn_u64(Bbu, Aba);
    Ebu = Bbu ^ _andn_u64(Aba, Bbe);
    Bga = ROL64(Abo ^ Do, 28);
    Bge = ROL64(Agu ^ Du, 20);
    Bgi = ROL64(Aka ^ Da, 3);
    Bgo = ROL64(Ame ^ De, 45);
    Bgu = ROL64(Asi ^ Di, 61);
    Ega = Bga ^ _andn_u64(Bge, Bgi);
    Ege = Bge ^ _andn_u64(Bgi, Bgo);
    Egi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ego = Bgo ^ _andn_u64(Bgu, Bga);
    Egu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Abe ^ De, 1);
    Bke = ROL64(Agi ^ Di, 6);
    Bki = ROL64(Ako ^ Do, 25);
    Bko = ROL64(Amu ^ Du, 8);
    Bku = ROL64(Asa ^ Da, 18);
    Eka = Bka ^ _andn_u64(Bke, Bki);
    Eke = Bke ^ _andn_u64(Bki, Bko);
    Eki = Bki ^ _andn_u64(Bko, Bku);
    Eko = Bko ^ _andn_u64(Bku, Bka);
    Eku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Abu ^ Du, 27);
    Bme = ROL64(Aga ^ Da, 36);
    Bmi = ROL64(Ake ^ De, 10);
    Bmo = ROL64(Ami ^ Di, 15);
    Bmu = ROL64(Aso ^ Do, 56);
    Ema = Bma ^ _andn_u64(Bme, Bmi);
    Eme = Bme ^ _andn_u64(Bmi, Bmo);
    Emi = Bmi ^ _andn_u64(Bmo, Bmu);
    Emo = Bmo ^ _andn_u64(Bmu, Bma);
    Emu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Abi ^ Di, 62);
    Bse = ROL64(Ago ^ Do, 55);
    Bsi = ROL64(Aku ^ Du, 39);
    Bso = ROL64(Ama ^ Da, 41);
    Bsu = ROL64(Ase ^ De, 2);
    Esa = Bsa ^ _andn_u64(Bse, Bsi);
    Ese = Bse ^ _andn_u64(Bsi, Bso);
    Esi = Bsi ^ _andn_u64(Bso, Bsu);
    Eso = Bso ^ _andn_u64(Bsu, Bsa);
    Esu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Eba ^= Da;
    Bbe = ROL64(Ege ^ De, 44);
    Bbi = ROL64(Eki ^ Di, 43);
    Bbo = ROL64(Emo ^ Do, 21);
    Bbu = ROL64(Esu ^ Du, 14);
    Aba = Eba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000000008003ULL;
    Abe = Bbe ^ _andn_u64(Bbi, Bbo);
    Abi = Bbi ^ _andn_u64(Bbo, Bbu);
    Abo = Bbo ^ _andn_u64(Bbu, Eba);
    Abu = Bbu ^ _andn_u64(Eba, Bbe);
    Bga = ROL64(Ebo ^ Do, 28);
    Bge = ROL64(Egu ^ Du, 20);
    Bgi = ROL64(Eka ^ Da, 3);
    Bgo = ROL64(Eme ^ De, 45);
    Bgu = ROL64(Esi ^ Di, 61);
    Aga = Bga ^ _andn_u64(Bge, Bgi);
    Age = Bge ^ _andn_u64(Bgi, Bgo);
    Agi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ago = Bgo ^ _andn_u64(Bgu, Bga);
    Agu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Ebe ^ De, 1);
    Bke = ROL64(Egi ^ Di, 6);
    Bki = ROL64(Eko ^ Do, 25);
    Bko = ROL64(Emu ^ Du, 8);
    Bku = ROL64(Esa ^ Da, 18);
    Aka = Bka ^ _andn_u64(Bke, Bki);
    Ake = Bke ^ _andn_u64(Bki, Bko);
    Aki = Bki ^ _andn_u64(Bko, Bku);
    Ako = Bko ^ _andn_u64(Bku, Bka);
    Aku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Ebu ^ Du, 27);
    Bme = ROL64(Ega ^ Da, 36);
    Bmi = ROL64(Eke ^ De, 10);
    Bmo = ROL64(Emi ^ Di, 15);
    Bmu = ROL64(Eso ^ Do, 56);
    Ama = Bma ^ _andn_u64(Bme, Bmi);
    Ame = Bme ^ _andn_u64(Bmi, Bmo);
    Ami = Bmi ^ _andn_u64(Bmo, Bmu);
    Amo = Bmo ^ _andn_u64(Bmu, Bma);
    Amu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Ebi ^ Di, 62);
    Bse = ROL64(Ego ^ Do, 55);
    Bsi = ROL64(Eku ^ Du, 39);
    Bso = ROL64(Ema ^ Da, 41);
    Bsu = ROL64(Ese ^ De, 2);
    Asa = Bsa ^ _andn_u64(Bse, Bsi);
    Ase = Bse ^ _andn_u64(Bsi, Bso);
    Asi = Bsi ^ _andn_u64(Bso, Bsu);
    Aso = Bso ^ _andn_u64(Bsu, Bsa);
    Asu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Aba ^= Da;
    Bbe = ROL64(Age ^ De, 44);
    Bbi = ROL64(Aki ^ Di, 43);
    Bbo = ROL64(Amo ^ Do, 21);
    Bbu = ROL64(Asu ^ Du, 14);
    Eba = Aba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000000008002ULL;
    Ebe = Bbe ^ _andn_u64(Bbi, Bbo);
    Ebi = Bbi ^ _andn_u64(Bbo, Bbu);
    Ebo = Bbo ^ _andn_u64(Bbu, Aba);
    Ebu = Bbu ^ _andn_u64(Aba, Bbe);
    Bga = ROL64(Abo ^ Do, 28);
    Bge = ROL64(Agu ^ Du, 20);
    Bgi = ROL64(Aka ^ Da, 3);
    Bgo = ROL64(Ame ^ De, 45);
    Bgu = ROL64(Asi ^ Di, 61);
    Ega = Bga ^ _andn_u64(Bge, Bgi);
    Ege = Bge ^ _andn_u64(Bgi, Bgo);
    Egi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ego = Bgo ^ _andn_u64(Bgu, Bga);
    Egu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Abe ^ De, 1);
    Bke = ROL64(Agi ^ Di, 6);
    Bki = ROL64(Ako ^ Do, 25);
    Bko = ROL64(Amu ^ Du, 8);
    Bku = ROL64(Asa ^ Da, 18);
    Eka = Bka ^ _andn_u64(Bke, Bki);
    Eke = Bke ^ _andn_u64(Bki, Bko);
    Eki = Bki ^ _andn_u64(Bko, Bku);
    Eko = Bko ^ _andn_u64(Bku, Bka);
    Eku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Abu ^ Du, 27);
    Bme = ROL64(Aga ^ Da, 36);
    Bmi = ROL64(Ake ^ De, 10);
    Bmo = ROL64(Ami ^ Di, 15);
    Bmu = ROL64(Aso ^ Do, 56);
    Ema = Bma ^ _andn_u64(Bme, Bmi);
    Eme = Bme ^ _andn_u64(Bmi, Bmo);
    Emi = Bmi ^ _andn_u64(Bmo, Bmu);
    Emo = Bmo ^ _andn_u64(Bmu, Bma);
    Emu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Abi ^ Di, 62);
    Bse = ROL64(Ago ^ Do, 55);
    Bsi = ROL64(Aku ^ Du, 39);
    Bso = ROL64(Ama ^ Da, 41);
    Bsu = ROL64(Ase ^ De, 2);
    Esa = Bsa ^ _andn_u64(Bse, Bsi);
    Ese = Bse ^ _andn_u64(Bsi, Bso);
    Esi = Bsi ^ _andn_u64(Bso, Bsu);
    Eso = Bso ^ _andn_u64(Bsu, Bsa);
    Esu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Eba ^= Da;
    Bbe = ROL64(Ege ^ De, 44);
    Bbi = ROL64(Eki ^ Di, 43);
    Bbo = ROL64(Emo ^ Do, 21);
    Bbu = ROL64(Esu ^ Du, 14);
    Aba = Eba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000000000080ULL;
    Abe = Bbe ^ _andn_u64(Bbi, Bbo);
    Abi = Bbi ^ _andn_u64(Bbo, Bbu);
    Abo = Bbo ^ _andn_u64(Bbu, Eba);
    Abu = Bbu ^ _andn_u64(Eba, Bbe);
    Bga = ROL64(Ebo ^ Do, 28);
    Bge = ROL64(Egu ^ Du, 20);
    Bgi = ROL64(Eka ^ Da, 3);
    Bgo = ROL64(Eme ^ De, 45);
    Bgu = ROL64(Esi ^ Di, 61);
    Aga = Bga ^ _andn_u64(Bge, Bgi);
    Age = Bge ^ _andn_u64(Bgi, Bgo);
    Agi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ago = Bgo ^ _andn_u64(Bgu, Bga);
    Agu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Ebe ^ De, 1);
    Bke = ROL64(Egi ^ Di, 6);
    Bki = ROL64(Eko ^ Do, 25);
    Bko = ROL64(Emu ^ Du, 8);
    Bku = ROL64(Esa ^ Da, 18);
    Aka = Bka ^ _andn_u64(Bke, Bki);
    Ake = Bke ^ _andn_u64(Bki, Bko);
    Aki = Bki ^ _andn_u64(Bko, Bku);
    Ako = Bko ^ _andn_u64(Bku, Bka);
    Aku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Ebu ^ Du, 27);
    Bme = ROL64(Ega ^ Da, 36);
    Bmi = ROL64(Eke ^ De, 10);
    Bmo = ROL64(Emi ^ Di, 15);
    Bmu = ROL64(Eso ^ Do, 56);
    Ama = Bma ^ _andn_u64(Bme, Bmi);
    Ame = Bme ^ _andn_u64(Bmi, Bmo);
    Ami = Bmi ^ _andn_u64(Bmo, Bmu);
    Amo = Bmo ^ _andn_u64(Bmu, Bma);
    Amu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Ebi ^ Di, 62);
    Bse = ROL64(Ego ^ Do, 55);
    Bsi = ROL64(Eku ^ Du, 39);
    Bso = ROL64(Ema ^ Da, 41);
    Bsu = ROL64(Ese ^ De, 2);
    Asa = Bsa ^ _andn_u64(Bse, Bsi);
    Ase = Bse ^ _andn_u64(Bsi, Bso);
    Asi = Bsi ^ _andn_u64(Bso, Bsu);
    Aso = Bso ^ _andn_u64(Bsu, Bsa);
    Asu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Aba ^= Da;
    Bbe = ROL64(Age ^ De, 44);
    Bbi = ROL64(Aki ^ Di, 43);
    Bbo = ROL64(Amo ^ Do, 21);
    Bbu = ROL64(Asu ^ Du, 14);
    Eba = Aba ^ _andn_u64(Bbe, Bbi) ^ 0x000000000000800aULL;
    Ebe = Bbe ^ _andn_u64(Bbi, Bbo);
    Ebi = Bbi ^ _andn_u64(Bbo, Bbu);
    Ebo = Bbo ^ _andn_u64(Bbu, Aba);
    Ebu = Bbu ^ _andn_u64(Aba, Bbe);
    Bga = ROL64(Abo ^ Do, 28);
    Bge = ROL64(Agu ^ Du, 20);
    Bgi = ROL64(Aka ^ Da, 3);
    Bgo = ROL64(Ame ^ De, 45);
    Bgu = ROL64(Asi ^ Di, 61);
    Ega = Bga ^ _andn_u64(Bge, Bgi);
    Ege = Bge ^ _andn_u64(Bgi, Bgo);
    Egi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ego = Bgo ^ _andn_u64(Bgu, Bga);
    Egu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Abe ^ De, 1);
    Bke = ROL64(Agi ^ Di, 6);
    Bki = ROL64(Ako ^ Do, 25);
    Bko = ROL64(Amu ^ Du, 8);
    Bku = ROL64(Asa ^ Da, 18);
    Eka = Bka ^ _andn_u64(Bke, Bki);
    Eke = Bke ^ _andn_u64(Bki, Bko);
    Eki = Bki ^ _andn_u64(Bko, Bku);
    Eko = Bko ^ _andn_u64(Bku, Bka);
    Eku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Abu ^ Du, 27);
    Bme = ROL64(Aga ^ Da, 36);
    Bmi = ROL64(Ake ^ De, 10);
    Bmo = ROL64(Ami ^ Di, 15);
    Bmu = ROL64(Aso ^ Do, 56);
    Ema = Bma ^ _andn_u64(Bme, Bmi);
    Eme = Bme ^ _andn_u64(Bmi, Bmo);
    Emi = Bmi ^ _andn_u64(Bmo, Bmu);
    Emo = Bmo ^ _andn_u64(Bmu, Bma);
    Emu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Abi ^ Di, 62);
    Bse = ROL64(Ago ^ Do, 55);
    Bsi = ROL64(Aku ^ Du, 39);
    Bso = ROL64(Ama ^ Da, 41);
    Bsu = ROL64(Ase ^ De, 2);
    Esa = Bsa ^ _andn_u64(Bse, Bsi);
    Ese = Bse ^ _andn_u64(Bsi, Bso);
    Esi = Bsi ^ _andn_u64(Bso, Bsu);
    Eso = Bso ^ _andn_u64(Bsu, Bsa);
    Esu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Eba ^= Da;
    Bbe = ROL64(Ege ^ De, 44);
    Bbi = ROL64(Eki ^ Di, 43);
    Bbo = ROL64(Emo ^ Do, 21);
    Bbu = ROL64(Esu ^ Du, 14);
    Aba = Eba ^ _andn_u64(Bbe, Bbi) ^ 0x800000008000000aULL;
    Abe = Bbe ^ _andn_u64(Bbi, Bbo);
    Abi = Bbi ^ _andn_u64(Bbo, Bbu);
    Abo = Bbo ^ _andn_u64(Bbu, Eba);
    Abu = Bbu ^ _andn_u64(Eba, Bbe);
    Bga = ROL64(Ebo ^ Do, 28);
    Bge = ROL64(Egu ^ Du, 20);
    Bgi = ROL64(Eka ^ Da, 3);
    Bgo = ROL64(Eme ^ De, 45);
    Bgu = ROL64(Esi ^ Di, 61);
    Aga = Bga ^ _andn_u64(Bge, Bgi);
    Age = Bge ^ _andn_u64(Bgi, Bgo);
    Agi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ago = Bgo ^ _andn_u64(Bgu, Bga);
    Agu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Ebe ^ De, 1);
    Bke = ROL64(Egi ^ Di, 6);
    Bki = ROL64(Eko ^ Do, 25);
    Bko = ROL64(Emu ^ Du, 8);
    Bku = ROL64(Esa ^ Da, 18);
    Aka = Bka ^ _andn_u64(Bke, Bki);
    Ake = Bke ^ _andn_u64(Bki, Bko);
    Aki = Bki ^ _andn_u64(Bko, Bku);
    Ako = Bko ^ _andn_u64(Bku, Bka);
    Aku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Ebu ^ Du, 27);
    Bme = ROL64(Ega ^ Da, 36);
    Bmi = ROL64(Eke ^ De, 10);
    Bmo = ROL64(Emi ^ Di, 15);
    Bmu = ROL64(Eso ^ Do, 56);
    Ama = Bma ^ _andn_u64(Bme, Bmi);
    Ame = Bme ^ _andn_u64(Bmi, Bmo);
    Ami = Bmi ^ _andn_u64(Bmo, Bmu);
    Amo = Bmo ^ _andn_u64(Bmu, Bma);
    Amu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Ebi ^ Di, 62);
    Bse = ROL64(Ego ^ Do, 55);
    Bsi = ROL64(Eku ^ Du, 39);
    Bso = ROL64(Ema ^ Da, 41);
    Bsu = ROL64(Ese ^ De, 2);
    Asa = Bsa ^ _andn_u64(Bse, Bsi);
    Ase = Bse ^ _andn_u64(Bsi, Bso);
    Asi = Bsi ^ _andn_u64(Bso, Bsu);
    Aso = Bso ^ _andn_u64(Bsu, Bsa);
    Asu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Aba ^= Da;
    Bbe = ROL64(Age ^ De, 44);
    Bbi = ROL64(Aki ^ Di, 43);
    Bbo = ROL64(Amo ^ Do, 21);
    Bbu = ROL64(Asu ^ Du, 14);
    Eba = Aba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000080008081ULL;
    Ebe = Bbe ^ _andn_u64(Bbi, Bbo);
    Ebi = Bbi ^ _andn_u64(Bbo, Bbu);
    Ebo = Bbo ^ _andn_u64(Bbu, Aba);
    Ebu = Bbu ^ _andn_u64(Aba, Bbe);
    Bga = ROL64(Abo ^ Do, 28);
    Bge = ROL64(Agu ^ Du, 20);
    Bgi = ROL64(Aka ^ Da, 3);
    Bgo = ROL64(Ame ^ De, 45);
    Bgu = ROL64(Asi ^ Di, 61);
    Ega = Bga ^ _andn_u64(Bge, Bgi);
    Ege = Bge ^ _andn_u64(Bgi, Bgo);
    Egi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ego = Bgo ^ _andn_u64(Bgu, Bga);
    Egu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Abe ^ De, 1);
    Bke = ROL64(Agi ^ Di, 6);
    Bki = ROL64(Ako ^ Do, 25);
    Bko = ROL64(Amu ^ Du, 8);
    Bku = ROL64(Asa ^ Da, 18);
    Eka = Bka ^ _andn_u64(Bke, Bki);
    Eke = Bke ^ _andn_u64(Bki, Bko);
    Eki = Bki ^ _andn_u64(Bko, Bku);
    Eko = Bko ^ _andn_u64(Bku, Bka);
    Eku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Abu ^ Du, 27);
    Bme = ROL64(Aga ^ Da, 36);
    Bmi = ROL64(Ake ^ De, 10);
    Bmo = ROL64(Ami ^ Di, 15);
    Bmu = ROL64(Aso ^ Do, 56);
    Ema = Bma ^ _andn_u64(Bme, Bmi);
    Eme = Bme ^ _andn_u64(Bmi, Bmo);
    Emi = Bmi ^ _andn_u64(Bmo, Bmu);
    Emo = Bmo ^ _andn_u64(Bmu, Bma);
    Emu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Abi ^ Di, 62);
    Bse = ROL64(Ago ^ Do, 55);
    Bsi = ROL64(Aku ^ Du, 39);
    Bso = ROL64(Ama ^ Da, 41);
    Bsu = ROL64(Ase ^ De, 2);
    Esa = Bsa ^ _andn_u64(Bse, Bsi);
    Ese = Bse ^ _andn_u64(Bsi, Bso);
    Esi = Bsi ^ _andn_u64(Bso, Bsu);
    Eso = Bso ^ _andn_u64(Bsu, Bsa);
    Esu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Eba ^= Da;
    Bbe = ROL64(Ege ^ De, 44);
    Bbi = ROL64(Eki ^ Di, 43);
    Bbo = ROL64(Emo ^ Do, 21);
    Bbu = ROL64(Esu ^ Du, 14);
    Aba = Eba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000000008080ULL;
    Abe = Bbe ^ _andn_u64(Bbi, Bbo);
    Abi = Bbi ^ _andn_u64(Bbo, Bbu);
    Abo = Bbo ^ _andn_u64(Bbu, Eba);
    Abu = Bbu ^ _andn_u64(Eba, Bbe);
    Bga = ROL64(Ebo ^ Do, 28);
    Bge = ROL64(Egu ^ Du, 20);
    Bgi = ROL64(Eka ^ Da, 3);
    Bgo = ROL64(Eme ^ De, 45);
    Bgu = ROL64(Esi ^ Di, 61);
    Aga = Bga ^ _andn_u64(Bge, Bgi);
    Age = Bge ^ _andn_u64(Bgi, Bgo);
    Agi = Bgi ^ _andn_u64(Bgo, Bgu);
    Ago = Bgo ^ _andn_u64(Bgu, Bga);
    Agu = Bgu ^ _andn_u64(Bga, Bge);
    Bka = ROL64(Ebe ^ De, 1);
    Bke = ROL64(Egi ^ Di, 6);
    Bki = ROL64(Eko ^ Do, 25);
    Bko = ROL64(Emu ^ Du, 8);
    Bku = ROL64(Esa ^ Da, 18);
    Aka = Bka ^ _andn_u64(Bke, Bki);
    Ake = Bke ^ _andn_u64(Bki, Bko);
    Aki = Bki ^ _andn_u64(Bko, Bku);
    Ako = Bko ^ _andn_u64(Bku, Bka);
    Aku = Bku ^ _andn_u64(Bka, Bke);
    Bma = ROL64(Ebu ^ Du, 27);
    Bme = ROL64(Ega ^ Da, 36);
    Bmi = ROL64(Eke ^ De, 10);
    Bmo = ROL64(Emi ^ Di, 15);
    Bmu = ROL64(Eso ^ Do, 56);
    Ama = Bma ^ _andn_u64(Bme, Bmi);
    Ame = Bme ^ _andn_u64(Bmi, Bmo);
    Ami = Bmi ^ _andn_u64(Bmo, Bmu);
    Amo = Bmo ^ _andn_u64(Bmu, Bma);
    Amu = Bmu ^ _andn_u64(Bma, Bme);
    Bsa = ROL64(Ebi ^ Di, 62);
    Bse = ROL64(Ego ^ Do, 55);
    Bsi = ROL64(Eku ^ Du, 39);
    Bso = ROL64(Ema ^ Da, 41);
    Bsu = ROL64(Ese ^ De, 2);
    Asa = Bsa ^ _andn_u64(Bse, Bsi);
    Ase = Bse ^ _andn_u64(Bsi, Bso);
    Asi = Bsi ^ _andn_u64(Bso, Bsu);
    Aso = Bso ^ _andn_u64(Bsu, Bsa);
    Asu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = Cu ^ ROL64(Ce, 1);
    De = Ca ^ ROL64(Ci, 1);
    Di = Ce ^ ROL64(Co, 1);
    Do = Ci ^ ROL64(Cu, 1);
    Du = Co ^ ROL64(Ca, 1);
    Bba = Aba ^ Da;
    Bbe = ROL64(Age ^ De, 44);
    Bbi = ROL64(Aki ^ Di, 43);
    Bbo = ROL64(Amo ^ Do, 21);
    Bbu = ROL64(Asu ^ Du, 14);
    Bga = ROL64(Abo ^ Do, 28);
    Bge = ROL64(Agu ^ Du, 20);
    Bgi = ROL64(Aka ^ Da, 3);
    Bgo = ROL64(Ame ^ De, 45);
    Bgu = ROL64(Asi ^ Di, 61);
    Bka = ROL64(Abe ^ De, 1);
    Bke = ROL64(Agi ^ Di, 6);
    Bki = ROL64(Ako ^ Do, 25);
    Bko = ROL64(Amu ^ Du, 8);
    Bku = ROL64(Asa ^ Da, 18);
    Bma = ROL64(Abu ^ Du, 27);
    Bme = ROL64(Aga ^ Da, 36);
    Bmi = ROL64(Ake ^ De, 10);
    Bmo = ROL64(Ami ^ Di, 15);
    Bmu = ROL64(Aso ^ Do, 56);
    Bsa = ROL64(Abi ^ Di, 62);
    Bse = ROL64(Ago ^ Do, 55);
    Bsi = ROL64(Aku ^ Du, 39);
    Bso = ROL64(Ama ^ Da, 41);
    Bsu = ROL64(Ase ^ De, 2);
    Eba = Bba ^ _andn_u64(Bbe, Bbi) ^ 0x0000000080000001ULL;
    Ege = Bge ^ _andn_u64(Bgi, Bgo);
    Eki = Bki ^ _andn_u64(Bko, Bku);
    Emo = Bmo ^ _andn_u64(Bmu, Bma);
    Esu = Bsu ^ _andn_u64(Bsa, Bse);
    Ca = Eba ^ Bga ^ Bka ^ Bma ^ Bsa ^ _andn_u64(Bge, Bgi) ^ _andn_u64(Bke, Bki) ^ _andn_u64(Bme, Bmi) ^ _andn_u64(Bse, Bsi);
    Ce = Bbe ^ Ege ^ Bke ^ Bme ^ Bse ^ _andn_u64(Bbi, Bbo) ^ _andn_u64(Bki, Bko) ^ _andn_u64(Bmi, Bmo) ^ _andn_u64(Bsi, Bso);
    Ci = Bbi ^ Bgi ^ Eki ^ Bmi ^ Bsi ^ _andn_u64(Bbo, Bbu) ^ _andn_u64(Bgo, Bgu) ^ _andn_u64(Bmo, Bmu) ^ _andn_u64(Bso, Bsu);
    Co = Bbo ^ Bgo ^ Bko ^ Emo ^ Bso ^ _andn_u64(Bbu, Bba) ^ _andn_u64(Bgu, Bga) ^ _andn_u64(Bku, Bka) ^ _andn_u64(Bsu, Bsa);
    Cu = Bbu ^ Bgu ^ Bku ^ Bmu ^ Esu ^ _andn_u64(Bba, Bbe) ^ _andn_u64(Bga, Bge) ^ _andn_u64(Bka, Bke) ^ _andn_u64(Bma, Bme);

    Bba = Eba ^ Cu ^ ROL64(Ce, 1);
    Bbe = ROL64(Ege ^ Ca ^ ROL64(Ci, 1), 44);
    Bbi = ROL64(Eki ^ Ce ^ ROL64(Co, 1), 43);
    Bbo = ROL64(Emo ^ Ci ^ ROL64(Cu, 1), 21);
    Bbu = ROL64(Esu ^ Co ^ ROL64(Ca, 1), 14);
    ((unsigned long long*)output)[0] = Bba ^ _andn_u64(Bbe, Bbi) ^ 0x8000000080008008ULL;
    ((unsigned long long*)output)[1] = Bbe ^ _andn_u64(Bbi, Bbo);
    ((unsigned long long*)output)[2] = Bbi ^ _andn_u64(Bbo, Bbu);
    ((unsigned long long*)output)[3] = Bbo ^ _andn_u64(Bbu, Bba);
#endif
}

void random(unsigned char* publicKey, unsigned char* nonce, unsigned char* output, unsigned int outputSize)
{
    unsigned char state[200];
    *((__m256i*) & state[0]) = *((__m256i*)publicKey);
    *((__m256i*) & state[32]) = *((__m256i*)nonce);
    bs->SetMem(&state[64], sizeof(state) - 64, 0);

    for (unsigned int i = 0; i < outputSize / sizeof(state); i++)
    {
        KeccakP1600_Permute_12rounds(state);
        bs->CopyMem(output, state, sizeof(state));
        output += sizeof(state);
    }
    if (outputSize % sizeof(state))
    {
        KeccakP1600_Permute_12rounds(state);
        bs->CopyMem(output, state, outputSize % sizeof(state));
    }
}

static unsigned long long miningData[65536];
static EFI_EVENT minerEvents[NUMBER_OF_MINING_PROCESSORS];
static unsigned short neuronLinks[NUMBER_OF_MINING_PROCESSORS][NUMBER_OF_NEURONS][2];
static unsigned char neuronValues[NUMBER_OF_MINING_PROCESSORS][NUMBER_OF_NEURONS];
static volatile long long numberOfMiningIterations = 0;
static unsigned short validationNeuronLinks[NUMBER_OF_NEURONS][2];
static unsigned char validationNeuronValues[NUMBER_OF_NEURONS];

typedef struct
{
    unsigned int size;
    unsigned short protocol;
    unsigned short type;
} RequestResponseHeader;

#define REQUEST_MINER_PUBLIC_KEY 21

#define RESPOND_MINER_PUBLIC_KEY 22

typedef struct
{
    unsigned char minerPublicKey[32];
} RespondMinerPublicKey;

#define RESPOND_RESOURCE_TESTING_SOLUTION 23

typedef struct
{
    unsigned char minerPublicKey[32];
    unsigned char nonce[32];
} RespondResourceTestingSolution;

const static __m256i ZERO = _mm256_setzero_si256();

static volatile char state = 0;

static unsigned long long miningData[65536];
static unsigned char minerPublicKey[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static unsigned char nonce[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static volatile long long numberOfMiningIterations = 0;
static volatile long long numberOfFoundSolutions = 0;

