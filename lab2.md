# Memory and Filesystems Template

## Q1. First download and extract the file evidence tar gz

- wget https://software.os3.nl/CCF/evidence.tar.gz
- wget https://software.os3.nl/CCF/evidence.tar.gz.sha512
- sha512sum evidence.tar.gz
- tar xzvf evidence.tar.gz
- sha256sum disk.img
- sha256sum memory.raw

## Q2. Read about Volatility and its features

- https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage

### a. What does Volatility do?

volatility extracts digital artifacts from samples of memory (RAM)

### b. Would Volatility be useful in the acquiring stage?

yes memdump / linux_dump_map can be used to acquire the resident memory pages

- https://www.andreafortuna.org/2017/07/10/volatility-my-own-cheatsheet-part-3-process-memory/

### c. What parts of Volatility would you use in your investigation on the acquired memory?

based on the output of imageinfo (see Q3), the Windows set of tools would be most appropriate for this image

- https://github.com/volatilityfoundation/volatility/wiki/Command-Reference

## Q3. Exactly identify the operating system that is running Note down the steps you take to detect this

- volatility imageinfo -f memory.raw
- volatility kdbgscan -f memory.raw --profile WinXPSP3x86
- based on the initial recommendation by imageinfo and the build string from kdbgscan, the image is probably from Windows XP Service Pack x86

```
root@caine:/local/ccf# volatility imageinfo -f memory.raw
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/local/ccf/memory.raw)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cf60L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2017-02-12 13:37:02 UTC+0000
     Image local date and time : 2017-02-12 14:37:02 +0100
```

```
root@caine:/local/ccf# volatility kdbgscan -f memory.raw --profile WinXPSP3x86
Volatility Foundation Volatility Framework 2.6
**************************************************
Instantiating KDBG using: Kernel AS WinXPSP3x86 (5.1.0 32bit)
Offset (V)                    : 0x8054cf60
Offset (P)                    : 0x54cf60
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): WinXPSP3x86
Version64                     : 0x8054cf38 (Major: 15, Minor: 2600)
Service Pack (CmNtCSDVersion) : 3
Build string (NtBuildLab)     : 2600.xpsp_sp3_qfe.130704-0421
PsActiveProcessHead           : 0x805614d8 (34 processes)
PsLoadedModuleList            : 0x8055b340 (117 modules)
KernelBase                    : 0x804d7000 (Matches MZ: True)
Major (OptionalHeader)        : 5
Minor (OptionalHeader)        : 1
KPCR                          : 0xffdff000 (CPU 0)

**************************************************
Instantiating KDBG using: Kernel AS WinXPSP3x86 (5.1.0 32bit)
Offset (V)                    : 0x8054cf60
Offset (P)                    : 0x54cf60
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): WinXPSP2x86
Version64                     : 0x8054cf38 (Major: 15, Minor: 2600)
Service Pack (CmNtCSDVersion) : 3
Build string (NtBuildLab)     : 2600.xpsp_sp3_qfe.130704-0421
PsActiveProcessHead           : 0x805614d8 (34 processes)
PsLoadedModuleList            : 0x8055b340 (117 modules)
KernelBase                    : 0x804d7000 (Matches MZ: True)
Major (OptionalHeader)        : 5
Minor (OptionalHeader)        : 1
KPCR                          : 0xffdff000 (CPU 0)
```

## Q4. Find out if there is any malware running on the computer

- malfind identified several sections of suspicious memory
- none of these were recognized by virustotal
- an antivirus program is already active, unless it is some new, unrecognized malware or explicitly whitelisted the user, I assume there is no malware running.

<spoiler|malfind>

```
root@caine:/local/ccf# volatility malfind -f memory.raw -D malware
Volatility Foundation Volatility Framework 2.6
Process: csrss.exe Pid: 560 Address: 0x7f6f0000
Vad Tag: Vad  Protection: PAGE_EXECUTE_READWRITE
Flags: Protection: 6

0x7f6f0000  c8 00 00 00 8d 01 00 00 ff ee ff ee 08 70 00 00   .............p..
0x7f6f0010  08 00 00 00 00 fe 00 00 00 00 10 00 00 20 00 00   ................
0x7f6f0020  00 02 00 00 00 20 00 00 8d 01 00 00 ff ef fd 7f   ................
0x7f6f0030  03 00 08 06 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x7f6f0000 c8000000         ENTER 0x0, 0x0
0x7f6f0004 8d01             LEA EAX, [ECX]
0x7f6f0006 0000             ADD [EAX], AL
0x7f6f0008 ff               DB 0xff
0x7f6f0009 ee               OUT DX, AL
0x7f6f000a ff               DB 0xff
0x7f6f000b ee               OUT DX, AL
0x7f6f000c 087000           OR [EAX+0x0], DH
0x7f6f000f 0008             ADD [EAX], CL
0x7f6f0011 0000             ADD [EAX], AL
0x7f6f0013 0000             ADD [EAX], AL
0x7f6f0015 fe00             INC BYTE [EAX]
0x7f6f0017 0000             ADD [EAX], AL
0x7f6f0019 0010             ADD [EAX], DL
0x7f6f001b 0000             ADD [EAX], AL
0x7f6f001d 2000             AND [EAX], AL
0x7f6f001f 0000             ADD [EAX], AL
0x7f6f0021 0200             ADD AL, [EAX]
0x7f6f0023 0000             ADD [EAX], AL
0x7f6f0025 2000             AND [EAX], AL
0x7f6f0027 008d010000ff     ADD [EBP-0xffffff], CL
0x7f6f002d ef               OUT DX, EAX
0x7f6f002e fd               STD
0x7f6f002f 7f03             JG 0x7f6f0034
0x7f6f0031 0008             ADD [EAX], CL
0x7f6f0033 06               PUSH ES
0x7f6f0034 0000             ADD [EAX], AL
0x7f6f0036 0000             ADD [EAX], AL
0x7f6f0038 0000             ADD [EAX], AL
0x7f6f003a 0000             ADD [EAX], AL
0x7f6f003c 0000             ADD [EAX], AL
0x7f6f003e 0000             ADD [EAX], AL

Process: IEXPLORE.EXE Pid: 552 Address: 0x5fff0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 16, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x5fff0000  64 74 72 52 00 00 00 00 20 03 ff 5f 00 00 00 00   dtrR......._....
0x5fff0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x5fff0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x5fff0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x5fff0000 647472           JZ 0x5fff0075
0x5fff0003 52               PUSH EDX
0x5fff0004 0000             ADD [EAX], AL
0x5fff0006 0000             ADD [EAX], AL
0x5fff0008 2003             AND [EBX], AL
0x5fff000a ff5f00           CALL FAR DWORD [EDI+0x0]
0x5fff000d 0000             ADD [EAX], AL
0x5fff000f 0000             ADD [EAX], AL
0x5fff0011 0000             ADD [EAX], AL
0x5fff0013 0000             ADD [EAX], AL
0x5fff0015 0000             ADD [EAX], AL
0x5fff0017 0000             ADD [EAX], AL
0x5fff0019 0000             ADD [EAX], AL
0x5fff001b 0000             ADD [EAX], AL
0x5fff001d 0000             ADD [EAX], AL
0x5fff001f 0000             ADD [EAX], AL
0x5fff0021 0000             ADD [EAX], AL
0x5fff0023 0000             ADD [EAX], AL
0x5fff0025 0000             ADD [EAX], AL
0x5fff0027 0000             ADD [EAX], AL
0x5fff0029 0000             ADD [EAX], AL
0x5fff002b 0000             ADD [EAX], AL
0x5fff002d 0000             ADD [EAX], AL
0x5fff002f 0000             ADD [EAX], AL
0x5fff0031 0000             ADD [EAX], AL
0x5fff0033 0000             ADD [EAX], AL
0x5fff0035 0000             ADD [EAX], AL
0x5fff0037 0000             ADD [EAX], AL
0x5fff0039 0000             ADD [EAX], AL
0x5fff003b 0000             ADD [EAX], AL
0x5fff003d 0000             ADD [EAX], AL
0x5fff003f 00               DB 0x0

Process: IEXPLORE.EXE Pid: 1996 Address: 0x3960000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x03960000  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x03960010  0f b6 05 00 00 96 03 85 c0 74 05 e9 4d ff c6 ff   .........t..M...
0x03960020  e9 c9 88 98 3a 00 00 00 00 00 00 00 00 00 00 00   ....:...........
0x03960030  0f b6 05 00 00 96 03 85 c0 74 05 e9 b5 e1 ba ff   .........t......

0x03960000 0100             ADD [EAX], EAX
0x03960002 0000             ADD [EAX], AL
0x03960004 0000             ADD [EAX], AL
0x03960006 0000             ADD [EAX], AL
0x03960008 0000             ADD [EAX], AL
0x0396000a 0000             ADD [EAX], AL
0x0396000c 0000             ADD [EAX], AL
0x0396000e 0000             ADD [EAX], AL
0x03960010 0fb60500009603   MOVZX EAX, BYTE [0x3960000]
0x03960017 85c0             TEST EAX, EAX
0x03960019 7405             JZ 0x3960020
0x0396001b e94dffc6ff       JMP 0x35cff6d
0x03960020 e9c988983a       JMP 0x3e2e88ee
0x03960025 0000             ADD [EAX], AL
0x03960027 0000             ADD [EAX], AL
0x03960029 0000             ADD [EAX], AL
0x0396002b 0000             ADD [EAX], AL
0x0396002d 0000             ADD [EAX], AL
0x0396002f 000f             ADD [EDI], CL
0x03960031 b605             MOV DH, 0x5
0x03960033 0000             ADD [EAX], AL
0x03960035 96               XCHG ESI, EAX
0x03960036 0385c07405e9     ADD EAX, [EBP-0x16fa8b40]
0x0396003c b5e1             MOV CH, 0xe1
0x0396003e ba               DB 0xba
0x0396003f ff               DB 0xff

Process: IEXPLORE.EXE Pid: 1996 Address: 0x38620000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 11, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x38620000  01 00 00 00 00 00 00 00 35 5c 91 7c 10 db 00 10   ........5\.|....
0x38620010  d8 67 02 10 03 00 00 00 05 00 00 00 68 6c 02 00   .g..........hl..
0x38620020  00 e9 14 5c 2f 44 00 00 00 00 00 00 00 00 00 00   ...\/D..........
0x38620030  05 00 00 00 68 6c 02 00 00 68 88 5d 91 7c e9 fc   ....hl...h.].|..

0x38620000 0100             ADD [EAX], EAX
0x38620002 0000             ADD [EAX], AL
0x38620004 0000             ADD [EAX], AL
0x38620006 0000             ADD [EAX], AL
0x38620008 355c917c10       XOR EAX, 0x107c915c
0x3862000d db00             FILD DWORD [EAX]
0x3862000f 10d8             ADC AL, BL
0x38620011 670210           ADD DL, [BX+SI]
0x38620014 0300             ADD EAX, [EAX]
0x38620016 0000             ADD [EAX], AL
0x38620018 0500000068       ADD EAX, 0x68000000
0x3862001d 6c               INS BYTE [ES:EDI], DX
0x3862001e 0200             ADD AL, [EAX]
0x38620020 00e9             ADD CL, CH
0x38620022 145c             ADC AL, 0x5c
0x38620024 2f               DAS
0x38620025 44               INC ESP
0x38620026 0000             ADD [EAX], AL
0x38620028 0000             ADD [EAX], AL
0x3862002a 0000             ADD [EAX], AL
0x3862002c 0000             ADD [EAX], AL
0x3862002e 0000             ADD [EAX], AL
0x38620030 0500000068       ADD EAX, 0x68000000
0x38620035 6c               INS BYTE [ES:EDI], DX
0x38620036 0200             ADD AL, [EAX]
0x38620038 006888           ADD [EAX-0x78], CH
0x3862003b 5d               POP EBP
0x3862003c 91               XCHG ECX, EAX
0x3862003d 7ce9             JL 0x38620028
0x3862003f fc               CLD

Process: IEXPLORE.EXE Pid: 1996 Address: 0x5fff0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 16, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x5fff0000  64 74 72 52 00 00 00 00 20 03 ff 5f 00 00 00 00   dtrR......._....
0x5fff0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x5fff0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x5fff0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x5fff0000 647472           JZ 0x5fff0075
0x5fff0003 52               PUSH EDX
0x5fff0004 0000             ADD [EAX], AL
0x5fff0006 0000             ADD [EAX], AL
0x5fff0008 2003             AND [EBX], AL
0x5fff000a ff5f00           CALL FAR DWORD [EDI+0x0]
0x5fff000d 0000             ADD [EAX], AL
0x5fff000f 0000             ADD [EAX], AL
0x5fff0011 0000             ADD [EAX], AL
0x5fff0013 0000             ADD [EAX], AL
0x5fff0015 0000             ADD [EAX], AL
0x5fff0017 0000             ADD [EAX], AL
0x5fff0019 0000             ADD [EAX], AL
0x5fff001b 0000             ADD [EAX], AL
0x5fff001d 0000             ADD [EAX], AL
0x5fff001f 0000             ADD [EAX], AL
0x5fff0021 0000             ADD [EAX], AL
0x5fff0023 0000             ADD [EAX], AL
0x5fff0025 0000             ADD [EAX], AL
0x5fff0027 0000             ADD [EAX], AL
0x5fff0029 0000             ADD [EAX], AL
0x5fff002b 0000             ADD [EAX], AL
0x5fff002d 0000             ADD [EAX], AL
0x5fff002f 0000             ADD [EAX], AL
0x5fff0031 0000             ADD [EAX], AL
0x5fff0033 0000             ADD [EAX], AL
0x5fff0035 0000             ADD [EAX], AL
0x5fff0037 0000             ADD [EAX], AL
0x5fff0039 0000             ADD [EAX], AL
0x5fff003b 0000             ADD [EAX], AL
0x5fff003d 0000             ADD [EAX], AL
0x5fff003f 00               DB 0x0

Process: firefox.exe Pid: 2996 Address: 0x7fb0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x07fb0000  a3 d0 42 7e 8b ff 55 8b ec e9 9a d0 47 76 00 00   ..B~..U.....Gv..
0x07fb0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x07fb0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x07fb0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x07fb0000 a3d0427e8b       MOV [0x8b7e42d0], EAX
0x07fb0005 ff558b           CALL DWORD [EBP-0x75]
0x07fb0008 ec               IN AL, DX
0x07fb0009 e99ad04776       JMP 0x7e42d0a8
0x07fb000e 0000             ADD [EAX], AL
0x07fb0010 0000             ADD [EAX], AL
0x07fb0012 0000             ADD [EAX], AL
0x07fb0014 0000             ADD [EAX], AL
0x07fb0016 0000             ADD [EAX], AL
0x07fb0018 0000             ADD [EAX], AL
0x07fb001a 0000             ADD [EAX], AL
0x07fb001c 0000             ADD [EAX], AL
0x07fb001e 0000             ADD [EAX], AL
0x07fb0020 0000             ADD [EAX], AL
0x07fb0022 0000             ADD [EAX], AL
0x07fb0024 0000             ADD [EAX], AL
0x07fb0026 0000             ADD [EAX], AL
0x07fb0028 0000             ADD [EAX], AL
0x07fb002a 0000             ADD [EAX], AL
0x07fb002c 0000             ADD [EAX], AL
0x07fb002e 0000             ADD [EAX], AL
0x07fb0030 0000             ADD [EAX], AL
0x07fb0032 0000             ADD [EAX], AL
0x07fb0034 0000             ADD [EAX], AL
0x07fb0036 0000             ADD [EAX], AL
0x07fb0038 0000             ADD [EAX], AL
0x07fb003a 0000             ADD [EAX], AL
0x07fb003c 0000             ADD [EAX], AL
0x07fb003e 0000             ADD [EAX], AL

Process: firefox.exe Pid: 2996 Address: 0x9ca0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x09ca0000  9c c4 42 7e 6a 10 68 70 c5 42 7e e9 93 c4 78 74   ..B~j.hp.B~...xt
0x09ca0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x09ca0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x09ca0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x09ca0000 9c               PUSHF
0x09ca0001 c4427e           LES EAX, [EDX+0x7e]
0x09ca0004 6a10             PUSH 0x10
0x09ca0006 6870c5427e       PUSH DWORD 0x7e42c570
0x09ca000b e993c47874       JMP 0x7e42c4a3
0x09ca0010 0000             ADD [EAX], AL
0x09ca0012 0000             ADD [EAX], AL
0x09ca0014 0000             ADD [EAX], AL
0x09ca0016 0000             ADD [EAX], AL
0x09ca0018 0000             ADD [EAX], AL
0x09ca001a 0000             ADD [EAX], AL
0x09ca001c 0000             ADD [EAX], AL
0x09ca001e 0000             ADD [EAX], AL
0x09ca0020 0000             ADD [EAX], AL
0x09ca0022 0000             ADD [EAX], AL
0x09ca0024 0000             ADD [EAX], AL
0x09ca0026 0000             ADD [EAX], AL
0x09ca0028 0000             ADD [EAX], AL
0x09ca002a 0000             ADD [EAX], AL
0x09ca002c 0000             ADD [EAX], AL
0x09ca002e 0000             ADD [EAX], AL
0x09ca0030 0000             ADD [EAX], AL
0x09ca0032 0000             ADD [EAX], AL
0x09ca0034 0000             ADD [EAX], AL
0x09ca0036 0000             ADD [EAX], AL
0x09ca0038 0000             ADD [EAX], AL
0x09ca003a 0000             ADD [EAX], AL
0x09ca003c 0000             ADD [EAX], AL
0x09ca003e 0000             ADD [EAX], AL

Process: firefox.exe Pid: 2996 Address: 0x188f0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 11, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x188f0000  03 00 00 00 00 00 00 00 d4 26 e8 66 a0 69 01 10   .........&.f.i..
0x188f0010  e8 74 02 10 03 00 00 00 01 00 00 00 55 e9 b3 26   .t..........U..&
0x188f0020  59 4e 00 00 00 00 00 00 00 00 00 00 00 00 00 00   YN..............
0x188f0030  02 00 00 00 55 89 e5 e9 9b 26 59 4e 00 00 00 00   ....U....&YN....

0x188f0000 0300             ADD EAX, [EAX]
0x188f0002 0000             ADD [EAX], AL
0x188f0004 0000             ADD [EAX], AL
0x188f0006 0000             ADD [EAX], AL
0x188f0008 d426             AAM 0x26
0x188f000a e866a06901       CALL 0x19f8a075
0x188f000f 10e8             ADC AL, CH
0x188f0011 7402             JZ 0x188f0015
0x188f0013 1003             ADC [EBX], AL
0x188f0015 0000             ADD [EAX], AL
0x188f0017 0001             ADD [ECX], AL
0x188f0019 0000             ADD [EAX], AL
0x188f001b 0055e9           ADD [EBP-0x17], DL
0x188f001e b326             MOV BL, 0x26
0x188f0020 59               POP ECX
0x188f0021 4e               DEC ESI
0x188f0022 0000             ADD [EAX], AL
0x188f0024 0000             ADD [EAX], AL
0x188f0026 0000             ADD [EAX], AL
0x188f0028 0000             ADD [EAX], AL
0x188f002a 0000             ADD [EAX], AL
0x188f002c 0000             ADD [EAX], AL
0x188f002e 0000             ADD [EAX], AL
0x188f0030 0200             ADD AL, [EAX]
0x188f0032 0000             ADD [EAX], AL
0x188f0034 55               PUSH EBP
0x188f0035 89e5             MOV EBP, ESP
0x188f0037 e99b26594e       JMP 0x66e826d7
0x188f003c 0000             ADD [EAX], AL
0x188f003e 0000             ADD [EAX], AL

Process: firefox.exe Pid: 2996 Address: 0x71000000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 11, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x71000000  01 00 00 00 00 00 00 00 35 5c 91 7c 10 db 00 10   ........5\.|....
0x71000010  d8 67 02 10 03 00 00 00 05 00 00 00 68 6c 02 00   .g..........hl..
0x71000020  00 e9 14 5c 91 0b 00 00 00 00 00 00 00 00 00 00   ...\............
0x71000030  05 00 00 00 68 6c 02 00 00 68 88 5d 91 7c e9 fc   ....hl...h.].|..

0x71000000 0100             ADD [EAX], EAX
0x71000002 0000             ADD [EAX], AL
0x71000004 0000             ADD [EAX], AL
0x71000006 0000             ADD [EAX], AL
0x71000008 355c917c10       XOR EAX, 0x107c915c
0x7100000d db00             FILD DWORD [EAX]
0x7100000f 10d8             ADC AL, BL
0x71000011 670210           ADD DL, [BX+SI]
0x71000014 0300             ADD EAX, [EAX]
0x71000016 0000             ADD [EAX], AL
0x71000018 0500000068       ADD EAX, 0x68000000
0x7100001d 6c               INS BYTE [ES:EDI], DX
0x7100001e 0200             ADD AL, [EAX]
0x71000020 00e9             ADD CL, CH
0x71000022 145c             ADC AL, 0x5c
0x71000024 91               XCHG ECX, EAX
0x71000025 0b00             OR EAX, [EAX]
0x71000027 0000             ADD [EAX], AL
0x71000029 0000             ADD [EAX], AL
0x7100002b 0000             ADD [EAX], AL
0x7100002d 0000             ADD [EAX], AL
0x7100002f 000500000068     ADD [0x68000000], AL
0x71000035 6c               INS BYTE [ES:EDI], DX
0x71000036 0200             ADD AL, [EAX]
0x71000038 006888           ADD [EAX-0x78], CH
0x7100003b 5d               POP EBP
0x7100003c 91               XCHG ECX, EAX
0x7100003d 7ce9             JL 0x71000028
0x7100003f fc               CLD
```

</spoiler>

## Q5. What kind of connections are currently open?

the following processes have open connections

- 2064: TuneUpUtilities
- 2444: AVGSvc.exe
- 2812: CCleaner.exe
- 2864: AVGUI.exe
- 2916: tor.exe
- 2996: firefox.exe
- 3872: avgsvcx.exe
- 552: IEXPLORE.EXE

- the tor connection to 178.63.198.113 (dsvr1.crm.apcg.com) stands out amongst the other connections to microsoft and avast,
  the address is apparently not a tor relay

<spoiler|connections>

```
root@caine:/local/ccf# volatility -f memory.raw --profile=WinXPSP3x86 connections
Volatility Foundation Volatility Framework 2.6
Offset(V)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x8144ed00 127.0.0.1:1770            127.0.0.1:1769            2996
0x8149d270 127.0.0.1:1775            127.0.0.1:1776            2916
0x81879008 127.0.0.1:1776            127.0.0.1:1775            2916
0x81980008 127.0.0.1:1769            127.0.0.1:1770            2996
0x81ae0e68 10.0.2.15:1209            212.4.153.164:443         3872
0x814155d0 127.0.0.1:9151            127.0.0.1:1784            2916
0x81d89808 127.0.0.1:1784            127.0.0.1:9151            2996
0x81cc9a58 10.0.2.15:1959            77.234.45.63:80           2444
0x8145be68 10.0.2.15:1783            178.63.198.113:443        2916
0x81b4e008 10.0.2.15:1265            209.10.120.24:80          3872
0x818c8e68 10.0.2.15:1594            209.10.120.50:443         2064
0x81baccd8 10.0.2.15:1754            151.101.36.64:443         2812
0x81b47008 10.0.2.15:1739            40.85.224.10:80           552
0x81210e68 127.0.0.1:1777            127.0.0.1:9151            2996
0x81a46668 127.0.0.1:9151            127.0.0.1:1777            2916
0x8121e298 10.0.2.15:1634            209.10.120.24:80          2064
0x81968008 10.0.2.15:1755            151.101.36.64:443         2812
0x81802928 127.0.0.1:9151            127.0.0.1:1778            2916
0x81e0bbe8 127.0.0.1:1778            127.0.0.1:9151            2996
0x8120bb28 10.0.2.15:1758            77.234.45.55:443          2864
0x81441e68 10.0.2.15:1728            13.107.21.200:80          552
0x81ab1298 10.0.2.15:1732            204.79.197.200:80         552
0x81b48b28 10.0.2.15:1597            209.10.120.53:443         2064
0x81bbbd00 10.0.2.15:1601            209.10.120.50:443         2064
0x81801008 10.0.2.15:1733            204.79.197.200:80         552
0x81caae68 10.0.2.15:1392            23.38.32.178:443          3872
0x819a2e68 10.0.2.15:1744            40.86.224.10:80           552
0x81bb02f8 10.0.2.15:1325            5.45.58.149:80            2444
```

</spoiler>

## Q6. Find out what programs and services are running

the following processes/services are running

- alg.exe
- avgdiagex.exe
- AVGSvc.exe
- avgsvcx.exe
- AVGUI.exe
- avguix.exe
- CCleaner.exe
- csrss.exe
- ctfmon.exe
- explorer.exe
- firefox.exe
- IEXPLORE.EXE
- lsass.exe
- services.exe
- smss.exe
- sol.exe
- spoolsv.exe
- svchost.exe
- System
- taskmgr.exe
- tor.exe
- TuneUpUtilities
- winlogon.exe
- wuauclt.exe

<spoiler|pslist>

```
root@caine:/local/ccf# volatility -f memory.raw --profile=WinXPSP3x86 pslist
Volatility Foundation Volatility Framework 2.6
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x81fc8830 System                    4      0     65     2373 ------      0
0x81e4e700 smss.exe                428      4      3       19 ------      0 2017-02-12 12:55:55 UTC+0000
0x81e50020 csrss.exe               560    428     11      712      0      0 2017-02-12 12:55:55 UTC+0000
0x81e057c8 winlogon.exe            584    428     20      630      0      0 2017-02-12 12:55:56 UTC+0000
0x81e7dda0 services.exe            628    584     15      286      0      0 2017-02-12 12:55:56 UTC+0000
0x81e04750 lsass.exe               640    584     22      504      0      0 2017-02-12 12:55:56 UTC+0000
0x81dcba00 svchost.exe             828    628     19      237      0      0 2017-02-12 12:55:56 UTC+0000
0x81db2a48 svchost.exe             920    628     11      340      0      0 2017-02-12 12:55:56 UTC+0000
0x81d9bda0 svchost.exe            1016    628     73     1735      0      0 2017-02-12 12:55:56 UTC+0000
0x81d1a7a8 svchost.exe            1232    628      5       76      0      0 2017-02-12 12:56:15 UTC+0000
0x81cf09f0 svchost.exe            1352    628     11      180      0      0 2017-02-12 12:56:15 UTC+0000
0x81cdd4f0 spoolsv.exe            1560    628     11      119      0      0 2017-02-12 12:56:15 UTC+0000
0x81caf308 svchost.exe            1660    628      5      107      0      0 2017-02-12 12:56:23 UTC+0000
0x81c17020 alg.exe                 760    628      5      103      0      0 2017-02-12 12:56:27 UTC+0000
0x81c10020 explorer.exe           1704   1856     15      556      0      0 2017-02-12 12:57:01 UTC+0000
0x81b19b88 wuauclt.exe            1584   1016      3      124      0      0 2017-02-12 12:57:42 UTC+0000
0x81d8b020 IEXPLORE.EXE           1108   1704     13      615      0      0 2017-02-12 12:58:24 UTC+0000
0x81da8020 ctfmon.exe             1760   1108      1       88      0      0 2017-02-12 12:58:24 UTC+0000
0x81bc3b40 IEXPLORE.EXE            552   1108     21      812      0      0 2017-02-12 12:58:24 UTC+0000
0x81c38708 sol.exe                3856   1704      1       54      0      0 2017-02-12 13:00:49 UTC+0000
0x81ad0390 avgsvcx.exe            3872    628     31     1433      0      0 2017-02-12 13:00:51 UTC+0000
0x81acd620 avguix.exe             1528   2580     26     1047      0      0 2017-02-12 13:00:52 UTC+0000
0x81a9fc68 AVGSvc.exe             2444    628     87     2697      0      0 2017-02-12 13:02:12 UTC+0000
0x81a491f0 AVGUI.exe              2864   3564     40      805      0      0 2017-02-12 13:02:13 UTC+0000
0x81968da0 TuneUpUtilities        2064    628     28      839      0      0 2017-02-12 13:04:06 UTC+0000
0x81a6f3b8 TuneUpUtilities        2316   2064     11      239      0      0 2017-02-12 13:04:11 UTC+0000
0x81222020 avguix.exe             3304   1528     10      198      0      0 2017-02-12 13:04:16 UTC+0000
0x8149b020 CCleaner.exe           2812   1964      7      384      0      0 2017-02-12 13:05:46 UTC+0000
0x81454458 CCleaner.exe           2828   2812      4      116      0      0 2017-02-12 13:05:50 UTC+0000
0x8120b020 IEXPLORE.EXE           1996   1108     18      643      0      0 2017-02-12 13:06:13 UTC+0000
0x81416da0 firefox.exe            2996   3804     49      901      0      0 2017-02-12 13:06:24 UTC+0000
0x81992da0 tor.exe                2916   2996      1      118      0      0 2017-02-12 13:06:32 UTC+0000
0x81826360 taskmgr.exe            1740    584      3       83      0      0 2017-02-12 13:08:48 UTC+0000
0x81a1d020 avgdiagex.exe          3568   3872      0 --------      0      0 2017-02-12 13:15:52 UTC+0000   2017-02-12 13:15:52 UTC+0000
```

</spoiler>

## Q7. How can you retrieve files out of the memory? What files can contain artifacts?

dumpfiles can extract (partial, zero padded) files that were cached in memory for performance.
Executables and (shared) library files ex dll s are most likely to contain interesting artifacts, as malware needs to run.

## Q8. Write a small paragraph of maximum 200 words about your findings Please remain objective

The user has antivirus, CCleaner, explorer, and firefox/tor running on a 32-bit Windows XP Service Pack 3 system. No known malware was identified from the memory dump.

## Q9. Read up on Scalpel and its features Explain what it does and how it works

Scalpel is a file carving tool to reassemble files from fragments in disk or memory in the absence of metadata.
Scalpel runs 2 passes to identify headers and footers from the file contents and writes out the resulting file to a new location

- https://www.andreafortuna.org/2017/04/20/four-tools-for-file-carving-in-forensic-analysis/
- http://www.linux-magazine.com/Online/Features/Recovering-Deleted-Files-with-Scalpel

## Q10. Inspect the image manually and look for any artifacts Describe this process completely

- mount -o loopback,ro,offset=32256 disk.img mount

## Q11. Configure Scalpel and let it inspect the disk image What files are useful for your investigation? Note any interesting files you find

- scalpel -o file disk.img

## Q12. Investigate the techniques that have been used to hide files

## Q13. How would you securely hide or delete your information?

To delete information, it is necessary to clear out any underlying data structures, typically by overwriting with new / zero / random data. This applies to both storage and memory.

Hiding information can be accomplished by disguising the data to appear innocuous, hiding in unused space by the OS (at the risk of getting overwritten) or hiding in normally inaccessible parts of the system such as filesystem reserved space.

## Q14. Write a small paragraph of maximum 200 words about your findings Please remain objective

## Q15. Did you find any traps that were interfering with your work?

## Q16. Create a timeline of the evidence and explain what happened Include both the memory and the disk forensics Use a maximum of 400 words
