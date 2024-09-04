---
slug: tiangongarticle043
date: 2024-08-21
title: 深入解析Windows VTL机制 & IUM进程
author: hongzhenhao
avatar: /authors/hongzhenhao.jpg
info: 微软 MSRC 全球最具价值安全精英榜上榜者、BlackHat USA 世界黑帽大会 Speaker
tags: [Windows, Virtual Trust Levels, VTL, Isolated User Mode, IUM]
---

# 深入解析Windows VTL机制 & IUM进程

## 一、前言

现今的Windows操作系统已经融合了虚拟化技术作为自身的核心功能，Windows平台下的虚拟化技术的应用也不仅限于Hyper-V虚拟化软件的应用，在一些用于保护Windows系统的安全功能中，虚拟化技术的使用也变得尤为重要。现在我们就来简单探索下Windows的VTL机制和IUM进程，这两种基于虚拟化技术的安全功能。

<!-- truncate -->

## 二、VTL机制和IUM进程介绍

Virtual Secure Mode(VSM)最早在Windows10和Windows Server 2016中被引入，是基于Windows平台下的虚拟化技术的安全功能，使用的是Hyper-V的虚拟化组件。

VSM的主要作用是，在这个安全功能开启的情况下，即使主机上的内核或者驱动程序（即Ring0层）受到攻击，受到VSM体系保护的数据依然可以保持安全，保证数据不被篡改或者无法被访问，甚至攻击者处于Ring0权限下。

与我们熟知的VMware或者QEMU虚拟化软件不同，Hyper-V的虚拟化实现是裸金属架构的，即Hypervisor层的组件运行在实体的硬件上，而无论是所谓的Guest(Child Parition)或者Host(Root Parition)都是Hypervisor层之上抽象出来的。

 ![](/attachments/2024-08-21-windows-vtl-ium/fbc5383a-474c-4cf8-bbe3-e31531b55388.gif)

那么，Hyper-V的技术架构是VSM功能的基础，无论是Guest还是Host，实际上都可以通过Hypervisor来控制不同分区对硬件资源的使用能力从而实现在VSM中提及的安全功能。

VSM功能的引入同时引入了一个新的概念——VTL。

Virtual Trust Levels（VTL），VSM通过VTL来实现和维护隔离。VTL是有层级概念的，例如熟知的Ring0\~3层级权限。但是与Ring0\~3概念不同的是，VTL的层级权限是级别高的权限要高于级别低的权限。举个例子：VTL0的权限 < VTL1的权限；VTL1的权限 < VTL2的权限。在微软对VTL的代码实现里，最多支持16个级别VTL，但是截止到目前的关于VTL的代码中，微软只实现了2个级别的VTL。

为了更直观的展示VTL的作用，这里使用了微软官方给出的IUM架构体系图。

 ![图片来源：参考链接\[2\]](/attachments/2024-08-21-windows-vtl-ium/7dc46ced-b1c0-45a6-b54b-fedcc58e8cb2.png)

从图中可以看到，我们所熟知的Windows内核态和用户态都属于VTL0级别下，而SecureKernel和运行在同VTL层级下的用户态进程属于VTL1级别下。此时，假如我们在VTL0种进行内核调试，都无法修改VTL1层级下的用户态进程空间内存。这个例子说明了低级别VTL无法影响到高级别VTL内存空间，不同的VTL级别之间有着明显的隔离边界。

有了VTL这个概念之后，下面我们来介绍下什么是Isolated User Mode(IUM)进程。通俗来讲，IUM进程就是运行在VTL1层级下的用户态进程。最简单的例子就是LSAIso.exe进程，当这个进程运行在VTL1层级下时，无论是在用户态还是内核态都无法修改这个进程的内存空间，同样地，对其进行调试也是无法进行的。

下面，我们一起来探索VTL机制和IUM进程（以及如何调试IUM进程）的一些内部细节。

## 三、必要的硬件虚拟化知识（Intel）

在探索之前，我们还需要简单的了解下CPU硬件虚拟化知识，这里我们以Intel处理器(Intel VT-x)加以介绍。

这里首先要介绍的是Intel VT-x和VMX是什么。Intel VT-x的全称是Intel Virtualization Technology for x86，这个东西就是所谓的Intel硬件虚拟化技术，而VMX是其实现的架构，全称为Virtual-Machine Extensions。在VMX下引入了两个概念：**VMX root operation**和**VMX non-root operation**模式。

VMX的root和non-root operation模式可以简单地理解成，hypervisor也就是虚拟化层，即VM管理者(VMM, virtual machine monitor)和Guest所使用的环境。这两种模式可以互相转换，当从VMX的root模式转换到non-root模式时，这个行为被称作**VM-entry**。那么当VMX的non-root模式切换到root模式，这个行为被称作**VM-Exit**。

假设目前VMX处于non-root状态，此时是在执行Guest中的代码，如果执行时遇到了比如CPUID，读写MSR寄存器等操作时，Guest操作系统会被暂停，并产生**Vm-Exit**事件，同时陷落入VMM，即root operation状态中。VMM根据不同的VM-Exit原因来处理（模拟）此时Guest的执行指令，处理数据并返回结果，最后vmm通过执行vmresume指令重新让Guest系统继续运行，此时的VMX状态又变回了non-root状态。

在VMX进行root和non-root operation状态切换时，VMCS（Virtual Machine Control Structure）用来配置此时发生切换的处理器状态和执行的环境。在Hyper-V的虚拟化环境中，每个虚拟处理器都对应着一个或者多个VMCS。

VMCS中有很多字段，对应着当前虚拟处理器的状态信息，比如用于记录当前VM-Exit信息的"Exit reason"字段，通过阅读Intel手册发现这个字段对应的ID是0x4402。因为VMCS中的字段信息无法直接通过读取物理内存的方式读取到，所以这里必须使用Intel给出的指令集vmread/vmwrite来读写对应的字段内容。

```c
#define EXIT_REASON_EXCEPTION_NMI            0
#define EXIT_REASON_EXTERNAL_INTERRUPT       1
#define EXIT_REASON_TRIPLE_FAULT             2
#define EXIT_REASON_INIT_SIGNAL              3
#define EXIT_REASON_SIPI_SIGNAL              4

#define EXIT_REASON_INTERRUPT_WINDOW         7
#define EXIT_REASON_NMI_WINDOW               8
#define EXIT_REASON_TASK_SWITCH              9
#define EXIT_REASON_CPUID                    10
#define EXIT_REASON_HLT                      12
#define EXIT_REASON_INVD                     13
#define EXIT_REASON_INVLPG                   14
#define EXIT_REASON_RDPMC                    15
#define EXIT_REASON_RDTSC                    16
#define EXIT_REASON_VMCALL                   18
#define EXIT_REASON_VMCLEAR                  19
#define EXIT_REASON_VMLAUNCH                 20
#define EXIT_REASON_VMPTRLD                  21
#define EXIT_REASON_VMPTRST                  22
#define EXIT_REASON_VMREAD                   23
#define EXIT_REASON_VMRESUME                 24
#define EXIT_REASON_VMWRITE                  25
#define EXIT_REASON_VMOFF                    26
#define EXIT_REASON_VMON                     27
#define EXIT_REASON_CR_ACCESS                28
#define EXIT_REASON_DR_ACCESS                29
#define EXIT_REASON_IO_INSTRUCTION           30
#define EXIT_REASON_MSR_READ                 31
#define EXIT_REASON_MSR_WRITE                32
#define EXIT_REASON_INVALID_STATE            33
#define EXIT_REASON_MSR_LOAD_FAIL            34
#define EXIT_REASON_MWAIT_INSTRUCTION        36
#define EXIT_REASON_MONITOR_TRAP_FLAG        37
#define EXIT_REASON_MONITOR_INSTRUCTION      39
#define EXIT_REASON_PAUSE_INSTRUCTION        40
#define EXIT_REASON_MCE_DURING_VMENTRY       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD      43
#define EXIT_REASON_APIC_ACCESS              44
#define EXIT_REASON_EOI_INDUCED              45
#define EXIT_REASON_GDTR_IDTR                46
#define EXIT_REASON_LDTR_TR                  47
#define EXIT_REASON_EPT_VIOLATION            48
#define EXIT_REASON_EPT_MISCONFIG            49
#define EXIT_REASON_INVEPT                   50
#define EXIT_REASON_RDTSCP                   51
#define EXIT_REASON_PREEMPTION_TIMER         52
#define EXIT_REASON_INVVPID                  53
#define EXIT_REASON_WBINVD                   54
#define EXIT_REASON_XSETBV                   55
#define EXIT_REASON_APIC_WRITE               56
#define EXIT_REASON_RDRAND                   57
#define EXIT_REASON_INVPCID                  58
#define EXIT_REASON_VMFUNC                   59
#define EXIT_REASON_ENCLS                    60
#define EXIT_REASON_RDSEED                   61
#define EXIT_REASON_PML_FULL                 62
#define EXIT_REASON_XSAVES                   63
#define EXIT_REASON_XRSTORS                  64
#define EXIT_REASON_UMWAIT                   67
#define EXIT_REASON_TPAUSE                   68
#define EXIT_REASON_BUS_LOCK                 74
#define EXIT_REASON_NOTIFY                   75
```

通过vmread读取0x4402 id字段的内容，就可以得到VM-Exit的原因，VMM根据上图中这些若干的原因进行处理，完成处理后，将结果改写到例如Guest中的寄存器中，此时也需要通过vmwrite改写其中关于Guest寄存器信息的字段，最后通过vmresume将控制权交还Guest。

这里还要介绍一对重要的指令：vmptrld/vmptrst，vmptrld这个指令是用来从内存中加载一个64位的物理地址作为当前VMCS指针；vmptrst是用来将当前的VMCS指针保存到内存中。vmptrld是用来切换当前VMCS的指令，而vmread/vmwrite所读写的也是当前VMCS。

下面要介绍的是SLAT（Second Level Address Translation），上面介绍了通过VMX root、non-root operation和VMCS来控制虚拟处理器，那么在虚拟机中的内存也需要和宿主机/其他虚拟机的内存做隔离。广为人知的四级页表转换已经无法满足这个需求，所以在此Intel提出了二级地址转换这个功能。

如quarkslab博客中文章中使用的图片所示，下图展现了SLAT完整的转换流程。

 ![图片来源：参考链接\[3\]](/attachments/2024-08-21-windows-vtl-ium/21aaab12-13e5-438c-b7f6-16fcd71fa351.png)

首先，在Guest中的虚拟地址通过四级页表转化成了Guest中的物理地址（GPA），然后GPA通过相似的四级页表转换，转换成了Host中的物理地址（SPA）。这样就实现了Guest和Host以及其他Guest之间的内存隔离，并且在Guest操作系统中是完全透明的，因为在GPA到SPA转换中，CPU是处于VMX root operation模式下的。

这里要提到EPT这个东西，EPT（Extend Page Table）的作用和CR3寄存器是一样的，用来确定页目录基址，完成GPA到SPA转换。我们可以通过读取当前VMCS中的EPT pointer字段(ID:0x201a)获取到EPT的指针。

这里举个简单的例子：首先我们准备一个Guest，这里我使用的是Linux，编写一个驱动，驱动主要是打印了一个buffer所在的物理地址的信息，如下。

```none
$dmesg –w|grep Hello
[+]phy address of string:"AAAAAAAAAAAA......" 0x96eee000
```

通过对Hyper-V的hypervisor进行逆向和调试，获得当前Guest所在的VMCS中的ept指针信息

```none
Breakpoint 4 hit
hv+0x2a0b35:
fffff800`078ceb35 b91a200000      mov     ecx,201Ah
0: kd> r rax
rax=00000001ea40901e
```

下面我们可以使用!vtop这个windbg命令快速求出Guest中我们的驱动的buffer的GPA对应SPA

```none
hv+0x23b7a0:
fffff800`078697a0 cc              int     3
1: kd> !vtop 1ea40901e 0x96eee000
Amd64VtoP: Virt 00000000`96eee000, pagedir 00000001`ea409000
Amd64VtoP: PML4E 00000001`ea409000
Amd64VtoP: PDPE 00000001`ea408010
Amd64VtoP: PDE 00000001`4da3a5b8
Amd64VtoP: PTE 00000001`4daf3770
Amd64VtoP: Mapped phys 00000001`972ee000
Virtual address 96eee000 translates to physical address 1972ee000.
1: kd> !db 1972ee000
#1972ee000 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee010 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee020 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee030 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee040 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee050 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee060 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
#1972ee070 41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
```

可以看到GPA：0x96eee000 对应的SPA：0x1972ee000。

## 四、VTL内部细节研究

这里先看一下一个简单的vmcall处理函数：HvDeletePartition，由于创建或者删除分区的权限只有root分区才有，所以在调用vmcall指令对应的功能时，要先检测当前陷入VM-Exit的分区的权限，以保证Child分区不会影响到Root分区。

```none
.text:FFFFF800003528C0     ; __int64 __fastcall vmcall_0x43_HvDeletePartition_sub_FFFFF800003528C0(_QWORD *)
.text:FFFFF800003528C0     vmcall_0x43_HvDeletePartition_sub_FFFFF800003528C0 proc near
.text:FFFFF800003528C0                                             ; DATA XREF: .pdata:FFFFF80000028D54↑o
.text:FFFFF800003528C0                                             ; CONST:FFFFF8000002B648↑o
.text:FFFFF800003528C0
.text:FFFFF800003528C0     arg_0           = qword ptr  8
.text:FFFFF800003528C0
.text:FFFFF800003528C0 000                 mov     [rsp+arg_0], rbx
.text:FFFFF800003528C5 000                 push    rdi
.text:FFFFF800003528C6 008                 sub     rsp, 20h
.text:FFFFF800003528CA 028                 mov     rax, gs:103E0h
.text:FFFFF800003528D3 028                 mov     rdi, rcx
.text:FFFFF800003528D6 028                 bt      qword ptr [rax+0F0h], 20h ; ' '
.text:FFFFF800003528DF 028                 jb      short loc_FFFFF800003528E8
.text:FFFFF800003528E1 028                 mov     ebx, 6
.text:FFFFF800003528E6 028                 jmp     short loc_FFFFF80000352905
.text:FFFFF800003528E8     ; ---------------------------------------------------------------------------
.text:FFFFF800003528E8
.text:FFFFF800003528E8     loc_FFFFF800003528E8:                   ; CODE XREF: vmcall_0x43_HvDeletePartition_sub_FFFFF800003528C0+1F↑j
.text:FFFFF800003528E8 028                 mov     rcx, [rcx]
.text:FFFFF800003528EB 028                 call    sub_FFFFF8000029A71C
.text:FFFFF800003528F0 028                 movzx   ebx, ax
.text:FFFFF800003528F3 028                 test    ax, ax
.text:FFFFF800003528F6 028                 jnz     short loc_FFFFF80000352905
.text:FFFFF800003528F8 028                 mov     r8, [rdi]
.text:FFFFF800003528FB 028                 mov     edx, 4102h
.text:FFFFF80000352900 028                 call    sub_FFFFF8000027FE6C
.text:FFFFF80000352905
.text:FFFFF80000352905     loc_FFFFF80000352905:                   ; CODE XREF: vmcall_0x43_HvDeletePartition_sub_FFFFF800003528C0+26↑j
.text:FFFFF80000352905                                             ; vmcall_0x43_HvDeletePartition_sub_FFFFF800003528C0+36↑j
.text:FFFFF80000352905 028                 movzx   eax, bx
.text:FFFFF80000352908 028                 mov     rbx, [rsp+28h+arg_0]
.text:FFFFF8000035290D 028                 add     rsp, 20h
.text:FFFFF80000352911 008                 pop     rdi
.text:FFFFF80000352912 000                 retn
```

从这个HvDeletePartition函数中可以看到，代码先从gs:\[0x103E0\]处拿到了一个指针，然后对这个指针offset 0xF0处的64bit的数据进行比特位检测运算，检测的比特位是第32位。通过逆向得知，这个64位数据就是Hyper-V Hypervisor TLFS中的HV_PARTITION_PRIVILEGE_MASK数据，比较幸运的是，微软公开了这个数据的数据结构，下面是它的参考。

```c
typedef struct
{
// Access to virtual MSRs
UINT64 AccessVpRunTimeReg:1;
UINT64 AccessPartitionReferenceCounter:1;
UINT64 AccessSynicRegs:1;
UINT64 AccessSyntheticTimerRegs:1;
UINT64 AccessIntrCtrlRegs:1;
UINT64 AccessHypercallMsrs:1;
UINT64 AccessVpIndex:1;
UINT64 AccessResetReg:1;
UINT64 AccessStatsReg:1;
UINT64 AccessPartitionReferenceTsc:1;
UINT64 AccessGuestIdleReg:1;
UINT64 AccessFrequencyRegs:1;
UINT64 AccessDebugRegs:1;
UINT64 AccessReenlightenmentControls:1
UINT64 Reserved1:18;
// Access to hypercalls
UINT64 CreatePartitions:1; //这里就是第32位要检测的bit位
UINT64 AccessPartitionId:1;
UINT64 AccessMemoryPool:1;
UINT64 AdjustMessageBuffers:1;
UINT64 PostMessages:1;
UINT64 SignalEvents:1;
UINT64 CreatePort:1;
UINT64 ConnectPort:1;
UINT64 AccessStats:1;
UINT64 Reserved2:2;
UINT64 Debugging:1;
UINT64 CpuManagement:1;
UINT64 Reserved:1
UINT64 Reserved:1;
UINT64 Reserved:1;
UINT64 AccessVSM:1;
UINT64 AccessVpRegisters:1;
UINT64 Reserved:1;
UINT64 Reserved:1;
UINT64 EnableExtendedHypercalls:1;
UINT64 StartVirtualProcessor:1;
UINT64 Reserved3:10;
} HV_PARTITION_PRIVILEGE_MASK;
```

在Windbg中表现为：

```none
14: kd> dq gs:[103e0]
0020:00000000`000103e0  ffffe800`00001000 ffffe800`01746050
0020:00000000`000103f0  00000080`01c00000 00000000`0009b922
0020:00000000`00010400  00000000`00000000 00000000`00000000
0020:00000000`00010410  00000000`00000000 00000000`00000000
0020:00000000`00010420  00000000`00000001 80000000`00000000
0020:00000000`00010430  00000000`00000000 80000000`00000000
0020:00000000`00010440  00000000`00000000 00000000`00000000
0020:00000000`00010450  00000000`00000000 00000000`00000000
14: kd> dq ffffe800`00001000+f0
ffffe800`000010f0  002bb9ff`00003fff ffffe800`00000000
ffffe800`00001100  00000000`00000000 ffffe800`0064acd0
ffffe800`00001110  00000017`00000018 00000000`00000000
ffffe800`00001120  ffffe800`0067c050 ffffe800`015c5130
ffffe800`00001130  ffffe800`015e9050 ffffe800`01607050
ffffe800`00001140  ffffe800`01624050 ffffe800`01641050
ffffe800`00001150  ffffe800`0165e050 ffffe800`0167b050
ffffe800`00001160  ffffe800`01698050 ffffe800`016b5050
14: kd> .formats 2bb9ff`00003fff 
Evaluate expression:
  Hex:     002bb9ff`00003fff
  Decimal: 12307928866373631
  Octal:   0000535637740000037777
  Binary:  00000000 00101011 10111001 11111111 00000000 00000000 00111111 11111111
  Chars:   .+....?.
  Time:    Mon Jan  2 14:54:46.637 1640 (UTC + 8:00)
  Float:   low 2.29575e-041 high 4.01565e-039
  Double:  7.7117e-308
```

通过windbg结果可以看到此时的分区权限拥有比如创建分区的权限等较多的权限，它目前就是root分区。

可以看到，HvDeletePartition函数先检测了当前的分区是否拥有创建分区权限，再进行下一步操作。这一步给我们的逆向思路提供了经验，gs:\[103e0\]中存储的很有可能就是代表partition的大结构体，其中offset 0xF0处代表这个分区的权限信息。通过对HvCreateVp这个函数的逆向，我们得出了进一步的信息。这里省略对HvCreateVp的逆向过程，感兴趣的小伙伴可以自行研究，很简单。

逆向得出，vmcall_0x4e_HvCreateVp_sub_FFFFF80000294100 --> sub_FFFFF800002A1D28，sub_FFFFF800002A1D28函数中会更新目前的partition中的虚拟处理器的信息。如下所示。

```none
.text:FFFFF800002A1E04
.text:FFFFF800002A1E04     loc_FFFFF800002A1E04:
.text:FFFFF800002A1E04 0D8 test    byte ptr [rbx+0E0h], 1
.text:FFFFF800002A1E0B 0D8 mov     rdi, [rbx+r13*8+120h]
.text:FFFFF800002A1E13 0D8 jz      short loc_FFFFF800002A1E37
.text:FFFFF800002A1E13
```

上述代码中的rbx指向的就是当前partition的指针，offset 0x120代表着当前partition index为0的虚拟处理器的指针，假设我有8个虚拟处理器，那么0x120 代表index为0的虚拟处理器指针，0x128代表index为1的虚拟处理器指针，剩下的以此类推。

通过逆向还发现partition指针offset 0x110处的4bytes代表着虚拟处理器的数量，0x114处的4bytes代表着虚拟处理器的最大index值。windbg中表现为：

```none
2: kd>  dq poi(gs:[103e0])+0x110 L?20
ffffe800`00001110  00000017`00000018 00000000`00000000
ffffe800`00001120  ffffe800`0067c050 ffffe800`015cd050
ffffe800`00001130  ffffe800`015e9050 ffffe800`01607050
ffffe800`00001140  ffffe800`01624050 ffffe800`01641050
ffffe800`00001150  ffffe800`0165e050 ffffe800`0167b050
ffffe800`00001160  ffffe800`01698050 ffffe800`016b5050
ffffe800`00001170  ffffe800`016d2050 ffffe800`016ef050
ffffe800`00001180  ffffe800`0170c050 ffffe800`01729050
ffffe800`00001190  ffffe800`01746050 ffffe800`01763050
ffffe800`000011a0  ffffe800`01780050 ffffe800`0179d050
ffffe800`000011b0  ffffe800`017ba050 ffffe800`017d7050
ffffe800`000011c0  ffffe800`017f4050 ffffe800`01811050
ffffe800`000011d0  ffffe800`0182e050 ffffe800`0184b050
ffffe800`000011e0  00000000`00000000 00000000`00000000
ffffe800`000011f0  00000000`00000000 00000000`00000000
ffffe800`00001200  00000000`00000000 00000000`00000000
```

由于这里演示用的partition是root分区，而且我的被调试机中硬件CPU的核心数量为24个，所以此时：

```none
partition + 0x110: 最大的虚拟处理器数量
partition + 0x114: 最大的虚拟处理器index值
partition + 0x120：index为0的虚拟处理器指针
partition + 0x128：index为的虚拟处理器指针
...
```

根据微软的TLFS文档中的内容，HvVtlCall这个函数的作用是将当前虚拟处理器的VTL权限升高。通过逆向这个函数内部实现，我们发现在后续的调用中出现了VTL实现的相关结构，如下代码所示。

 ![](/attachments/2024-08-21-windows-vtl-ium/96cee79a-955f-4f77-8594-259202c62624.png)

这个函数包含三个参数，其中的第二参数是我们上面提到的Viurtal Process结构体指针，第三参数是VTL等级。通过代码得知，VP offset 0x328处使用了VTL级别来进行引索，随后取出一个指针，我们暂时称这个指针为struc1。然后从struc1 offset 0x10d0处取出了一个指针，这个指针我们暂时称为struc2。后续又从struc2 offset 0x188中取出一个64bits的地址，这个地址就是我们上文提到过的VMCS的地址。代码运行到vmptrld这里，就实现了VMCS的切换，同时抽象理解成为VTL也完成了切换。

Windbg中过程如下：

```none
Breakpoint 0 hit
hv+0x211058:
fffff83b`24f56058 48895c2410      mov     qword ptr [rsp+10h],rbx
2: kd> r rdx
rdx=ffffe800015e9050 //当前的VirtualProcess指针（VP 指针）
2: kd> r r8
r8=0000000000000001
2: kd> rdmsr 0xc0000101
msr[c0000101] = ffffe800`006eb000
2: kd> dq ffffe800`006eb000+103e0
ffffe800`006fb3e0  ffffe800`00001000 ffffe800`015e9050 
//可以发现gs:[0x103e0]是partition pointer，gs:[0x103e8]是当前的VP指针
ffffe800`006fb3f0  00000080`00400000 00000000`0000da94
ffffe800`006fb400  00000000`00000000 00000000`00000000
ffffe800`006fb410  00000000`00000000 00000000`00000000
ffffe800`006fb420  00000000`00000101 80000000`00000000
ffffe800`006fb430  00000000`00000000 80000000`00000000
ffffe800`006fb440  00000000`00000000 00000000`00000000
ffffe800`006fb450  00000000`00000000 00000000`00000000
2: kd> dq ffffe800`015e9050+328
ffffe800`015e9378  ffffe800`015ea000 ffffe800`015ec000
//低地址指针是VTL0的struc1，高地址指针是VTL1的struc1
ffffe800`015e9388  00000000`00000000 ffffe800`015ea000
ffffe800`015e9398  00000000`00000001 00000000`00000000
ffffe800`015e93a8  00000000`00000002 00000000`00000006
ffffe800`015e93b8  00000000`890ced27 00000000`00000000
ffffe800`015e93c8  00000000`00000000 00000000`00000002
ffffe800`015e93d8  ffffe800`00001000 00000002`000000c0
ffffe800`015e93e8  ffffe800`015ee050 00000000`00000000
2: kd> dq poi(ffffe800`015ea000+10d0)+180
ffffe800`015eb558  ffffe800`015f3000 00000004`7a2c6000//VTL0下的VMCS VA和VMCS PA
ffffe800`015eb568  ffffe800`015f5000 00000000`00000000
ffffe800`015eb578  00000000`00000000 00000000`0000000f
ffffe800`015eb588  00000000`00000000 00000000`00000000
ffffe800`015eb598  00000000`00000000 00000000`00000000
ffffe800`015eb5a8  00000000`00000000 00000000`00000000
ffffe800`015eb5b8  00000000`00000000 00000000`00000000
ffffe800`015eb5c8  00000000`00000000 00000000`00000000
2: kd> dq poi(ffffe800`015ec000+10d0)+180
ffffe800`015ed558  ffffe800`015f6000 00000004`7a2c9000//VTL1下的VMCS VA和VMCS PA
ffffe800`015ed568  ffffe800`015f8000 00000000`00000000
ffffe800`015ed578  00000000`00000000 00000000`0000000f
ffffe800`015ed588  00000000`00000000 00000000`00000000
ffffe800`015ed598  00000000`00000000 00000000`00000000
ffffe800`015ed5a8  00000000`00000000 00000000`00000000
ffffe800`015ed5b8  00000000`00000000 00000000`00000000
ffffe800`015ed5c8  00000000`00000000 00000000`00000000
```

我们在发生VTL切换时下断点

```none
Breakpoint 1 hit
hv+0x211248:
fffff83b`24f56248 0fc7b188010000  vmptrld qword ptr [rcx+188h] //切换VMCS
2: kd> bd 1
2: kd> !vmread 0x201a //EPT Pointer
@$vmread(0x201a) : 0x12382301e
2: kd> !vmread 0x6802 //CR3 Guest
@$vmread(0x6802) : 0x1aa002
2: kd> p
hv+0x21124f:
fffff83b`24f5624f e99cfeffff      jmp     hv+0x2110f0 (fffff83b`24f560f0)
2: kd> !vmread 0x201a //EPT Pointer
@$vmread(0x201a) : 0x12382501e
2: kd> !vmread 0x6802 //CR3 Guest
@$vmread(0x6802) : 0x4c00000
```

可以看到，VTL从0升为1时，并执行过vmptrld进行VMCS切换后，典型的NT内核的CR3从0x1aa002变为0x4c00000，并且EPT指针从0x12382301e变为0x12382501e。

这里用一个更直观的例子来验证VTL0 VTL1之间的差别。vmsp.exe进程也属于IUM进程，所以我们即使在内核调试环境下，都无法对vmsp.exe进程空间进行修改。

```none
7: kd> !process 0n9012
Searching for Process with Cid == 2334
PROCESS ffffe10e0d4bb080
    SessionId: 0  Cid: 2334    Peb: f5073af000  ParentCid: 01d8
    DirBase: 84f417002  ObjectTable: ffff8004c6be6040  HandleCount:  51.
    Image: vmsp.exe
    VadRoot ffffe10e0a78fd30 Vads 40 Clone 0 Private 236. Modified 1. Locked 0.
    DeviceMap ffff8004c9ea3120
    Token                             ffff8004c6bc4060
    ElapsedTime                       00:00:12.882
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         25416
    QuotaPoolUsage[NonPagedPool]      5704
    Working Set Sizes (now,min,max)  (1056, 50, 345) (4224KB, 200KB, 1380KB)
    PeakWorkingSetSize                1062
    VirtualSize                       2101299 Mb
    PeakVirtualSize                   2101299 Mb
    PageFaultCount                    3029
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      333

        THREAD ffffe10e0d57a080  Cid 2334.2ba4  Teb: 000000f5073b0000 Win32Thread: 0000000000000000 WAIT: (UserRequest) UserMode Non-Alertable
            ffffe10e0d67a560  NotificationEvent
        Not impersonating
        DeviceMap                 ffff8004c9ea3120
        Owning Process            ffffe10e0d4bb080       Image:         vmsp.exe
        Attached Process          N/A            Image:         N/A
        Wait Start TickCount      382305         Ticks: 819 (0:00:00:12.796)
        Context Switch Count      2              IdealProcessor: 14             
        UserTime                  00:00:00.000
        KernelTime                00:00:00.078
        Win32 Start Address 0x00007ff6a26277d0
        Stack Init fffff90c6e1afc70 Current fffff90c6e1af310
        Base fffff90c6e1b0000 Limit fffff90c6e1aa000 Call 0000000000000000
        Priority 9 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
        Child-SP          RetAddr               Call Site
        fffff90c`6e1af350 fffff806`21eccdc5     nt!KiSwapContext+0x76
        fffff90c`6e1af490 fffff806`21ecdc2a     nt!KiSwapThread+0x545
        fffff90c`6e1af530 fffff806`21ece886     nt!KiCommitThreadWait+0x15a
        fffff90c`6e1af5d0 fffff806`223591ab     nt!KeWaitForSingleObject+0x236
        fffff90c`6e1af6c0 fffff806`223590da     nt!ObWaitForSingleObject+0xbb
        fffff90c`6e1af720 fffff806`2201dc04     nt!NtWaitForSingleObject+0x6a
        fffff90c`6e1af760 fffff806`2204506a     nt!VslpDispatchIumSyscall+0x34
        fffff90c`6e1af7e0 fffff806`224914ea     nt!VslpEnterIumSecureMode+0x1d447a
        fffff90c`6e1af8b0 fffff806`22026cf8     nt!PspUserThreadStartup+0x1a65ba
        fffff90c`6e1af9a0 fffff806`22026c60     nt!KiStartUserThread+0x28
        fffff90c`6e1afae0 00007ff8`4cc1e880     nt!KiStartUserThreadReturn (TrapFrame @ fffff90c`6e1afae0)
        000000f5`070ef8e8 00000000`00000000     0x00007ff8`4cc1e880

        THREAD ffffe10e0cfb32c0  Cid 2334.2964  Teb: 000000f5073b2000 Win32Thread: 0000000000000000 WAIT: (WrQueue) UserMode Alertable
            ffffe10e0d32ec40  QueueObject
        Not impersonating
        DeviceMap                 ffff8004c9ea3120
        Owning Process            ffffe10e0d4bb080       Image:         vmsp.exe
        Attached Process          N/A            Image:         N/A
        Wait Start TickCount      382658         Ticks: 466 (0:00:00:07.281)
        Context Switch Count      30             IdealProcessor: 16             
        UserTime                  00:00:00.000
        KernelTime                00:00:00.203
        Win32 Start Address 0x1000000140000060
        Stack Init fffff90c6e1bdc70 Current fffff90c6e1bd080
        Base fffff90c6e1be000 Limit fffff90c6e1b8000 Call 0000000000000000
        Priority 8 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
        Child-SP          RetAddr               Call Site
        fffff90c`6e1bd0c0 fffff806`21eccdc5     nt!KiSwapContext+0x76
        fffff90c`6e1bd200 fffff806`21ecdc2a     nt!KiSwapThread+0x545
        fffff90c`6e1bd2a0 fffff806`21f5eb70     nt!KiCommitThreadWait+0x15a
        fffff90c`6e1bd340 fffff806`21f5dc08     nt!KeRemoveQueueEx+0xbc0
        fffff90c`6e1bd400 fffff806`21f5d5b4     nt!IoRemoveIoCompletion+0x98
        fffff90c`6e1bd530 fffff806`2201dc04     nt!NtWaitForWorkViaWorkerFactory+0xdf4
        fffff90c`6e1bd760 fffff806`2204506a     nt!VslpDispatchIumSyscall+0x34
        fffff90c`6e1bd7e0 fffff806`224914ea     nt!VslpEnterIumSecureMode+0x1d447a
        fffff90c`6e1bd8b0 fffff806`22026cf8     nt!PspUserThreadStartup+0x1a65ba
        fffff90c`6e1bd9a0 fffff806`22026c60     nt!KiStartUserThread+0x28
        fffff90c`6e1bdae0 00007ff8`4cc1e880     nt!KiStartUserThreadReturn (TrapFrame @ fffff90c`6e1bdae0)
        000000f5`0716fa18 00000000`00000000     0x00007ff8`4cc1e880

        THREAD ffffe10e0d299080  Cid 2334.2470  Teb: 000000f5073b4000 Win32Thread: 0000000000000000 WAIT: (WrQueue) UserMode Alertable
            ffffe10e0d32ec40  QueueObject
        Not impersonating
        DeviceMap                 ffff8004c9ea3120
        Owning Process            ffffe10e0d4bb080       Image:         vmsp.exe
        Attached Process          N/A            Image:         N/A
        Wait Start TickCount      382670         Ticks: 454 (0:00:00:07.093)
        Context Switch Count      116            IdealProcessor: 18             
        UserTime                  00:00:00.000
        KernelTime                00:00:00.859
        Win32 Start Address 0x1000000140000060
        Stack Init fffff90c6e1c4c70 Current fffff90c6e1c4080
        Base fffff90c6e1c5000 Limit fffff90c6e1bf000 Call 0000000000000000
        Priority 9 BasePriority 8 PriorityDecrement 16 IoPriority 2 PagePriority 5
        Child-SP          RetAddr               Call Site
        fffff90c`6e1c40c0 fffff806`21eccdc5     nt!KiSwapContext+0x76
        fffff90c`6e1c4200 fffff806`21ecdc2a     nt!KiSwapThread+0x545
        fffff90c`6e1c42a0 fffff806`21f5eb70     nt!KiCommitThreadWait+0x15a
        fffff90c`6e1c4340 fffff806`21f5dc08     nt!KeRemoveQueueEx+0xbc0
        fffff90c`6e1c4400 fffff806`21f5d5b4     nt!IoRemoveIoCompletion+0x98
        fffff90c`6e1c4530 fffff806`2201dc04     nt!NtWaitForWorkViaWorkerFactory+0xdf4
        fffff90c`6e1c4760 fffff806`2204506a     nt!VslpDispatchIumSyscall+0x34
        fffff90c`6e1c47e0 fffff806`224914ea     nt!VslpEnterIumSecureMode+0x1d447a
        fffff90c`6e1c48b0 fffff806`22026cf8     nt!PspUserThreadStartup+0x1a65ba
        fffff90c`6e1c49a0 fffff806`22026c60     nt!KiStartUserThread+0x28
        fffff90c`6e1c4ae0 00007ff8`4cc1e880     nt!KiStartUserThreadReturn (TrapFrame @ fffff90c`6e1c4ae0)
        000000f5`071efba8 00000000`00000000     0x00007ff8`4cc1e880


7: kd> !thread ffffe10e0d57a080
THREAD ffffe10e0d57a080  Cid 2334.2ba4  Teb: 000000f5073b0000 Win32Thread: 0000000000000000 WAIT: (UserRequest) UserMode Non-Alertable
    ffffe10e0d67a560  NotificationEvent
Not impersonating
DeviceMap                 ffff8004c9ea3120
Owning Process            ffffe10e0d4bb080       Image:         vmsp.exe
Attached Process          N/A            Image:         N/A
Wait Start TickCount      382305         Ticks: 819 (0:00:00:12.796)
Context Switch Count      2              IdealProcessor: 14             
UserTime                  00:00:00.000
KernelTime                00:00:00.078
Win32 Start Address 0x00007ff6a26277d0
Stack Init fffff90c6e1afc70 Current fffff90c6e1af310
Base fffff90c6e1b0000 Limit fffff90c6e1aa000 Call 0000000000000000
Priority 9 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
Child-SP          RetAddr               : Args to Child                                                           : Call Site
fffff90c`6e1af350 fffff806`21eccdc5     : 00000000`00000000 fffff90c`00000000 ffff9a81`0ef00180 00000000`00000000 : nt!KiSwapContext+0x76
fffff90c`6e1af490 fffff806`21ecdc2a     : ffffe10e`00000000 00000000`00000000 ffffe10e`0d57a100 ffff33a8`00000000 : nt!KiSwapThread+0x545
fffff90c`6e1af530 fffff806`21ece886     : ffffe10e`00000000 fffff806`00000000 fffff90c`6e1af600 00000000`00000000 : nt!KiCommitThreadWait+0x15a
fffff90c`6e1af5d0 fffff806`223591ab     : ffffe10e`0d67a560 00000000`00000006 00000000`00000001 00000000`00000000 : nt!KeWaitForSingleObject+0x236
fffff90c`6e1af6c0 fffff806`223590da     : fffff90c`6e1af900 ffffe10e`0d57a080 00000000`00000001 00000000`00000000 : nt!ObWaitForSingleObject+0xbb
fffff90c`6e1af720 fffff806`2201dc04     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!NtWaitForSingleObject+0x6a
fffff90c`6e1af760 fffff806`2204506a     : 00000000`00000000 fffff90c`6e1af900 ffffe10e`0d57a080 00000000`00000001 : nt!VslpDispatchIumSyscall+0x34
fffff90c`6e1af7e0 fffff806`224914ea     : ffff9a81`0f300180 ffffe10e`0d57a080 ffff9a81`0f30c640 00000000`00000298 : nt!VslpEnterIumSecureMode+0x1d447a
fffff90c`6e1af8b0 fffff806`22026cf8     : ffff9a81`0f300180 ffffe10e`0d57a080 ffff9a81`0f30c640 00000000`00000000 : nt!PspUserThreadStartup+0x1a65ba
fffff90c`6e1af9a0 fffff806`22026c60     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiStartUserThread+0x28
fffff90c`6e1afae0 00007ff8`4cc1e880     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiStartUserThreadReturn (TrapFrame @ fffff90c`6e1afae0)
000000f5`070ef8e8 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : 0x00007ff8`4cc1e880
7: kd> !vtop 84f417000 0x00007ff6a26277d0 
Amd64VtoP: Virt 00007ff6a26277d0, pagedir 000000084f417000
Amd64VtoP: PML4E 000000084f4177f8
Amd64VtoP: PDPE 00000004be923ed0
Amd64VtoP: PDE 00000004b9b24898
Amd64VtoP: PTE 0000000845625138
Amd64VtoP: Mapped phys 000000049b36e7d0
Virtual address 7ff6a26277d0 translates to physical address 49b36e7d0.
7: kd> !db 49b36e7d0
#49b36e7d0 48 83 ec 28 e8 ff 04 00-00 48 83 c4 28 e9 5e fe H..(.....H..(.^.
#49b36e7e0 ff ff cc cc cc cc cc cc-cc cc cc cc cc cc cc cc ................
#49b36e7f0 cc cc cc cc cc cc 66 66-0f 1f 84 00 00 00 00 00 ......ff........
#49b36e800 48 3b 0d 79 d9 00 00 f2-75 12 48 c1 c1 10 66 f7 H;.y....u.H...f.
#49b36e810 c1 ff ff f2 75 02 f2 c3-48 c1 c9 10 e9 4f 00 00 ....u...H....O..
#49b36e820 00 cc cc cc cc cc cc cc-40 53 48 83 ec 20 48 8b ........@SH.. H.
#49b36e830 d9 33 c9 ff 15 3f 2f 00-00 48 8b cb ff 15 2e 2f .3...?/..H...../
#49b36e840 00 00 ff 15 e0 2f 00 00-48 8b c8 ba 09 04 00 c0 ...../..H.......
7: kd> .process ffffe10e0d4bb080 
Implicit process is now ffffe10e`0d4bb080
WARNING: .cache forcedecodeuser is not enabled
7: kd> db 0x00007ff6a26277d0
00007ff6`a26277d0  48 83 ec 28 e8 ff 04 00-00 48 83 c4 28 e9 5e fe  H..(.....H..(.^.
00007ff6`a26277e0  ff ff cc cc cc cc cc cc-cc cc cc cc cc cc cc cc  ................
00007ff6`a26277f0  cc cc cc cc cc cc 66 66-0f 1f 84 00 00 00 00 00  ......ff........
00007ff6`a2627800  48 3b 0d 79 d9 00 00 f2-75 12 48 c1 c1 10 66 f7  H;.y....u.H...f.
00007ff6`a2627810  c1 ff ff f2 75 02 f2 c3-48 c1 c9 10 e9 4f 00 00  ....u...H....O..
00007ff6`a2627820  00 cc cc cc cc cc cc cc-40 53 48 83 ec 20 48 8b  ........@SH.. H.
00007ff6`a2627830  d9 33 c9 ff 15 3f 2f 00-00 48 8b cb ff 15 2e 2f  .3...?/..H...../
00007ff6`a2627840  00 00 ff 15 e0 2f 00 00-48 8b c8 ba 09 04 00 c0  ...../..H.......
7: kd> eb 0x00007ff6a26277d0 11
                              ^ Memory access error in 'eb 0x00007ff6a26277d0 11'
7: kd> !db 49b36e7d0 
#49b36e7d0 48 83 ec 28 e8 ff 04 00-00 48 83 c4 28 e9 5e fe H..(.....H..(.^.
#49b36e7e0 ff ff cc cc cc cc cc cc-cc cc cc cc cc cc cc cc ................
#49b36e7f0 cc cc cc cc cc cc 66 66-0f 1f 84 00 00 00 00 00 ......ff........
#49b36e800 48 3b 0d 79 d9 00 00 f2-75 12 48 c1 c1 10 66 f7 H;.y....u.H...f.
#49b36e810 c1 ff ff f2 75 02 f2 c3-48 c1 c9 10 e9 4f 00 00 ....u...H....O..
#49b36e820 00 cc cc cc cc cc cc cc-40 53 48 83 ec 20 48 8b ........@SH.. H.
#49b36e830 d9 33 c9 ff 15 3f 2f 00-00 48 8b cb ff 15 2e 2f .3...?/..H...../
#49b36e840 00 00 ff 15 e0 2f 00 00-48 8b c8 ba 09 04 00 c0 ...../..H.......
7: kd> !eb 49b36e7d0  11
Physical memory write at 49b36e7d0 failed
If you know the caching attributes used for the memory,
try specifying [c], [uc] or [wc], as in !dd [c] <params>.
WARNING: Incorrect use of these flags will cause unpredictable
processor corruption.  This may immediately (or at any time in
the future until reboot) result in a system hang, incorrect data
being displayed or other strange crashes and corruption.
```

通过上面的调试发现，在VTL0环境下，即使拥有ring0权限，依然无法对物理地址0x49b36e7d0进行修改。

下面再回到hypervisor调试的场景，我们来看看到底为什么VTL0下Ring0无法访问到这片内存。

```none
6: kd> !vtop 0x12382301e 49b36e7d0 //这个是VTL0环境的地址转换
Amd64VtoP: Virt 000000049b36e7d0, pagedir 0000000123823000
Amd64VtoP: PML4E 0000000123823000
Amd64VtoP: PDPE 0000000123829090
Amd64VtoP: PDE 00000001219876c8
Amd64VtoP: Large page mapped phys 000000049b36e7d0
Virtual address 49b36e7d0 translates to physical address 49b36e7d0.
6: kd> !vtop 0x12382501e 49b36e7d0 //这个是VTL1环境的地址转换
Amd64VtoP: Virt 000000049b36e7d0, pagedir 0000000123825000
Amd64VtoP: PML4E 0000000123825000
Amd64VtoP: PDPE 000000012382b090
Amd64VtoP: PDE 00000001219886c8
Amd64VtoP: Large page mapped phys 000000049b36e7d0
Virtual address 49b36e7d0 translates to physical address 49b36e7d0.
```

这里发现，root分区的物理地址0x49b36e7d0经过二级地址转换后依然还是0x49b36e7d0，因为所处的分区是root分区的原因，所以转换前后的物理地址都是一致的。但是差别出现在权限上。

根据Intel用户手册发现。

 ![](/attachments/2024-08-21-windows-vtl-ium/98b98a90-65ad-4cc2-bd1d-0eeaaa65c4e7.png)

如果我们修改最后PDE的读写权限，就可以实现VTL的隔离操作了，下面调试验证一下。

```none
7: kd> !dq 0000000121987000+80*d //VTL0 环境下
#121987680 00000004`9a0007b7 00000004`9a2007b7
#121987690 00000004`9a4007b7 00000004`9a6007b7
#1219876a0 00000004`9a8007b7 00000004`9aa007b7
#1219876b0 00000004`9ac007b7 00000004`9ae007b7
#1219876c0 00000004`9b0007b7 00000004`9b2005b5 //哦豁，盲生，你发现了华点！对应低三bits，就是没有写权限
#1219876d0 00000004`9b4007b7 00000004`9b6007b7
#1219876e0 00000004`9b8007b7 00000004`9ba007b7
#1219876f0 00000004`9bc007b7 00000004`9be007b7
19: kd> !dq 121988000 +80*d //VTL1 环境下
#121988680 00000004`9a0007b7 00000004`9a2007b7
#121988690 00000004`9a4007b7 00000004`9a6007b7
#1219886a0 00000004`9a8007b7 00000004`9aa007b7
#1219886b0 00000004`9ac007b7 00000004`9ae007b7
#1219886c0 00000004`9b0007b7 00000004`9b2007b7 //VTL1环境下就是读写执行权限全给
#1219886d0 00000004`9b4007b7 00000004`9b6007b7
#1219886e0 00000004`9b8007b7 00000004`9ba007b7
#1219886f0 00000004`9bc007b7 00000004`9be007b7
```

那么，我们照猫画虎，把VTL0环境下的PTE条目给他改成0x4\`9b2007b7，看看VTL0环境下是否还会无法写入数据。

Hypervisor调试

```none
7: kd> !ed 1219876c8 9b2007b7
7: kd> !dq 1219876c8
#1219876c8 00000004`9b2007b7 00000004`9b4007b7
#1219876d8 00000004`9b6007b7 00000004`9b8007b7
#1219876e8 00000004`9ba007b7 00000004`9bc007b7
#1219876f8 00000004`9be007b7 00000004`9c0007b7
#121987708 00000004`9c2007b7 00000004`9c4007b7
#121987718 00000004`9c6007b7 00000004`9c8007b7
#121987728 00000004`9ca007b7 00000004`9cc007b7
#121987738 00000004`9ce007b7 00000004`9d0007b7
```

Ring0调试

```none
7: kd> .process ffffe10e0d4bb080 
Implicit process is now ffffe10e`0d4bb080
WARNING: .cache forcedecodeuser is not enabled
7: kd> db 0x00007ff6a26277d0
00007ff6`a26277d0  48 83 ec 28 e8 ff 04 00-00 48 83 c4 28 e9 5e fe  H..(.....H..(.^.
00007ff6`a26277e0  ff ff cc cc cc cc cc cc-cc cc cc cc cc cc cc cc  ................
00007ff6`a26277f0  cc cc cc cc cc cc 66 66-0f 1f 84 00 00 00 00 00  ......ff........
00007ff6`a2627800  48 3b 0d 79 d9 00 00 f2-75 12 48 c1 c1 10 66 f7  H;.y....u.H...f.
00007ff6`a2627810  c1 ff ff f2 75 02 f2 c3-48 c1 c9 10 e9 4f 00 00  ....u...H....O..
00007ff6`a2627820  00 cc cc cc cc cc cc cc-40 53 48 83 ec 20 48 8b  ........@SH.. H.
00007ff6`a2627830  d9 33 c9 ff 15 3f 2f 00-00 48 8b cb ff 15 2e 2f  .3...?/..H...../
00007ff6`a2627840  00 00 ff 15 e0 2f 00 00-48 8b c8 ba 09 04 00 c0  ...../..H.......
7: kd> eb 0x00007ff6a26277d0 11
7: kd> db 0x00007ff6a26277d0
00007ff6`a26277d0  11 83 ec 28 e8 ff 04 00-00 48 83 c4 28 e9 5e fe  ...(.....H..(.^.
00007ff6`a26277e0  ff ff cc cc cc cc cc cc-cc cc cc cc cc cc cc cc  ................
00007ff6`a26277f0  cc cc cc cc cc cc 66 66-0f 1f 84 00 00 00 00 00  ......ff........
00007ff6`a2627800  48 3b 0d 79 d9 00 00 f2-75 12 48 c1 c1 10 66 f7  H;.y....u.H...f.
00007ff6`a2627810  c1 ff ff f2 75 02 f2 c3-48 c1 c9 10 e9 4f 00 00  ....u...H....O..
00007ff6`a2627820  00 cc cc cc cc cc cc cc-40 53 48 83 ec 20 48 8b  ........@SH.. H.
00007ff6`a2627830  d9 33 c9 ff 15 3f 2f 00-00 48 8b cb ff 15 2e 2f  .3...?/..H...../
00007ff6`a2627840  00 00 ff 15 e0 2f 00 00-48 8b c8 ba 09 04 00 c0  ...../..H.......
7: kd> eb 0x00007ff6a26277d0 48
7: kd> db 0x00007ff6a26277d0
00007ff6`a26277d0  48 83 ec 28 e8 ff 04 00-00 48 83 c4 28 e9 5e fe  H..(.....H..(.^.
00007ff6`a26277e0  ff ff cc cc cc cc cc cc-cc cc cc cc cc cc cc cc  ................
00007ff6`a26277f0  cc cc cc cc cc cc 66 66-0f 1f 84 00 00 00 00 00  ......ff........
00007ff6`a2627800  48 3b 0d 79 d9 00 00 f2-75 12 48 c1 c1 10 66 f7  H;.y....u.H...f.
00007ff6`a2627810  c1 ff ff f2 75 02 f2 c3-48 c1 c9 10 e9 4f 00 00  ....u...H....O..
00007ff6`a2627820  00 cc cc cc cc cc cc cc-40 53 48 83 ec 20 48 8b  ........@SH.. H.
00007ff6`a2627830  d9 33 c9 ff 15 3f 2f 00-00 48 8b cb ff 15 2e 2f  .3...?/..H...../
00007ff6`a2627840  00 00 ff 15 e0 2f 00 00-48 8b c8 ba 09 04 00 c0  ...../..H.......
```

内存修改的极度丝滑！vmsp进程的VTL内存隔离已经被打破，我们可以对IUM进程空间内存进行任意修改。

简单的总结下：

 ![](/attachments/2024-08-21-windows-vtl-ium/f867f973-3754-4df5-8a3e-4055e47f449a.png)

## 五、调试IUM进程

介绍了完了VTL机制，我们来介绍下比较实际的技巧，因为IUM进程无法在用户态被正常attach，这种情况无疑对安全研究造成了些许阻碍，下面我们就来介绍如何开启IUM进程的调试。

首先，我们要找到securekenel.exe的基址，然后patch掉securekernel!SkpsIsProcessDebuggingEnabled中关于调试attach判断的代码。

首先，进行hypervisor的调试

```none
Breakpoint 1 hit
hv+0x211248:
fffff83b`24f56248 0fc7b188010000  vmptrld qword ptr [rcx+188h]
2: kd> bd 1
2: kd> !vmread 0x201a
@$vmread(0x201a) : 0x12382301e
2: kd> !vmread 0x6802
@$vmread(0x6802) : 0x1aa002
2: kd> !vmread 0x681c //VTL0 Guest RSP
@$vmread(0x681c) : 0xfffff90c646f28e8
2: kd> p
hv+0x21124f:
fffff83b`24f5624f e99cfeffff      jmp     hv+0x2110f0 (fffff83b`24f560f0)
2: kd> !vmread 0x201a
@$vmread(0x201a) : 0x12382501e
2: kd> !vmread 0x6802
@$vmread(0x6802) : 0x4c00000
2: kd> !vmread 0x681c //VTL1 Guest RSP
@$vmread(0x681c) : 0xffff9e003ef75ec8
2: kd> !vtop 0x4c00000 0xffff9e003ef75ec8
Amd64VtoP: Virt ffff9e003ef75ec8, pagedir 0000000004c00000
Amd64VtoP: PML4E 0000000004c009e0
Amd64VtoP: PDPE 0000000004c0b000
Amd64VtoP: PDE 0000000004c0cfb8
Amd64VtoP: PTE 0000000128dc1ba8
Amd64VtoP: Mapped phys 0000000128dacec8
Virtual address ffff9e003ef75ec8 translates to physical address 128dacec8.
2: kd> !dq 128dacec8
#128dacec8 fffff806`26d05b9a 00000000`00000001 //栈顶，返回地址0xfffff806`26d05b9a 
#128daced8 fffff90c`00000000 00000000`00d10002
#128dacee8 ffff9e00`3ef75ed0 00000000`00000000
#128dacef8 00000000`00000000 00000000`00000000
#128dacf08 00000000`00000000 00000000`00000000
#128dacf18 00000000`00000000 00000000`00000000
#128dacf28 00000000`00000000 00000000`00000000
#128dacf38 00000000`00000000 00000000`00000000
2: kd> !vtop 0x4c00000  fffff80626d05b9a
Amd64VtoP: Virt fffff80626d05b9a, pagedir 0000000004c00000
Amd64VtoP: PML4E 0000000004c00f80
Amd64VtoP: PDPE 0000000004c030c0
Amd64VtoP: PDE 0000000004c029b0
Amd64VtoP: PTE 0000000004c01828
Amd64VtoP: Mapped phys 0000000002eaeb9a
Virtual address fffff80626d05b9a translates to physical address 2eaeb9a.
2: kd> !db 2eaeb9a
# 2eaeb9a 48 89 04 24 48 89 6c 24-08 48 89 54 24 10 65 48 H..$H.l$.H.T$.eH
# 2eaebaa 8b 04 25 10 00 00 00 48-8b ec 48 89 48 10 48 8b ..%....H..H.H.H.
# 2eaebba 0c 24 48 89 48 08 65 f6-04 25 b8 09 00 00 01 74 .$H.H.e..%.....t
# 2eaebca 4c 65 80 24 25 b8 09 00-00 f7 65 0f b6 04 25 ba Le.$%.....e...%.
# 2eaebda 09 00 00 65 38 04 25 c0-09 00 00 74 11 65 88 04 ...e8.%....t.e..
# 2eaebea 25 c0 09 00 00 b9 48 00-00 00 33 d2 0f 30 65 0f %.....H...3..0e.
# 2eaebfa b6 14 25 b8 09 00 00 f7-c2 04 00 00 00 74 0e b8 ..%..........t..
# 2eaec0a 01 00 00 00 33 d2 b9 49-00 00 00 0f 30 0f ae e8 ....3..I....0...
```

到了这里我们可以使用IDA的内存搜索，搜索`48 89 04 24 48 89 6c 24`字节码，得到了如下地址：

 ![](/attachments/2024-08-21-windows-vtl-ium/c577863d-1cab-452b-a5bb-cb1460d92516.png)

知道了目前的函数偏移，我们可以轻松的推断出securekernel.exe的基物理地址是：0x2e40000

```none
2: kd> !db 2eaeb9a-6EB9A 
# 2e40000 4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00 MZ..............
# 2e40010 b8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00 ........@.......
# 2e40020 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
# 2e40030 00 00 00 00 00 00 00 00-00 00 00 00 00 01 00 00 ................
# 2e40040 0e 1f ba 0e 00 b4 09 cd-21 b8 01 4c cd 21 54 68 ........!..L.!Th
# 2e40050 69 73 20 70 72 6f 67 72-61 6d 20 63 61 6e 6e 6f is program canno
# 2e40060 74 20 62 65 20 72 75 6e-20 69 6e 20 44 4f 53 20 t be run in DOS 
# 2e40070 6d 6f 64 65 2e 0d 0d 0a-24 00 00 00 00 00 00 00 mode....$.......
```

我们要进行patch的函数SkpsIsProcessDebuggingEnabled偏移是0x9EDD3，这里把`mov al, bl`patch成`mov al, 1`。对应的字节码就是`8a c3` --> `B0 01`。

```none
2: kd> !db 2e40000 +9EDD3
# 2ededd3 8a c3 48 8b 4c 24 58 48-33 cc e8 3e 5c fa ff 4c ..H.L$XH3..>\..L
# 2edede3 8d 5c 24 60 49 8b 5b 18-49 8b 73 20 49 8b e3 5f .\$`I.[.I.s I.._
# 2ededf3 c3 cc cc cc cc cc cc cc-cc 4c 8b dc 48 83 ec 38 .........L..H..8
# 2edee03 83 64 24 48 00 49 8d 43-18 ba 03 00 00 00 49 c7 .d$H.I.C......I.
# 2edee13 43 18 04 00 00 00 4d 8d-4b 10 49 89 43 e8 44 8d C.....M.K.I.C.D.
# 2edee23 42 04 e8 92 02 00 00 85-c0 78 0b b8 01 00 00 00 B........x......
# 2edee33 39 44 24 48 74 02 32 c0-48 83 c4 38 c3 cc cc cc 9D$Ht.2.H..8....
# 2edee43 cc cc cc cc cc 48 89 5c-24 20 89 4c 24 08 56 57 .....H.\$ .L$.VW
2: kd> !eb 2ededd3 b0
2: kd> !eb 2ededd4 1
2: kd> !db 2e40000 +9EDD3
# 2ededd3 b0 01 48 8b 4c 24 58 48-33 cc e8 3e 5c fa ff 4c ..H.L$XH3..>\..L
# 2edede3 8d 5c 24 60 49 8b 5b 18-49 8b 73 20 49 8b e3 5f .\$`I.[.I.s I.._
# 2ededf3 c3 cc cc cc cc cc cc cc-cc 4c 8b dc 48 83 ec 38 .........L..H..8
# 2edee03 83 64 24 48 00 49 8d 43-18 ba 03 00 00 00 49 c7 .d$H.I.C......I.
# 2edee13 43 18 04 00 00 00 4d 8d-4b 10 49 89 43 e8 44 8d C.....M.K.I.C.D.
# 2edee23 42 04 e8 92 02 00 00 85-c0 78 0b b8 01 00 00 00 B........x......
# 2edee33 39 44 24 48 74 02 32 c0-48 83 c4 38 c3 cc cc cc 9D$Ht.2.H..8....
# 2edee43 cc cc cc cc cc 48 89 5c-24 20 89 4c 24 08 56 57 .....H.\$ .L$.VW
```

最后回到用户态用windbg尝试attach一下。

 ![](/attachments/2024-08-21-windows-vtl-ium/0f752483-b9c8-4996-a8cc-7bbe8ff3f4e2.png)

秒杀！

## 六、总结

简单探索了Windows下的VTL机制和IUM进程的调试，介绍了一小部分的Intel硬件虚拟化技术。总的来说，虚拟化对于Windows不仅限于Hyper-V虚拟化软件，还渗透在Windows操作系统的安全措施中，足以看出微软对虚拟化的重视程度。在撰写本文时，主要参考了QuarksLab的这两篇文章（[A virtual journey: From hardware virtualization to Hyper-V's Virtual Trust Levels](https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html), [Debugging Windows Isolated User Mode (IUM) Processes](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html)），感兴趣的小伙伴可以去了解一下。

## 七、References

1. [虚拟安全模式](https://learn.microsoft.com/zh-cn/virtualization/hyper-v-on-windows/tlfs/vsm)
2. [隔离用户模式 (IUM) 进程](https://learn.microsoft.com/zh-cn/windows/win32/procthread/isolated-user-mode--ium--processes)
3. **[A virtual journey: From hardware virtualization to Hyper-V's Virtual Trust Levels](https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html "Permalink to A virtual journey: From hardware virtualization to Hyper-V's Virtual Trust Levels")**
4. **[Debugging Windows Isolated User Mode (IUM) Processes](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html "Permalink to Debugging Windows Isolated User Mode (IUM) Processes")**
5. [Hypervisor Top Level Functional Specification](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs)
6. [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
