---
slug: tiangongarticle044
date: 2024-09-04
title: 【DEFCON & HITB】Bug Hunting In VMware Device Virtualization（上篇）
author: s0duku
tags: ["议题解读", "DEFCONF", "HITB"]
---

奇安信天工实验室安全研究成果，入选国际顶级安全会议DEFCON 32 和 HITBSecConf 2024，议题名称《Dragon Slaying Guide: Bug Hunting In VMware Device Virtualization》。

我们将该议题分为三篇文章进行详细讲解。本文是第一篇，主要介绍VMware虚拟化实现，为后续深入探讨VMware虚拟设备漏洞挖掘打下坚实的理论基础。

## 一、Introduction

VMware Workstation/ESXi是市场上最流行的商用虚拟化软件之一。其复杂的虚拟化系统设计和在基础设施中的关键地位使其长期成为黑客的顶级目标。对于安全研究人员来说，发现VMware Hypervisor中的虚拟化逃逸漏洞就像在角色扮演游戏中与巨龙较量一样具有挑战性。

**本议题揭露了一个新型攻击面：Device Virtualization in VMKernel** 。这是迄今为止，尚未被安全研究探索的未知领地。且该攻击视角尚未被VMware考虑进防御体系，其现有的沙箱机制理论上完全无法防御从VMKernel发起的攻击。在对本次攻击面的分析和VMware Hypervisor的逆向工程中，我们发现了8个与设备虚拟化相关的漏洞，其中5个漏洞已经被分配了CVE编号(CVE-2024-22251、CVE-2024-22252、CVE-2024-22255、CVE-2024-22273、CVE-2024-37086)，其余3个漏洞已经被VMware确认。

本议题将从VMware虚拟化实现、USB Device Virtualization 和 SCSI Device Virtualization 三个部分递进讲解，如何发现VMKernel这个攻击面，找到多个未知漏洞的过程。

本周将为大家介绍第一部分：VMware虚拟化实现。该部分会深入介绍 vmm 的加载过程，vmm与vmx数据共享功能的实现，VMware的UserRPC这一Hypervisor与Host通信的实现，这些都是在虚拟设备模拟中至关重要的机制。

## 二、VMware Virtualization Details

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/993fef41-27e0-41e5-8ef6-cb37ada16459.png " =764x394.5")

我们将通过介绍我们对VMware 设备虚拟化的逆向工作，来展示我们是如何发现VMKernel这一与设备虚拟化相关的新攻击面的。为了方便阐述我们会用自己逆向所定义的符号名配合代码片段进行解释，其中也有部分符号直接来自于open-vm-tools，我们发现open-vm-tools与vmx共享很多通用数据结构，这加速了我们的逆向分析过程。

我们都知道VMware利用UserRpc机制完成了对很多虚拟设备的实现，在分析具体UserRpcHandler时我们总是会发现vmx经常会使用一些与vmm称为SharedArea 的共享数据，只审计UserRpcHandler我们无法判断这些数据的来源与去向，这时常会让我们有些抓狂。所以我们决定首先分析 UserRpc 的实现，以了解VMware在设备虚拟化方面的工作流程，判断我们在Guest中的数据可以影响的二进制代码块。

## 三、UserRpc In VMX

当 vmx 进程启动时，其最重要的部分就是按顺序初始化系统需要使用的所有模块，这个模块的表项由模块名和启动初始化函数组成，他很容易从二进制入口点静态分析追踪到，除此之外我们还使用了API Monitor 来监控vmx与内核模块vmx86.sys的通信过程，通过IOCTL指令立即数，我们能在vmx中定位到对应请求发起的位置，以及在vmx86.sys中对应的处理代码。幸运的是，我们能在IDA中看到一些调试日志字符串，这让我们更容易理解相应IOCTL指令的含义。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/83cc9b41-67d4-4710-b3cc-bdba72000bb8.png " =636x133.5")

首先引起我们注意的便是 "IOCTL_VMX86_RUN_VM" 这条指令，他被调用于一个线程的循环内。代码结构上，它一直保持循环调用并会使用 IOCTL_VMX86_RUN_VM 的返回值作为参数之一传递给 Monitor_ProcessUserRpcCall 负责调用对应的处理函数。这种代码结构正是我们需要寻找的 vmm 切回宿主机并调用 vmx 处理UserRpc请求的过程代码，Monitor_ProcessUserRpcCall 其中调用功能函数表就是 Vmware 的 UserRPC 功能在 vmx 侧的实现，并且这些UserRpcHandler函数使用了称为userRpcBlock的共享内存区域指针作为其唯一的参数。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/63490b88-2430-464e-80d4-1e21b7516809.jpeg)

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/9c6d3848-dd61-44c9-8dcf-f8a7c5446833.png " =1168x418")

## 四、SharedArea Implementation

SharedArea_Lookup 函数负责获取 userRpcBlock 指针，这个接口实际上负责查询所有 vmx 与 vmm 之间的SharedArea共享内存，它以在符号名字符串，内存区域大小为参数查找由 SharedArea 模块初始化的全局哈希表中保存的共享内存区域信息，并最终返回目标共享内存区域在vmx进程上下文中的内存地址。

SharedArea的实现和vmm的创建与加载息息相关，SharedArea模块的初始化函数会首先抽取嵌入在vmx 二进制文件中的Elf Object格式的vmmblob文件。提取此文件后，我们可以在 vmmblob 中的 .shared_per_vcpu_vmx 节发现 userRpcBlock 等预定义的导出符号及其相应的映射地址。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/ce15583b-679e-452e-95f6-0c9887fbf9c6.png " =428x81.5")

VMware 在 vmx 中实现了 ELF 格式链接器的代码，并会根据配置 .vmx 用户配置决定在 vmm 是否启用对应的虚拟设备扩展，这些扩展同样是ELF object 文件并且以节的形式被一起保存在 vmmblob 的 vmmmods 节中。

有些虚拟设备实现需要在 vmm 侧留出共享内存，vmx 在与SharedArea相关的section中定义出对应大小的导出符号，最终所有vmm相关的模块会通过链接器重新链接。vmm 在 vmx 内存中完成组装后，vmx 会计算所有SharedArea 内存大小并分配对应内存空间。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/63f4eaf0-5b66-4e12-bcc2-ca2cbbec7c2a.png)

通过分析 APIMonitor的记录以及模块在vmx中初始化的顺序，在vmm完成组装后首先一处重要的IO调用号为 0x81013F4C，通过逆向分析他在vmx86.sys中负责创建虚拟机对象动作，该调用使用vmmblob的.host_params节区为参数，vmx86.sys 将会根据 .host_param 内容准备 vmm 环境下的 gdt 表。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/ff566a4c-046f-45a9-a473-0663f3d427c5.png)

值得注意的是，由于 vmmblob 相关的 binary 还包含大量的带有类型信息以及符号的代码，尤其是这些类型和代码有些还会在 vmx 或vmx86 中共享，比如 vmmblob 中也包含 Elf 链接器相关的代码。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/ced58c7a-b27c-4938-bff8-eeeb80469238.png " =817.5x232.5")

在 vmx 调用 vmx86.sys 完成基本虚拟机对象创建后，vmx 随后会通知 vmx86.sys 准备 vmm 的运行环境。vmx 首先会抽取 vmmblob 中的 .monLoader 节并根据其内容制作 vmm 下的必要的页表环境，同时还会一同传递为sharedArea分配的内存空间信息，基本上 SharedArea 的实现就是由 vmx 分配内存空间，并根据vmmblob提供的信息为 vmm 构建其页表环境从而完成内存的直接映射。另外由于 vmmblob 存在类型信息，我们可以很容易恢复 .monLoader 表项符号，通过 monloader 的信息我们可以在逆向 vmm 时判断代码中所使用的绝对地址的含义。

 ![7](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/3362cb17-2e3d-4192-b3e8-35d5b8ffaba3.png " =550.5x416")

## 五、VMM Switch Implementation

vmx86.sys 会为每个 vcpu 分配一个页大小称为 CrossPage 的内存区域，他会负责保存 vmm 与 host 之间共享数据，随后 vmx86 还会根据 .monloader 表项信息分配必要的内存空间并加载从vmmblob或主机上加载数据，并计算对应物理页号填充给 vmm即将使用的页表结构，逆向.monLoader的处理过程中可以发现 CrossPage 被映射到了 vmm 的 0xFFFFFFFFFCA00 虚拟页上，vmm会通过访问这个地址与Host交换数据。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/e2df5a9d-4db8-471f-be16-22c300233e25.png)

在 vmx86.sys 对准备好vmm的运行时环境后，vmx 就可以通过前文提到的 IOCTL_VMX86_RUN_VM 从 host 切入 vmm。通过调用 HostSwitchToVmm 代码片段，Host 会负责将CPU当前状态保存至 CrossPage中，包括cr3寄存器等系统级上下文，同时把 CrossPage 中保存的 vmm 运行时上下文恢复到当前 CPU，以此来完成从 Host 到 vmm 的入，切出操作则是与之相反。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/1a73b1a2-4a15-4df7-bb47-06c69949faef.png)

## 六、UserRpc In VMM

实际上vmm的核心实现集中在 vmm.vmm 这个子模块中，其中包含了对x86指令的模拟处理过程，但我们并没有太过深入研究它，当vmm需要发起UserRpc时，他就会切出vmm返回host，而UserRpc内部的通过PlatformUserCall实现，PlatformUserCall将opcode保存至 vmm 的 0xFFFFFFFFFCA00550 地址处，以及ModuleCall调用号100放到0xFFFFFFFFFCA00428处，随后切回Host下的vmx86.sys上下文中。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/60213c99-2684-4d59-b484-a10e347908ae.png)

前两个地址刚好其实就是 CrossPage 的偏移 0x550 和 0x428 处。vmx86.sys 分析 ModuleCall 调用号并选择不同的处理代码，在 UserRpc调用的情况下，vmx86.sys 会选择将 CrossPage 0x550 处保存的 opcode 返回给 vmx，在 vmx 的 IOCTL_VMX86_RUN_VM 主循环中，vmx 会根据此调用号选择对应的UserRpcHandler进行处理，至于参数UserRpcBlock 也正是vmm借助SharedArea在Host与Vmm内存的直接映射，将内容保存进去，以作为参数给 RpcHandler 使用。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/03b65c9e-f9d3-4edd-aec4-fff16d2151b9.png)

## 七、Device Virtualization

在设备虚拟化方面，对于 IN/OUT 指令的模拟则是借助了 UserRpc 这一机制，当 vmm 解析 IO 指令完成后它会使用IOSpaceInOutWork来模拟，并有可能尝试使用 UserRPC(317) 传呼 vmx 进行处理, vmx 中对应 RPCHandler 则会根据相应设备注册的回调函数执行模拟过程。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/52e399f5-8801-44b9-989a-1c9eea770341.png)

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/2dc27f18-84c4-4192-a7d2-8cb4093b591d.png)

除此之外，并非所有设备都会在 vmx 中注册IO回调函数，有些设备则是将IO回调函数放在vmm中执行。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/91fc1c86-d688-4f1f-b74c-b8d44fe90424.png)

对于 mmio 方面，在默认情况下，大部分内存区域，vmx 都时使用一个 id 将其和 vmm 中对应的 MemHandler 联系起来，vmm 在处理 GuestMem_AccessLinear 时，会根据访问的地址范围，找出对应回调函数 id，并尝试调用 mmio 模拟函数。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/0180d614-fe97-4f34-9711-4d9f1c04eb08.png)

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/4861dc2b-9e79-4926-9fa3-1618851c5207.png)

大部分mmio最终还是会使用 UserRpc 回调 vmx 中相关的处理例程，但他们先会对请求做初步处理，尤其是虚拟设备在vmx中几乎都会使用SharedArea与vmm之间共享内存数据，如果我们想要分析代码的细节不得不对 vmm 中 memHandler 处理过程先进行分析。

最后一个在设备虚拟化中值得注意的点时 vmx 访问物理内存的接口，基本上所有对物理内存的访问，都有类似的调用形式，首先根据物理地址获取物理内存的表示对象，然后根据对象的类型一般是使用vmx中的内存直接访问，也有可能会利用一些临时缓冲区以代替不能访问的内存，我们曾使用 frida 对这个接口做过一些调用参数上的调试希望能查看他是否有类似 qemu 那样递归访问 mmio 内容的特性，但似乎VMware并没有这样的实现，但VMware历史上数个虚拟设备中出现内存未初始化问题，实际上都与这个接口的实现不当有关，未初始化的对象实际上都是这个接口返回的物理内存的表示对象。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/0529bae2-7edc-41d1-a713-a3203fb056ab.png " =474.5x209")

总而言之，我们认为在涉及虚拟化的技术上，对内存访问接口的审计也是至关重要的一环，内存访问接口不仅仅直接指出了受到Guest数据影响的代码位置，更有可能带有一些独有的特性或问题。

## 八、Device Virtualization In VMKernel

vmx在Workstation和Esxi上代码逻辑几乎是一样的，但在分析虚拟设备实现我们发现个别设备在 vmm 中处理 Guest 的MMIO访问请求时表现会有所不同，Esxi 上vmm会将请求初步处理并使用 vmkcall 的形式调用 VMKernerl 中对应处理函数进行处理，这一点使得Esxi和Workstation在部分虚拟设备的实现上会有显著不同，这也为我们打开了新的值得审计的二进制模块，即 VMKernel。

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/75d7ba67-ff4a-4b55-86ff-4d9c68aa6916.png " =402x60")

 ![](/attachments/2024-09-04-defcon-hitbbug-hunting-in-vmware-device-virtualization/2e59a659-f4bc-44ef-b709-bb47c80d9827.png " =534.5x312")

VMKernel 使用 World (类似进程的概念)组织 Guest 虚拟机，并将 World 以组的形式组织在一起在内核中共享必要的数据。在我们代码审计过程中能在 vmm 中虚拟设备相关的模块发现一些使用ud2指令实现的断言错误，但一般只能导致当前虚拟机相关的World组中所有World因为错误退出，仅仅只是 self-dos。但是到了VMKernel下情况截然不同，即便是断言错误这样在vmm中可能出现的无关紧要的问题，到了VMKernel场景下都有可能带来对其他Guest Machine的拒绝服务攻击。

## 九、Conclusion

本篇文章作为该议题的第一部分，主要是深入介绍了VMware Hypervisor系统架构，能够对后续具体虚拟设备的漏洞挖掘提供重要参考：它可以帮助确定Guest数据能够影响的Hypervisor代码片段；了解操纵虚拟设备的完整流程，特别是像SVGA这样缺乏公开设计文档的私有设备；甚至发现一些不常见的功能或虚拟设备模拟代码。总而言之，对VMM（虚拟机管理程序）的分析至关重要，它贯穿于我们对整个虚拟设备实现的逆向分析过程中。

该系列的另外两部分内容将分别介绍USB Device Virtualization和SCSI Device Virtualization，侧重于USB设备和SCSI设备的漏洞挖掘实战。这两篇文章也将陆续在本公众号发布。