---
slug: tiangongarticle046
date: 2024-09-18
title: 【DEFCON & HITB】Bug Hunting In VMware Device Virtualization（下篇）
author: s0duku
tags: ["议题解读", "DEFCONF", "HITB"]
---

本文是天工实验室在DEFCON上发表的议题《Dragon Slaying Guide: Bug Hunting in VMware Device Virtualization》的第三部分内容。在该议题的前两篇文章中，分别介绍了VMware虚拟化实现和虚拟USB设备漏洞挖掘。

本周将继续讲解议题最后一个部分：**SCSI Device Virtualization**。主要介绍虚拟磁盘系统SCSI相关设备模拟在VMware Workstation和ESXI下的异同，以及我们在VMKernel中发现的有关磁盘设备模拟的设计缺陷。

## 一、前言

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/fe31ba25-6277-45f8-ba1a-eef851ff224b.png)

磁盘设备的代码架构和USB设备类似，首先他有许多作为前端的主机控制器设备模拟代码，比如 LsiLogic，NVME，PVSCSI，AHCI，有趣的地方在与作为连同主机控制器与磁盘设备的中间层代码实际上只处理SCSI协议指令，VMware为每种主机控制器都设计了用于将主机控制器请求翻译成SCSI请求的代码，所有不同磁盘设备的主机控制器请求在最终都会被统一成SCSI指令，后端设备模拟代码同样使用了类似面向对象的设计，从基本的SCSI设备对象可以派生出各种不同类型的设备，CDROM，Disk 等等。

无论是Esxi还是Workstation的 vmx 都有几乎一样的处理代码，但真正引起我们注意的是 Esxi 在默认情况下并没有使用 vmx 中对磁盘请求处理的代码，只有在启用了 HostEmulated 配置时，才会由vmx负责处理。

通过前文对 vmm 部分的分析，我们发现Esxi默认情况下正是通过 vmm 中对 VMKernel 的调用使用 VMKernel 中对应的模拟代码进行处理，这很快就引起了我们的兴趣，在 VMKernel 的范围下，哪怕是出现断言错误都可能带来整个 Hypervisor 的瘫痪，从而引起单个Esxi上所有客户机拒绝服务。

## 二、漏洞一：CVE-2024-22273：Out-of-bounds Read/Write

关于磁盘部分的第一个漏洞，如果按照控制器-后端设备模型来看，它处于后端设备模拟部分。

VMware会将所有请求在模拟阶段统一转化为SCSI指令，接着解析你访问的磁盘ID，根据磁盘ID来将SCSI指令转发到对应的设备上。转发这一过程，在VMware中有一个专门的函数进行处理，我们将其称为SCSIDevice_Dispatch。在SCSIDevice_Dispatch函数中，首先会解析你SCSI指令中的CDB部分，判断CDB请求是否符合要求。处理完CDB请求后，会来到我们将其称为HBAHosted_PostIo的函数中。

该函数中有一段特别的代码逻辑，这段代码逻辑可以理解为磁盘验证器功能，磁盘验证器负责检测磁盘是否存在坏扇区。验证原理如下：硬盘以块为单位（扇区）写入数据，硬盘每次更新扇区时，也会更新校验和（紧接在扇区数据之后存储）。当从硬盘驱动器读取扇区时，预计扇区校验和将与扇区数据匹配，如果不匹配，则表示磁盘在写入操作期间出现了问题，存在坏扇区。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/525efe04-6246-4f5e-9e5a-b88d9ff2d926.png " =840x539")

VMware的磁盘验证器代码中，申请了一块等价磁盘大小的堆作为校验和的存储内容，对磁盘进行访问操作时(Read/Write)，磁盘验证器并没有对命令中访问扇区的边界做任何检测与限制，直接计算用户访问的目标扇区的校验和并将其写入对应内存，这就导致了用户访问的目标扇区可能超出磁盘的扇区上限，引发严重的堆越界访问问题。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/c126cc4a-3344-415d-8e4f-8b49276285bf.png)

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/976dcb83-11bc-4a70-b958-2a4e940f6d9c.png)

又因为CDB命令中，读写指令的最大范围为Write16/Read16。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/cc6d21c9-4d6e-4fad-9217-6e9095d169e9.png)

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/07dbb3fa-dce3-4729-8f33-8076c3464dd5.png)

即允许访问的扇区数最大数据类型为uint64，从而形成了骇人听闻的任意写漏洞。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/cdae8646-1b1c-4d39-bcfd-26506da0ecec.png " =641.5x146")

该漏洞同时存在于Workstation/Esxi中，但对应的触发路径不尽相同。在Workstation中，可以从CD/ROM或SCSI磁盘两个方面分别去触发该漏洞；但在Esxi中，只能从CD/ROM去触发漏洞，无法从SCSI磁盘角度去触发。

因为在Esxi中，VMM会判断主机是否处于hostedEmulation模式，如果处于，就将请求通过UserRPC发送到VMX中处理，如果不处于，就将请求通过vmkcall发送到VMKernel，这就导致了在Esxi的磁盘设备上无法触发该漏洞。

当然，正因为Esxi会将磁盘请求发送到VMKernel中去处理，这也引出了后续关于VMKernel中磁盘的漏洞。

## 三、漏洞二：CVE-2024-37086：Out-of-bounds Read

我们发现，VMware在VMKernel中对发送来的磁盘请求处理已经尽可能的小心翼翼，禁用了许多不必要的SCSI命令，只启用小部分必要的SCSI命令。但即使是在如此谨慎的情况下，被启用的SCSI命令中依然存在严重的设计问题。

SCSI命令中的UNMAP命令允许一个或多个LBA(Logical Block Address)被取消映射，该命令常用在精简配置技术中，以提高存储利用率、灵活的容量规划和不间断存储配置服务。

在SPC-6(SCSI Primary Commands - 6)中对于UNMAP命令的设计如下图所示：

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/72fdd68a-c383-4c05-a9eb-17a56f88ce9b.png)

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/e8809cdf-e94e-4af5-955c-8c0b0f3cb177.png)

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/cc3c2ceb-3c63-4665-bdc7-2c97c35ca153.png)

先来解释一下图里重要的数据结构：

Table 204 UNMAP command中最重要的字段为`PARAMETER LIST LENGTH`，表示应用客户端发送到设备服务器的 UNMAP 参数数据的长度

Table 205 UNMAP parameter list中`UNMAP DATA LENGTH`表示可从数据输出缓冲区传输的数据的长度，`UNMAP BLOCK DESCRIPTOR DATA LENGTH`表示从数据输出缓冲区传输的UNMAP 块描述符数据的长度

而VMware在设计UNMAP命令的时候，忽略了`PARAMETER LIST LENGTH`、`UNMAP DATA LENGTH`、`UNMAP BLOCK DESCRIPTOR DATA LENGTH`之间的强关联性。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/85b83304-006c-42c6-8598-4bfea1d6a362.png)

其UNMAP命令代码分支首先会调用名为`VSCSI_CheckUnmapCmd`的函数来检测输入的UNMAP命令的合法性，`VSCSI_CheckUnmapCmd`函数首先根据`PARAMETER LIST LENGTH`来获取所有的UNMAP数据。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/8b0e8178-1157-4b25-be23-cacc20bd7896.png)

接着获取数据中的`UNMAP BLOCK DESCRIPTOR DATA LENGTH`来确定有多少块UNMAP block descriptor，依次检测所有的UNMAP block descriptor访问的扇区是否超出总扇区范围

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/186cde71-71a5-4b2d-aa38-d9555eec552a.png)

如果检测没问题，就进入`VSCSI_UnmapCmdIterateBegin`函数，在该函数里再次根据`PARAMETER LIST LENGTH`来获取所有的UNMAP数据交给后续使用

获取完毕后，UNMAP命令代码分支以`PARAMETER LIST LENGTH`为最大边界，依次处理数据中每一个UNMAP block descriptor

这里就存在一个逻辑上的问题

VSCSI_CheckUnmapCmd的检测函数

* 获取数据是以`PARAMETER LIST LENGTH`来获取的


* 检测是以`UNMAP BLOCK DESCRIPTOR DATA LENGTH`来确定检测范围

其并没有检测`PARAMETER LIST LENGTH`与`UNMAP BLOCK DESCRIPTOR DATA LENGTH`之间的关系，二者在SPC-6(SCSI Primary Commands - 6)的设计中实际是强关联的关系，VMware的开发人员没有深刻的意识到这一点。

这就导致了有一部分UNMAP block descriptor在`VSCSI_CheckUnmapCmd`检测函数中会被漏掉。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/bcca1c92-400e-4223-a2b3-e8829cf5cf9a.png)

后续的使用中，数据的获取与使用都是以`PARAMETER LIST LENGTH`作为边界，这就导致未被检测到的那一部分UNMAP block descriptor又会被使用，这部分UNMAP block descriptor可以突破磁盘总扇区的上限来进行访问。

在`VSCSI_ExecFSSUnmap`函数中会根据访问的磁盘ID，将UNMAP block descriptor数据分发给对应的磁盘处理时，这部分未被检测的UNMAP block descriptor会根据访问的不同磁盘类型，造成不同的危害，其中最严重的危害是越界写入

## 四、漏洞三：CVE-2024-37086：Out-of-bounds Read（第二种形式）

第三个漏洞也在UNMAP命令代码分支中，其根因实际上和第二个漏洞是同一个，VMware在后续的修补中将其归为同一个漏洞，此处仅作简单讲解。

`VSCSI_UnmapCmdIterateBegin`函数中会使用如下结构体：

```none
struct struc_1
{
  Parameter_List *Parameter_List;
  __int64 parameter_list_length;
  unmap_block_descriptor *p_unmap_block_descriptor;
};

struct Parameter_List
{
  __int16 unmap_data_length;
  __int16 unmap_block_descriptor_data_length;
  int reserved;
  unmap_block_descriptor unmap_descriptor;
};
```

Parameter_List作为一个指针指向Parameter_List堆块，其存放着本次UNMAP命令的所有数据。

parameter_list_length表明Parameter_List堆块的大小。

p_unmap_block_descriptor作为一个指针，指向Parameter_List->unmap_descriptor。

 ![](/attachments/2024-09-18-defcon-hitbbug-hunting-in-vmware-device-virtualization-3/68beab40-74b0-40b9-8d0e-7f9330ab6b40.png)

在后续的使用中，获取p_unmap_block_descriptor指针来找到对应的unmap_descriptor，依次处理数据中每一个UNMAP block descriptor，每处理完一个UNMAP block descriptor都会将p_unmap_block_descriptor指针往后移动10字节。

很不幸的是，处理的边界被设置为PARAMETER LIST LENGTH，即处理边界是：

```none
a1a.Parameter_List + a1a.parameter_list_length <= (char *)p_unmap_block_descriptor
```

PARAMETER LIST LENGTH是什么?

```none
PARAMETER LIST LENGTH = sizeof(struct Parameter_List)
```

其中还包含了2字节的unmap_data_length，2字节的unmap_block_descriptor_data_length与4字节的reserved

p_unmap_block_descriptor指针指向的是Parameter List结构体8字节偏移的位置。

很明显，如果以PARAMETER LIST LENGTH作为处理边界，会导致多出来一个UNMAP block descriptor被解析，从而在后续的处理中造成与BUG2一样的问题。

## 五、总  结

VMKernel作为一个全新的攻击面，其攻击场景远不止文中所讲述的这点内容。文章关于VMKernel中SCSI磁盘的攻击面讲解也只揭露VMKernel中磁盘的很小一部分内容，NVME、PVSCSI等类型的磁盘都是可供后续审计的点。甚至不限于磁盘，还有其他虚拟设备也有与VMKernel进行数据交互的地方，其还有很大的潜力可供各位挖掘。

VMKernel作为新攻击面的出现，不仅为研究人员们开辟了全新的审计思路，也为厂商带来了更加严峻的挑战。众所周知，从内核态进行的攻击是无视用户态的防御机制的。这就表明，如果真有某些不法分子从VMKernel进行攻击，VMware现有沙箱机制是完全无效的，需要厂商进一步在内核中部署全新的防御机制。