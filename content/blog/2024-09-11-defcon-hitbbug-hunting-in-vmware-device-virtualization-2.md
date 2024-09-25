---
slug: tiangongarticle045
date: 2024-09-11
title: 【DEFCON & HITB】Bug Hunting In VMware Device Virtualization（中篇）
author: s0duku
tags: ["议题解读", "DEFCONF", "HITB"]
---

本文是天工实验室在DEFCON上发表的议题《Dragon Slaying Guide: Bug Hunting in VMware Device Virtualization》的第二部分内容。在该议题的[第一篇文章](/blog/tiangongarticle044/)中，介绍了VMware虚拟化实现的内容。

本周将继续讲解议题第二个重要部分：**USB Device Virtualization**，通过讲解我们挖掘的漏洞，介绍主机控制器、VUsb及模拟USB设备，即整个USB系统视角下各处可能出现的安全问题。

## 一、前言

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/8a61dbd9-769b-44d5-ba32-94c4f2160836.png " =744.5x420")

我们对vmm和vmx以及是其他位于Host上的服务上进行逆向分析，并且尽可能全面的分析整个 USB 设备的模拟过程，从USB主机控制器的实现（UHCI, EHCI, XHCI）到具体后端USB设备的模拟，并在其中发现了 多个错误，其中一些甚至与天府杯2023的所使用的漏洞达成了一致，接下来我们会介绍VMware对USB系统模拟的实现，以及其中一些典型错误产生的原因，以及所能它们带给我们的启示。

VMware 实现 USB 模拟的代码，大体上可以结构为三个部分，第一个部分为 USB 主机控制器模拟，这部分代码负责模拟 USB 主机控制器设备，包括 UHCI，EHCI，XHCI 三种，这部分代码负责处理整个USB传输中与主机控制器相关的数据传输部分，三种控制器的mmio处理基本都是现在 vmm 中，vmm 负责按照手册标准处理内存寄存器访问的各种实现，并通过UserRpc调用vmx配合实现具体主机控制器的数据传输过程。整个模拟最重要的部分为将Guest传输的数据从主机控制器表示形式转换成保存在URB对象的USB Request形式，并将URB对象通过VUsb中间层传输给后端USB设备。

第二个部分我称为 VUsb 中间层，这层代码负责对接主机控制器和后端USB设备，他在所有后端USB设备上形成了一层抽象，USB主机控制器代码大多负责将Guest的输入重新封装成 URB 对象，VUsb 这层代码则负责管理URB相关的对象，他会更具后端目标设备类型的不同选择不同URB对象分配和释放方式，不同的后端USB设备还会在VUsb层形成一个统一表示后端设备的 VUsbDeviceObj，在传输URB时VUsb还会将Urb交给VUsbDeviceObj中目标Endpoint对应VUsbPipe对象管理。

第三个部分即VUsb 后端设备，VMware实现了大量不同类型USB设备的模拟，包括 HID，Bluetooth，CCID，他们大多采用一个回调函数处理URB对象，并根据URB对象的保存的数据进行行为模拟。其中比较特殊的时VUsbGeneric这类设备，这类设备在Guest Machine表示通用USB设备，一般用来直通Host上的物理USB设备，VMware通过Host上的本地 usbarbitrator 服务转发vmx中的请求数据。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/656ec509-2f63-4fb3-bd34-868b5b870ff8.png)

## 二、漏洞一：CVE-2024-22255: Uninitialized Memory

我们分享的第一个漏洞来自于UHCI控制器模拟部分。在USB设备的控制传输中，USB设备使用有效载荷之一是Standard Device Request，他以 Setup Packet 格式开始。

**Setup Packet Format**

| Offest | Field | Size |
|----|----|----|
| 0 | bmRequestType | 1 |
| 1 | bRequest | 1 |
| 2 | wValue | 2 |
| 4 | wIndex | 2 |
| 6 | wLength | 2 |

其中最有趣的字段在于 wLength，他将提醒 Usb 设备请求跟随的后续数据的长度。Standard Device request 是Usb设备的有效载荷，对于USB主机控制器来说它并不以此为单位传输数据，对于UHCI，他以 Transfer Descriptor 为单位传输数据，并在Guest内存中以Queue Head (QH) 类似链表的形式链接起来。VMware的UHCI控制器在处理控制传输时，需要以单次Standard Device request为单位分配URB对象，他将合并位于Queue Head上所有与请求相关的Transfer Descriptor (TD)中的待传输数据。

VMware 首先获取 QH 上第一个 TD 并以此为 Setup Packet 开始解析，去除其中 wLength 字段并加上 Setup Packet 大小作为 URB 对象数据缓冲区的大小。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/bc45d07b-d8c7-4704-8474-5813bdffaa54.png)

我们可以看到 VMware 在涉及拷贝数据时已经尽可能小心，但他却忽略了如果 QH上没有足够wLength 长度的 TD 的情况。这种情况，他会认为整个QH 已经处理完毕，随后便直接将URB对象放到表示连接到对应后端Usb设备端点的VUsbPipeObject上，并且通过VUsb_SubmitUrb调用对应后端设备的URB处理函数进行处理。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/f51a7fef-24bb-4edc-a283-5a08d5cf65b9.png)

URB 的分配过程取决于你要传输的目标设备是什么，不同类型的后端Usb设备分配出来的 URB对象在私有结构上也会有所不同。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/12421600-3306-432a-8a12-547dd37b7a58.png)

考虑 HID 设备，他在分配 URB 对象时，除了 URB 通用的数据字段，没有添加额外的结构，同时它使用 Malloc 进行数据的分配。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/5b74ed72-8860-4104-9555-ff1bc046b260.png)

如果我们没有提供由 wLength 字段指定长度的数据会导致 URB 保存数据的缓冲区中留下一大段未初始化的堆数据，但URB的有效载荷长度任然会被设置为wLength+sizeof(Setup Packet)大小。在后端模拟HID设备处理Setup Packet中带有SET_CONFIGURATION 类型请求时，默认没有修改URB中数据缓冲区的内容，并将返回数据的大小直接设置成和原始数据一样，这使得 Guest 可以直接获取 vmx 进程堆上的未初始化内容。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/641a5031-bf09-41ac-8187-8f1c2d2cd660.png)

## 三、漏洞二：CVE-2024-22252: Use-After-Free

XHCI会在设备侧维护Device Slot Context 以及 Endpoint Context 来保存目标USB设备及设备端点的状态信息，同时还允许在Endpoint Context上创建多个Transfer Ring，Transfer Ring对象使用TRB传输数据，VMware 使用哈希表存储Transfer Ring对象。

深入逆向分析我们还会发现当XHCI将Transfer Ring 上的TRB数据构造成URB对象时，URB会有一个指针字段用于记录所有与之相关的TRB数据在 Transfer Ring 上的起始位置，当XHCI给Guest返回USB设备响应时，他需要用这个指针跟踪数据，而指针字段刚好指向对应Transfer Ring对象的成员。

我们发现的这个问题与 CVE-2021-22040 类似，CVE-2021-22040 的补丁非常有趣，他改动XHCI模拟代码中各处对USB端点上的Transfer Ring 释放的调用与Device Slot Context的赋值的顺序。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/ef83bf36-f702-4125-ad89-faefc45bc479.png " =521x546")

我们想要理解问题的成因就需要清楚释放的行为构成，当XHCI试图释放一个Endpoint Context时，他会检查这个Endpoint Context上的Transfer Ring哈希表，释放与之相关的所有Transfer Ring对象，以及所有Transfer Ring 活跃的传输数据，在VUsb 中间层上这些活跃的传输数据在以URB对象的形式链接在对应Endpoint的UsbPipeObject对象上，所以释放一个Transfer Ring首先需要释放所有在VUsbPipeObject上与之相关的URB对象。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/e92171a1-b001-4c43-8095-cd4a0f81dc00.png " =783.5x312")

XHCI 首先根据Endpoint Cotntext 所属的 Device Slot Context 中保存的USB Port Number获取 VUsbDeviceObject 对象，再根据Endpoint ID从VUsbDeviceObject 中获取VUsbPipeObject，在 CVE-2021-22040 补丁修复之前，Configure Endpoint 等 XHCI 指令可以在释放 Transfer Ring 之前就修改Endpoint Context的内容，Endpoint Context中保存有Endpoint的类型，类型被修改成与VUsbPipeObject不匹配后，使得释放 Transfer Ring 时获取不到VUsbPipeObject的，从而导致VUsbPipeObject上属于TransferRing的URB对象不能被先行释放，而我们提到，URB中保存有Transfer Ring对象成员的指针，这就导致URB中悬挂已经释放的指针进而发生Use-After-Free问题。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/8d0614d4-d4fb-47b4-980e-505dbbbe1229.png " =627x282.5")

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/7bbbd548-6cec-4db6-85ae-a320ba895030.png " =843x56")

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/7e6d13f6-b3c7-4428-ad33-904d35dae622.png " =513.5x200")

CVE-2021-22040 补丁提前了释放的顺序，以确保释放之前Device Slot Context或是Endpoint Context不会被提前修改，但是这并不足以修复这个问题，问题的根本是这些拥有依赖关系的数据结构，相互之间索引的方式较为松散，即便现在没有办法通过修改Endpoint Context内容来影响VUsbPipeObject的获取，仍然可以通过修改Device Slot Context使得获取其他VUsbDeviceObject虚拟USB设备对象，进而导致不能获取正确的VUsbPipeObject对象。

ADDRESS_DEVICE 指令会修改Slot Context 以及 Control Endpoint Context 的内容，这意味着我们可以先完成一个设备的配置流程，并在其非Control Endpoint的Endpoint上创建 Transfer Ring，以及在 Transfer Ring 上传输 URB 数据。完成之后，我们再对同一个 Device Slot 上使用 ADDRESS_DEVICE 指令修改Device Slot Context内容，使其 Device Port Number 指向其他USB设备，VMware的实现使ADDRESS_DEVICE 并不会影响其他非Control Endpoint Context的状态，这使得当我们尝试释放之前传输过URB数据的Endpoint上的Transfer Ring对象，在查找 VUsbPipeObject 过程中，会由于查到的 VUsbDeviceObject 和本该释放URB所在的VUsbPipeObject所属的VUsbDeviceObject 不匹配，导致释放再次失败，再次引发Use-After-Free。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/f48a8031-de96-4996-ab7b-87ef94260b00.png " =758x126.5")

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/964987b4-bf51-4df8-9b02-380566e1cd38.png " =525.5x354.5")

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/da97eb2c-4077-4a8d-a52a-d1e5e6e7ca1c.png " =518x344")

## 四、漏洞三：CVE-2024-22251: Out-Of-Bound Read

本部分介绍的最后一个漏洞来自于 VUsb 后端设备模拟过程中，并且在系统API中被触发。APDU (Application Protocol Data Unit) 作为 SmartCard Reader 和 SmartCard 之间交互的数据单元，而 Guest 和 VMware 所模拟的 SmartCard Reader 设备使用如下数据结构交互：

```none
00000000 ccid_xfrblock_msg_hdr struc ; (sizeof=0xA, mappedto_759)
00000000                                         ; XREF: ccid_xfrblock_msg_with_command_apdu/r
00000000 msg_type        db ?
00000001 msg_len         dd ?
00000005 slot_num        db ?
00000006 seq_num         db ?
00000007 bwi             db ?
00000008 level_param     dw ?
0000000A ccid_xfrblock_msg_hdr ends

00000000 command_apdu    struc ; (sizeof=0x5, mappedto_760)
00000000                                         ; XREF: ccid_xfrblock_msg_with_command_apdu/r
00000000 cla             db ?
00000001 ins             db ?
00000002 p1              db ?
00000003 p2              db ?
00000004 len             db ?
00000005 command_apdu    ends

00000000 ccid_xfrblock_msg_with_command_apdu struc ; (sizeof=0xF, mappedto_761)
00000000 hdr             ccid_xfrblock_msg_hdr ?
0000000A apdu            command_apdu ?
0000000F ccid_xfrblock_msg_with_command_apdu ends
```

VMware 会检查ccid_xfrblock_msg_hdr 的字段与作为有效载荷的APDU的 len 长度字段是否符合，但却没检查这两个字段是否与整个URB缓冲区大小是否符合，而是直接使用这个字段作为了参数调用了 Windows 的 SCardTransmit API，SCardTransmit 以缓冲区指针和缓冲区大小为参数，他当然没法检查这两个参数之间的合法性，这不是他的责任，于是导致了堆数据的越界访问。

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/50358093-3d8a-4878-89bd-2244c5ff5bfc.png " =583.5x301.5")

 ![](/attachments/2024-09-11-defcon-hitbbug-hunting-in-vmware-device-virtualization-2/7473b563-66a0-4053-abde-5d9a90261e55.png " =508.5x117.5")

## 五、总  结

本篇文章中分享的漏洞在Workstation和Esxi上均可被触发，这使我们意识到，在整个USB模拟系统中，问题不仅可能出现在接近虚拟机Guest操作系统的USB主机控制器层面，甚至USB后端设备模拟也可能收到恶意的用户输入影响。XHCI的越界写也说明模块之间的数据结构也不能过度信任，更有甚者，充当前后端之间桥梁的过渡代码，也有可能因为对内存对象的管理不当而给Host带来威胁。

整个USB模拟系统视角下攻击面远不止如此，VMware为了实现物理USB设备与Guest直通，还在Host上安装了专用服务与vmx交互转发数据，相关服务也可能成为攻击者关注的目标。不仅是来自Guest系统的输入值得关注，而且恶意的USB设备响应数据也能借助虚拟化技术影响Host主机，USB这样复杂系统的实现毫无疑问为我们带来极大安全挑战。