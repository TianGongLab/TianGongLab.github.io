---
slug: tiangongarticle022
date: 2024-03-20
title: Windows hypervisor&内核调试的几种常见/不常见方法
author: hongzhenhao
tags: [Windows, Hypervisor, Kernel, Debug]
---

# Windows hypervisor&内核调试的几种常见/不常见方法

## 一、前言

本文主要介绍了使用调试器对Windows操作系统的内核层和hypervisor层进行双机调试的几种常见和不常见的方法。本文中使用的windbg调试器和其附带的实用调试工具都可以在windows sdk安装包中选择安装，windows sdk安装包官方的下载地址是: ([https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/))。 有需要的读者可以自行下载并安装。

<!-- truncate -->

## 二、串口调试

首先我们先来介绍使用VMware虚拟机的情况下如何使用串口进行双机调试Windows内核及hypervisor。

在VMware的虚拟机设置中，添加"串行端口"设备后，并设置"串行端口"设备"使用命名的管道"，这里命名管道的名称可以自己设定，并分别选择"该端是服务器"和"另一端是应用程序"。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/249d116d-7ed1-4d73-8d3f-88944f4f37e0.png)

然后我们在被调试机中设置bcdedit参数，这里的目的是在系统启动过程中添加debug参数。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/d5cbd595-b3e3-40d2-9fe6-88a603327d3c.png)

在被调试机中我们分别使用`bcdedit /dbgsettings serial debugport:1 baudrate:115200`和 `bcdedit /hypervisorsettings serial debugport:1 baudrate:115200`命令将Windows内核和hypervisor的调试参数设置为串口调试，串口为com1，波特率为115200。然后再使用`bcdedit /debug on`和`bcdedit /set hypervisordebug on`命令分别开启windows内核和hypervisor层的调试。最后设置dbgtransport为kdcom.dll，这里是为了保证被调试机在系统启动过程中使用串口进行调试。

现在被调试机已经整装待发做好了被调试的准备，但调试机还需要一些配置。因为我们需要同时调试windows的内核和hypervisor，而且在被调试机的参数中使用了同一个串口(com1)作为调试串口，所以需要将不同层级的调试数据分发，根据不同层级将调试数据分发到不同的命名管道。我们可以使用`& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\vmdemux.exe' -src pipe:pipename=com2`命令实现这一过程。

成功运行如上命令后，vmdemux进程会自动生成两个命名管道`\\.\pipe\Vm0`和`\\.\pipe\Vm1`。分别使用`& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe' -k com:port=\\.\pipe\Vm0,pipe,resets=0,reconnect`和`& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe' -k com:port=\\.\pipe\Vm1,pipe,resets=0,reconnect`命令打开windows hypervisor和内核的调试窗口。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/6f544518-18c6-4e42-b5a8-2011e7f86b89.png)

下面我们介绍在双实体机的情况下如何使用串口进行双机调试。

双实体机进行串口调试需要被调试机的主板上保留9针串口，在10年前的电脑主板上，串口几乎是标准配置，然而随着主板厂商的革新，主板串口也渐渐退出历史舞台。

除了需要主板中保留串口外，还需要拥有一条串口调试线：Null-modem线，或者准备一条2，3交叉线。关于Null-modem调试线的线序如下图，感兴趣的读者可以自己手动做一条。

 ![](/attachments/2024-03-20-windows-hypervisor/4244fad8-fc4e-4545-ae2a-e81718ad4e1e.png)

当使用串口调试线连接好调试端和被调试端，就可以使用 `& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\vmdemux.exe' -src com:port=com2`命令将不同层级的数据分发到指定的层级，实现windows内核和hypervisor调试。

## 三、网络调试

Windows内核和hypervisor调试中，可以使用网络进行调试，不需要特殊的调试线连接两台机器，网络调试大大方便了双机调试中的准备过程。

首先，配置被调试机bcdedit配置，这里假设我们的调试机IP地址为192.168.111.1，调试hypervisor的端口为52201，调试windows内核的端口是52202。运行如下图的命令，设置网络调试，最后将dbgtransport设置为kdnet.dll。

 ![](/attachments/2024-03-20-windows-hypervisor/88ed3953-73ed-46a2-9dd9-995c3f3ee16e.png)

在图中可以看到，如果成功设置了网络调试后，会返回一个key，这个key是用来给调试机中的windbg连接被调试机使用的。这里这两个key要先记下来。

重启被调试机后，在调试机端使用`& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -k net:port=52202,key=rq644uvs2p16.3ked98d1isrrq.hr7oioflkdt2.37b29ko4f79yj`和`& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -k net:port=52201,key=2mko67of9fjih.233nl9lfzytc2.13u0ikbj37np1.3im74f7f672zj`命令打开windows内核和hypervisor调试窗口。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/93766d09-7f98-446e-8ae7-6b3296a528b6.png)

## 四、USB 3.0调试

USB3.0接口也可以用作Windows内核调试的解决方案，在例如一些超薄笔记本电脑没有PCIE网卡的情况下，USB3.0便成了唯一的内核调试方案。

首先，需要将windows sdk套件中的usbview.exe这个程序复制到被调试机中，位置在：`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\usbview.exe`。

在被调试机中打开usbview.exe，并找到USB3.0主控器，查看主控制器的信息，如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/9bc217c6-7ca9-4de3-bcff-620cab81b8f6.png)

如图中所示，图中选中的USB3.0主机控制器中的信息显示它的Debug Port Number不为None，这个主控器设备所在的位置在0.20.0这个位置上。Debug Port Number的信息不为None说明当前的USB3.0主控器拥有调试能力。

当确定好了主控制器位置后，还需要准备一条USB3.0调试线，根据USB3.0引脚定义可以得知，USB3.0的引脚1是供电，引脚2、3是USB2.0数据传输所用引脚。

所以根据微软给出的文档：（[https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-usb-3-0-debug-cable-connection](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-usb-3-0-debug-cable-connection)），只需要先购买一条USB3.0 A/A公对公线，然后使用透明胶带将买来的线材的1、2、3号引脚绝缘屏蔽后就得到了一条USB3.0调试线。

随后将调试线的一端插入调试机USB3.0接口中，另一端插入到被调试机位置在0.20.0主控制器所在的端口中。如果这里无法确定哪个接口是所在主控制器所在端口的话，可以找一个U盘挨个尝试，在usbview.exe中观察，直到找到正确的端口。

下面我们在被调试机中配置bcdedit参数。使用如下三条命令开启USB3.0内核调试：

* `bcdedit /debug on`
* `bcdedit /dbgsettings usb targetname:ikun`
* `bcdedit /set "{dbgsettings}" busparams 0.20.0`

这里的targetname可以取一个任意的名字；busparams要填入刚才找到的拥有USB3.0调试能力的USB3.0主控制器设备的位置。

重启被调试机后，使用如下命令打开Windows内核调试窗口：

 `& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -k usb:targetname=ikun`

读到这里有人肯定发现了这里的USB3.0调试好像并没有配置hypervisor层的调试，这个原因是因为微软只实现了Windows内核的USB3.0调试，Windows hypervisor层并不支持USB3.0调试。

## 五、VMware + IDA调试

VMware虚拟化软件也拥有强大的调试能力，我们可以借用VMware和IDA调试任意操作系统。

首先，在配置及安装完虚拟机后，打开虚拟机的配置文件，例如：Windows10_x64_hyperv.vmx。打开vmx文件后，在文件的末尾添加如下配置：

* `debugStub.listen.guest64 = "TRUE"`
* `debugStub.hideBreakpoints = "TRUE"`
* `debugStub.listen.guest64.remote = "TRUE"`
* `monitor.debugOnStartGuest64 = "TRUE"`

这四句配置是启用VMware的调试能力。

如果想在虚拟机中安装Hyper-V的话，还需要使用如下配置"欺骗"Windows系统让其觉得在一个可以安装Hyper-V的环境：

* `hypervisor.cpuid.v0 = "FALSE"`
* `mce.enable = "TRUE"`
* `vhv.enable = "TRUE"`

修改完虚拟机配置后，启动虚拟机，此时的虚拟机会直接黑屏。这时打开IDA，在菜单中选择Debugger->Attach->Remote GDB Debugger，连接本地调试器，端口号为8864，如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/6f0f479e-631b-40da-ae20-f92f65bdfea8.png)

随后选择attach到目标进程选项后，会弹出IDA的调试窗口，此时IDA调试窗口显示当前RIP所在的位置，如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/ca01fbf9-bfe2-46ce-b594-145f4bd16124.png)

从图中可以看出，当前RIP的显示还是有问题，所以还需要添加内存的地址范围。打开菜单-> Debugger→Manual memory regions，在Manual memory regions窗口中按下insert键，添加一个0\~0xffffffffffffff00的地址范围。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/f9cc4401-bcf9-4415-bc9a-9b820893147f.png)

此时按F9可以继续虚拟机的运行，如果需要调试就按下suspend进行调试。

IDA调试的优点是无需操作系统支持调试，而且虚拟机中无法检测调试器的存在，但是缺点是需要手动加载符号，调试时也不如windbg那样方便。

## 六、USB3.0 DCI调试

USB3.0 DCI调试听起来相对比较陌生，那么DCI是什么呢？DCI的全称是Direct Connect Interface，是Intel平台中提供的调试方法，这个技术主要实现了可以直接通过使用USB3.0端口来调试目标系统。说白了其实就是这个技术实现了直接通过一根USB3.0调试线调试被调试机，而且这种办法是JTAG调试，调试器会暂停CPU的运行，是一种硬件级别的调试。

但Intel平台的调试支持并不是一个新技术，在过去Intel平台的硬件调试器是一个被大家叫做蓝盒子的调试器。这个调试器官方叫它Intel ITP(In Target Probe)，ITP要求在被调试机的主板制造时预留并安装ITP/XDP接口，并且如果你使用ITP进行调试必须要购买Intel的硬件调试器，也就是"蓝盒子"，官方购买的话大概要几千美元。所以在过去，Intel平台的硬件调试几乎是给Intel的合作伙伴使用的，用作硬/软件的开发和调试。

不过现在好日子来了，DCI在Intel Skylake系列之后的产品中，硬件上都支持DCI功能。也就是说，从Intel 6代的CPU和100系列芯片组之后的产品都会支持DCI功能。

但是坏消息是市面上大多数的主板都会默认关闭DCI这个功能，当然这是考虑到安全性问题。所以我们如果要启用这个功能，则需要修改主板的BIOS。那目前可以进行BIOS修改的主板有支持AMI BIOS的主板，例如华硕，微星等。

修改BIOS第一个办法可以使用AMIBCP工具修改BIOS镜像。例如这里通过修改BIOS镜像中的Setup →PCH-IO Configuration→DCI Enable(HDCIEN)选项，将其设置为Enabled。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/31cada81-34e1-4a0b-80ee-60d8528253b2.png)

随后保存镜像并刷BIOS。

第二种办法是使用UEFITOOL和IFRExtractor工具将BIOS固件导出IRF（UEFI Internal Form Representation）表。并在IRF表中寻找如下字段：

* `Debug Interface`
* `Debug Interface Lock`
* `DCI enable(HDCIEN)`

记录下这些字段的`VarStoreInfo (VarOffset/VarName)`和`VarStore`的值，例如作者这里的信息如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/b87bb62f-9acc-4679-8c8a-c14675d7ea6f.png)

可以看到这些字段的`VarStore`的值都是1，此时我们翻到IRF表的最前头，查找`VarStoreId`为1的条目。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/1d1f702c-8d37-477d-b346-63ab21c552f6.png)

可以看到这个是BIOS选项里的Setup条目。

下面重启被调试机，使用RU.exe工具修改BIOS，注意这里的RU工具版本可以选择旧一点的，新版的可能会有bug，笔者这里选择的RU版本是5.28.0397。

进入到RU的界面后，按下ALT+=进入BIOS界面，选择Setup条目，然后根据我们找的上文中那三个字段的VarOffset值来修改对应字段的配置。

这里我们需要将字段的配置修改至如下状态：

* `Debug Interface`  →  1
* `Debug Interface Lock`  →  0
* `DCI enable(HDCIEN)`  →  1

修改Debug Interface字段是为了启用硬件调试功能；Debug Interface Lock如果为enable会影响CPU的频率，如果不修改CPU可能会以0.x Ghz的频率运行；DCI enable是开启DCI功能的设置。

修改完成后，被调试机的准备工作就做完了。除此之外，我们还需要一条USB3.0调试线，具体的制作方法前文已经介绍了。

此时我们需要配置下调试端的环境，首先安装Intel DCI驱动，这个驱动是将被调试机的USB端口识别成`Intel USB Native Debug Class`设备。运行`Setup_x64_Intel_DCI_Driver_1.10.0.0.msi`并安装驱动，安装驱动完成并且连接好调试机和被调试机后，启动被调试端，调试端的设备管理器就会显示`Intel USB Native Debug Class Devices`设备，这说明DCI运行良好。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/31e70bd1-de17-44a7-9227-92afc0730759.png)

配置好调试机环境后，使用我们提供的DCI调试相关的工具包，安装python库ipccli。使用`ipccli.baseaccess()`连接被调试机，再使用`ipc.status()`查看被调试机CPU状态。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/2e07bd4c-28ce-4207-b633-971a49556103.png)

也可以使用另外一种办法进行调试，首先到DCI调试相关的工具包的位置，然后打开`%DCI工具包%\windbg-ext\iajtagserver\intel64\`路径，以管理员权限运行`regsvr32.exe ExdiIpc.dll`。这一步骤是为了注册COM组件，可以让后面使用windbg exdi调试时唤起IntelExdiServer。

下面运行工具包中的`windbg_iajtag_console.bat`批处理连接上被调试机，并在批处理窗口中输入`windbg()`命令开始进行调试。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/e8580c77-f92e-4c59-9e60-96a05880bd44.png)

目前的windbg已经连接上了被调试机，但是还没有加载上NT内核以及其他内核模块的符号。我们可以使用`.scriptload reload_manual.js`加载查找内核模块地址的脚本，并使用`!reloadmod`查找并加载符号。如下图。

 ![](/attachments/2024-03-20-windows-hypervisor/71bb8cd0-fc5c-4b96-bf64-21fbb8eca12b.png)

## 七、总结

优缺点分析如图所示。

 ![](/attachments/2024-03-20-windows-hypervisor/a54a7d2f-8b13-4eed-b08d-d14c97e6baf8.png)

与其他的调试方式不同的是，DCI调试可以在ring-2层级上工作，也就是说可以进行SMM的调试，也可以调试比如Intel ME组件。
