---
slug: tiangongarticle032
date: 2024-05-29
title:  "【GeekCon 2024】TI C2000 DSP Chip Hacking: 绕过德州仪器C2000芯片的CSM/DCSM安全保护机制"
author: ha1vk
tags: [Texas Instruments, Digital Signal Processing, DSP, Chip, Code Security Module, CSM, Dual Code Security Module, DCSM, GeekCon]
---

# 【GeekCon 2024】TI C2000 DSP Chip Hacking: 绕过德州仪器C2000芯片的CSM/DCSM安全保护机制

5月26日，奇安信天工实验室安全研究员赵海，出席国际知名极客大会GEEKCON 2024 Singapore，发表 **《TI C2000 DSP Chip Hacking》** 议题演讲，现场展示并成功破解了使用德州仪器TMS320F28375D芯片开发的"安全U盘"，绕过CSM/DCSM保护机制读取其中存储的文件。

议题分享了德州仪器TMS320F28x芯片的CSM/DCSM安全保护机制突破，同时披露了TI C2000 DSP芯片下隐藏了20多年之久的CSM/DCSM锁密机制绕过漏洞。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/9a16bc64-5dcd-4d79-b787-e009ccd35cb8.jpeg)

<!-- truncate -->

## 一、芯片介绍

DSP芯片（Digital Signal Processing Chip）是一种专门用于数字信号处理的微处理器或微控制器。C2000™产品作为TI乃至业界最为悠久的MCU产品线之一，至今已有25年历史，从高铁到电动汽车、从数控机床到机械臂、从逆变器到服务器，哪里都有C2000的身影。TMS320F28x是C2000系列中最新的一批芯片，目前广泛使用。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/e198d810-dfa5-4eaf-a4da-5b3e76a6647c.png)

## 二、CSM保护机制

代码安全模块(CSM)是C2000芯片内置的一种数据访问保护机制，开发者在芯片指定位置刷入CSM密码给芯片上锁，可以防止内部flash中的固件被UnSecureZone(JTAG调试器、BOOTROM等)读取。

TMS320F28x系列CSM密码为128位（8个16位字），分别是KEY0、KEY1、KEY2、KEY3到KEY7，映射到 FLASH 的地址中，这一地址位置是由 TI 设计的时候设计好的，使用者不能改变，如果加密位置都为 1,那么该芯片为非加密状态，可以访问用户存储区，如果加密位在全 0 的状态，该芯片就处于锁死状态，无法继续使用。

在芯片处于加密状态，无论是使用硬件的 JTAG 调试还是软件指令去读取加密区，得到的结果都是 0。如下使用JTAG调试器查看内存数据，此处看似是空数据，实际上这里是被CSM保护的内存区域，在不知道密码的情况下无法被读取。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/7e9c7a6b-1692-4ea3-82ac-2305872a5ff9.png)

使用CSM密码解锁后，可以正常读取到数据：

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/954c8720-8b19-47da-96d8-01b300e2af27.png)

CSM机制的流程如图所示，如果要访问SecureZone区，则需要使用CSM密码进行`unlock`，`unlock`的过程是在硬件中实现的，用户只需要对相关硬件寄存器传入密码即可自动进行。为了防止在运行时调试器附加提取数据，CSM机制规定了UnsecureZone无需解锁可以直接执行SecureZone中的代码，因此BOOTROM在启动固件时，也不需要知道密码。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/3b29b3f5-14e0-4af2-bec4-a364889c591c.png)

## 三、DCSM保护机制

双代码安全模块(DCSM)存在于C2000系列中一些新推出的型号产品，该功能支持将芯片中的memory划为两个独立区域(SecureZone1、SecureZone2)，并设置各自独立的的128位CSM密码进行保护。通过烧写DCSM相关寄存器，可以对内存区域进行划分保护，例如将Flash Sector A、Sector C、RAMLS01划分到SecureZone1，Flash Sector B、Sector D、RANLS02、RAMLS03划分到SecureZone2。带有DCSM机制的芯片还具有SecureROM，这是内置于芯片中的一段代码，提供了一些对DCSM保护区操作的API函数，例如`SafeCrc`函数可以在无需解锁CSM的情况下被`UnSecureZone`中的代码调用计算一个SecureZone中数据的CRC。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/9fad79f9-c251-4c3d-ab4e-af32fe053f2c.png)

## 四、CSM/DCSM解锁

知道了CSM的加锁方式，对研究CSM解锁思路就有两条。第一，想办法得到128位密码，如果拥有了密码，那么就可以访问用户存储区；第二，在无法得到的情况下如何让芯片编程不加密状态呢？前面提到如果是全为1就为不加密状态，那么就想办法让该位置全变为 1，只要达到了这个状态，就破解掉了DSP的加密。市面上的芯片解密公司使用的是第二种方法：将芯片开盖，使用高精密仪器修改 OTP 存储区的电路，让加密位全部置 1 达到解密的状态。

 ![图片来源：参考链接\[1\]](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/f8dab45b-f44b-4231-97ef-8d17f9935e86.png)

这种解锁方式造价高且流程复杂容易毁坏芯片。我们研究发现CSM/DCSM在软件层面上存在漏洞，保护区的数据可以利用漏洞间接访问。

## 五、CSM/DCSM安全漏洞

前面在介绍CSM时提到可以在无需解锁的情况下去执行SecureZone中的代码，漏洞在于**可以执行SecureZone中任意地址的代码即使该地址不是一个函数的开头位置。**

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/d6d9304c-7c53-40b1-86d6-62b98ac25f5c.png)

SecureZone内部的代码是有权限直接访问这个SecureZone本身的数据的，因此可以调用内部的一些`ROP Gadgets`去间接读写这个SecureZone。如图所示，调用了`MOVL ACC,*+XAR5[0]`这样的一个内存加载的`gadget`，可以读取`SecureZone`中4字节数据到ACC寄存器中。而`MOVL *+XAR4[0], ACC`这样的数据存储的`gadget`则可以被用于写`SecureZone`。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/6d819ab8-c911-4959-ac2a-ed474ec9faf9.png)

由于事先不知道`SecureZone`的内容，那么如何获取`gadget`的地址是一个问题。将思路转变为`CTF`的盲打题，我们可以直接从一块未知内容区爆破出想要的`ROP Gadget`。如下图流程所示，我们使用BOOTROM的下载模式上传我们的代码到RAM执行，想要爆破出数据加载到寄存器的`gadget`，先在一个地址处存入数据，例如在`0x100`地址处存入一个`Magic Value`，接着设置寄存器`XAR4、XAR5`寄存器（这两个寄存器出现在内存读写的指令中比较频繁）为地址`0x100`，清空其他寄存器，然后从`SecureZone`开始的位置进行函数调用执行，如果执行错误没有成功返回，则说明当前地址不是我们需要的，下一轮对函数地址增1继续调用；如果函数调用成功返回，则检查哪一个寄存器中的值变成了`Magic Value`，如果有，说明我们成功找到一个能够从内存加载数据到寄存器的`gadget`，利用这个`gadget`可以把数据全部读取，然后反汇编后寻找`内存写的gadget`。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/c3899282-7c67-4520-8d46-3dbeab513b43.png)

CSM/DCSM保护机制都可以使用这种方式来绕过读写保护，由于DCSM增加了SecureROM且SecureROM拥有对SecureZone的读写权限，我们也可以去调用`SecureROM`中的gadgets。SecureROM无法被JTAG提取但是可以在TI官方的`C2000Wave SDK`包中找到二进制文件，可以对其进行逆向提取需要的`ROP gadgets`，这样无需爆破，且适配多种产品而不依赖于`flash`中的代码变化。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/e4672d3f-c841-46df-b332-eccf59b9903c.png)

## 六、EXEONLY保护绕过

如果对DCSM中的EXEONLY寄存器进行烧写，可以对指定内存进行`只可执行`保护，例如设置Flash Sector A、RAMLS01为`EXEONLY`，开了该保护，即使同一个`SecureZone`的代码也不能对`EXEONLY`保护区进行读写，因此上面的绕过方法就失效了。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/1bf6628f-7506-4291-8300-7616f0ece8e1.png)

翻阅德州仪器官方的文档，SecureROM提供了两个API可以对`EXEONLY`区进行读写，但是参数有很严格的限制，也不能被利用。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/fb460445-5542-4a5e-91f1-1d87d61d97ae.png)

通过对`SecureROM`的逆向分析，我们发现内部的关键代码：

```markup
_SafeCopyCodeZ1:
...
MOVW DP, #0x17c0
OR @0x22, #0x0001
...
do some R/W
```

这里地址计算一下，实际上是对`0x5f022`地址处写入了一个标志位1，然后就可以正常的进行读写了。经过测试，写入标志位和读写数据必须由`SecureROM`中的代码来完成才能成功，并且两个操作中途不能返回到`UnSecureZone`中否则也会失败。我们可以使用ROP来完成这个操作。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/4601ee52-5d75-4dad-b661-7481a9240423.png)

我们找到了合适的gadgets，先用`VMOV32 *+XAR5[0], VCC`来设置标志位，然后ROP到数据拷贝的`gadget`处。

## 七、Flash刷写保护绕过

对于开了CSM保护的芯片，我们可以利用漏洞读取位于`Sector A`中的CSM密码，然后进行解锁即可直接刷写flash。对于`DCSM`，密码在`OTP`中不可被读取，但是可以在不解锁的情况下刷写flash：在同一个`SecureZone`中的代码，如果设置了`DcsmCommonRegs.FLSEM.all = 0xA501;`这个特殊的寄存器，则后续代码可以直接刷写flash。我们可以先利用漏洞绕过DCSM的读写保护，将flash刷写代码写入到`SecureZone`中的RAM区，然后再去执行RAM中的代码即可对同一个SecureZone中的flash sector进行刷写。

## 八、写在最后

C2000的CSM/DCSM漏洞究其原因是UnSecureZone可以调用SecureZone中任意位置的代码，这是保护机制实现上的缺陷。相比之下，ARM在SecureZone的实现中加入了NSC(Non-secure Callable)这个中间跳板，UnsecureZone只能通过中间跳板进入SecureZone。

 ![](/attachments/2024-05-29-geekcon-2024ti-c2000-dsp-chip-hacking-c2000csmdcsm/16161ec8-c748-4f75-83f7-2eaa1a137999.png)

## 九、相关链接

\[1\] [PSIRT Notification C2000 DCSM ROM Gadget/ROP Vulnerability](https://www.ti.com/lit/ca/swra800/swra800.pdf)

\[2\] [Understanding Security Features for C2000 Real-Time Control MCUs](https://www.ti.com/lit/ab/swpb019d/swpb019d.pdf)

\[3\] [DCSM模块使用说明](https://e2echina.ti.com/blogs_/b/the_process/posts/dcsm)

\[4\] [TRUSTZONE TECHNOLOGY](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/lpc/39306/1/04_LPC5500_TrustZone_v1.4.pdf)

\[5\] [MCU芯片加密历程](http://www.51hei.com/bbs/dpj-108061-1.html)
