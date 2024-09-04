---
slug: tiangongarticle002
date: 2023-10-25
title: Microsoft Hyper-V 虚拟 TPM 设备漏洞分析
author: hongzhenhao
avatar: /authors/hongzhenhao.jpg
info: 微软 MSRC 全球最具价值安全精英榜上榜者、BlackHat USA 世界黑帽大会 Speaker
tags: [Microsoft, Hyper-V, TPM]
---

# Microsoft Hyper-V 虚拟 TPM 设备漏洞分析

## 一、漏洞描述

2023年10月微软发布的安全更新中，修复了2个由笔者报送的Hyper-V虚拟TPM设备漏洞。本次修复的Hyper-V虚拟TPM组件的漏洞可以通过远程访问虚拟机的方式触发漏洞，造成宿主机拒绝服务或者远程代码执行，对宿主机上的其他虚拟机或业务造成损失。

<!-- truncate -->

## 二、背景介绍

Hyper-V的虚拟TPM组件旨在为虚拟机提供模拟的TPM设备，虚拟TPM设备可以为依赖TPM设备的服务或者操作系统（例如Windows 11）提供支持。

漏洞位于`vmsp.exe`进程中的`TpmEngUM.dll`二进制文件中，本次介绍的两个虚拟TPM组件的漏洞就是位于`TpmEngUM.dll`这个二进制文件中。

`vmsp.exe`进程与`vmwp.exe`进程相似，都是一个虚拟机实例启动一个进程。但是不同的是`vmsp.exe`进程是隔离用户模式(IUM)进程，也就是说`vmsp.exe`进程无法在windows用户态下被正常attach。所以在调试上，针对`vmsp.exe`进程的调试就需要额外的“手脚”，这里我们引用Quarkslab博客的文章（https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html），感兴趣的读者可以去了解并实践下，这里不做讨论。

## 三、环境搭建

虚拟TPM组件漏洞的触发需要在Hyper-V虚拟机设置中的“安全”设置中，勾选“启用受信任的平台模块”。

 ![](/attachments/2023-10-25-microsoft-hyper-vtpm/0c7d620e-97ff-45cc-a12f-b4c66a317e2a.png)

## 四、漏洞分析CVE-2023-36717

该漏洞是一个拒绝服务漏洞，当这个漏洞被触发时会导致宿主机`vmsp.exe`进程进入死循环，并占用大量CPU计算资源。由于`vmsp.exe`进程是IUM进程，所以当漏洞被触发后，管理员无法从用户态结束掉这个进程，这种情况下除非重启宿主机操作系统否则计算资源一直无法被释放。

这个漏洞位于`TpmEngUM!TPM2_ECDH_KeyGen`函数中。

```javascript
__int64 __fastcall TPM2_ECDH_KeyGen(unsigned int *a1, __int64 a2)
{
  OBJECT *v3; // rax
  OBJECT *v4; // rsi
  unsigned int v5; // eax
  unsigned int v6; // ebx
  unsigned __int16 v8[28]; // [rsp+20h] [rbp-58h] BYREF

  v3 = ObjectGet(*a1);
  v4 = v3;
  if ( v3->public_type != 0x23
    || (v3->public_objectAttributes & 0x10000) != 0
    || (v3->public_objectAttributes & 0x20000) == 0 )
  {
    return 0x19Ci64;
  }
  while ( !(unsigned __int16)cpri__GetEphemeralEcc(
                               (unsigned __int16 *)(a2 + 104),
                               v8,
                               v4->public_parameters_Detail_keyBits) )
  {
    *(_WORD *)(a2 + 0x66) = TPMS_ECC_POINT_Marshal((_BYTE *)(a2 + 104), 0i64, 0i64);
    v5 = CryptEccPointMultiply(
           (_WORD *)(a2 + 2),
           v4->public_parameters_Detail_keyBits,
           v8,
           (__int64)&v4->public_unique_ecc_x);
    v6 = v5;
    if ( v5 == 0xA7 )
      break;
    if ( v5 != 0x154 )
      goto LABEL_9;
  }
  v6 = 156;
LABEL_9:
  if ( !v6 )
    *(_WORD *)a2 = TPMS_ECC_POINT_Marshal((_BYTE *)(a2 + 2), 0i64, 0i64);
  return v6;
}
```

在`TpmEngUM!TPM2_ECDH_KeyGen`函数中，`v4->public_unique_ecc_x`成员可以从Guest中被控制，如果`v4->public_unique_ecc_x`成员是一个NULL ECC Point的情况下（`TPM2B_ECC_PARAMETER.size`为0x00,并且`TPM2B_ECC_PARAMETER.buffer`数组被0填充），`TpmEngUM!CryptEccPointMultiply`会一直返回错误码0x154，并不停的循环调用`TpmEngUM!CryptEccPointMultiply`函数，最终造成vmsp.exe进程死循环，导致宿主机拒绝服务。

## 五、漏洞分析CVE-2023-36718

该漏洞是远程代码执行漏洞，当这个漏洞被触发时会使用未初始化的栈空间变量。这个漏洞位于`TpmEngUM!CryptSecretEncrypt`函数中。

```javascript
__int64 __fastcall CryptSecretEncrypt(unsigned int a1, _BYTE *a2_plabel, __int64 a3, __int16 *a4)
{
  unsigned int v7; // ebx
  OBJECT *v8_obj; // rax
  OBJECT *v9_obj; // rdi
  unsigned __int16 DigestSize; // ax
  unsigned __int16 public_parameters_Detail_keyBits; // cx
  __int16 public_nameAlg; // cx
  void *v14; // [rsp+40h] [rbp-C0h] BYREF
  __int16 v15[28]; // [rsp+48h] [rbp-B8h] BYREF
  __int16 v16[56]; // [rsp+80h] [rbp-80h] BYREF
  __int16 v17_Z_eccpointaftermul[56]; // [rsp+F0h] [rbp-10h] BYREF

  v7 = 0;
  v8_obj = ObjectGet(a1);
  v9_obj = v8_obj;

......

  DigestSize = cpri__GetDigestSize(v8_obj->public_nameAlg);
  *(_WORD *)a3 = DigestSize;
  
......


  if ( v9_obj->public_type == 1 )
  {
 
......


  }
  else
  {
    if ( v9_obj->public_type != 0x23 )
    {

......

    }
    public_parameters_Detail_keyBits = v9_obj->public_parameters_Detail_keyBits;
    v14 = a4 + 1;
    if ( (unsigned int)cpri__EccIsPointOnCurve(
                         public_parameters_Detail_keyBits,
                         (__int64)&v9_obj->public_unique_ecc_x) )
    {
      cpri__GetEphemeralEcc((unsigned __int16 *)v16, (unsigned __int16 *)v15, v9_obj->public_parameters_Detail_keyBits);
      *a4 = TPMS_ECC_POINT_Marshal(v16, &v14, 0i64);
      if ( (unsigned int)CryptEccPointMultiply(
                           v17_Z_eccpointaftermul,
                           v9_obj->public_parameters_Detail_keyBits,
                           (unsigned __int16 *)v15,
                           (__int64)&v9_obj->public_unique_ecc_x) )
      {
        v7 = 0x9C;
      }
      else if ( BitIsSet((unsigned __int16)v9_obj->public_nameAlg, (__int64)&g_toTest, 9u) )
      {
        public_nameAlg = v9_obj->public_nameAlg;
        if ( public_nameAlg != 0x10 )
          TestAlgorithm(public_nameAlg, 0i64);
      }
      cpri__KDFe(
        v9_obj->public_nameAlg,
        (unsigned __int16 *)v17_Z_eccpointaftermul,
        a2_plabel,
        (unsigned __int16 *)v16,
        (unsigned __int16 *)&v9_obj->public_unique_ecc_x,
        8 * *(unsigned __int16 *)a3,
        (_BYTE *)(a3 + 2));
    }
    else
    {
      return 0x9C;
    }
  }
  return v7;
}
```

上面代码中的`v17_Z_eccpointaftermul`是一个栈上的数组（也可能是个结构体），`v17_Z_eccpointaftermul`的大小是0x70字节。代码中的`v9_obj->public_unique_ecc_x`成员可以从Guest中被控制，当`v9_obj->public_unique_ecc_x`成员是一个NULL ECC Point的情况下`（TPM2B_ECC_PARAMETER.size`为0x00,并且`TPM2B_ECC_PARAMETER.buffer`数组被0填充），`TpmEngUM!CryptEccPointMultiply`函数会返回一个错误码并将v7设置为0x9C。

设置完v7的值之后，程序继续走到要调用`TpmEngUM!cpri__KDFe`函数这里，此时`v17_Z_eccpointaftermul`是一个栈上未初始化的数组，并作为`TpmEngUM!cpri__KDFe`函数的第二参数进入到之后的`TpmEngUM!cpri__KDFe`函数的代码流程里。

在`TpmEngUM!cpri__KDFe`函数后续的代码流程中，使用了未初始化的栈上的数据，导致越界读或者内存损坏。下面是崩溃时的现场：

```javascript
(4afc.2f4c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
TpmEngUM!SymCryptSha512AppendBlocks_ull+0xa7:
00007ffb`38d9a42f 4d8b41f0        mov     r8,qword ptr [r9-10h] ds:00000000`00153ffe=????????????????
0:000> k
 # Child-SP          RetAddr           Call Site
00 00000000`0014ec80 00007ffb`38d99e01 TpmEngUM!SymCryptSha512AppendBlocks_ull+0xa7
01 00000000`0014eed0 00007ffb`38d99e59 TpmEngUM!SymCryptSha512Append+0x95
02 00000000`0014ef10 00007ffb`38d87724 TpmEngUM!SymCryptSha384Append+0x9
03 00000000`0014ef40 00007ffb`38d66cd7 TpmEngUM!cpri__KDFe+0x1a4
04 00000000`0014f110 00007ffb`38d7c7cd TpmEngUM!CryptSecretEncrypt+0x143
05 00000000`0014f2c0 00007ffb`38d70a54 TpmEngUM!TPM2_MakeCredential+0x7d
06 00000000`0014f340 00007ffb`38d61c54 TpmEngUM!CommandDispatcher+0xa78
07 00000000`0014f420 00007ffb`38d61313 TpmEngUM!ExecuteCommand+0x460
08 00000000`0014f530 00000001`400c3862 TpmEngUM!VTpmExecuteCommand+0x73
```

## 六、总结

借助此文简单的介绍了下Hyper-V虚拟TPM组件的两个漏洞，可以发现这两个漏洞都是Hyper-V虚拟TPM组件在处理Guest数据时发生了错误导致宿主机进程受到了影响。通过本文帮助读者更好地理解虚拟TPM组件漏洞的成因，以及希望能够在TPM组件的漏洞挖掘工作中帮到大家。
