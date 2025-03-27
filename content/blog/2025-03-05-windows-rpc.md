---
slug: tiangongarticle68
date: 2025-03-05
title: Windows RPC服务漏洞挖掘之旅
author: lm0963
tags: ["windows rpc"]
---


在当今的网络安全领域，Windows操作系统的漏洞挖掘一直是研究者们关注的焦点之一。其中，RPC（**Remote Procedure Call**，远程方法调用）服务作为Windows系统的核心组件，因其广泛的使用和潜在的安全风险，成为了漏洞挖掘的重要目标，历史上出了非常多的漏洞。

### 一、Windows RPC介绍

#### 1.1 RPC是什么？

RPC是Windows系统里最基础的组件之一，很多服务都是基于此开发。RPC是**Remote Procedure Call**的缩写，即远程方法调用。简单来说，客户端可以通过RPC远程调用服务端已注册的接口内的方法并取得执行结果，而无需关心具体实现。这种机制使得不同进程之间的通信变得高效且透明。

 ![](/attachments/2025-03-05-windows-rpc/7d49f978-644c-41a0-83c5-112e35b85282.png " =644x361")

#### 1.2 RPC工作原理

RPC的工作过程可以分为以下几个步骤，参考[微软官方文档](https://learn.microsoft.com/en-us/windows/win32/rpc/how-rpc-works)：


1. 客户端将参数和要调用的方法按约定序列化成NDR（`Network Data Representation`）格式。
2. 通过网络或管道将数据发送给服务端。
3. 服务端接收数据后将数据反序列化，并调用对应的接口中的方法，反序列化的数据按约定作为各参数。
4. 服务端方法执行结束后，将返回结果序列化。
5. 再次通过网络或管道将数据发送给客户端。
6. 客户端接收数据后将数据反序列化，从而获得服务端执行结果。

 ![](/attachments/2025-03-05-windows-rpc/7f638033-8eb9-4ced-9913-339d2fc20fd4.png)

#### 1.3 为什么关注RPC？

RPC作为Windows系统的核心组件，具有以下特点使其成为漏洞挖掘的重要目标，并且历史上也出现了非常多的漏洞：


1. **丰富的攻击面**：由于RPC是许多服务的基础，因此它提供了大量的潜在攻击点。
2. **高权限运行**：RPC服务通常以高权限（如`SYSTEM`权限）运行，或者至少具备`SeImpersonatePrivilege`权限。这意味着一旦被利用，攻击者可以利用RPC服务进行提权操作。

### 二、Windows RPC Demo

为了更好地理解RPC的工作机制，我们可以通过一个简单的Demo来展示RPC的基本操作。以下是[Windows官方教程](https://learn.microsoft.com/zh-cn/windows/win32/rpc/tutorial)的Windows RPC服务端和客户端代码示例：

#### 2.1 服务端代码

```clike
//file hello.idl
[
    uuid(7a98c250-6808-11cf-b73b-00aa00b677a7),
    version(1.0)
]
interface hello
{
    void HelloProc([in, string] unsigned char * pszString);
    void Shutdown(void);
}
```

```clike
/* file: hellos.c */
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "hello.h"
#include <windows.h>

void HelloProc(char * pszString)
{
    printf("%s\n", pszString);
}

void Shutdown(void)
{
    RPC_STATUS status;
 
    status = RpcMgmtStopServerListening(NULL);
 
    if (status) 
    {
       exit(status);
    }
 
    status = RpcServerUnregisterIf(NULL, NULL, FALSE);
 
    if (status) 
    {
       exit(status);
    }
}

void main()
{
    RPC_STATUS status;
    unsigned char * pszProtocolSequence = "ncacn_np";
    unsigned char * pszSecurity         = NULL; 
    unsigned char * pszEndpoint         = "\\pipe\\hello";
    unsigned int    cMinCalls = 1;
    unsigned int    fDontWait = FALSE;
 
    status = RpcServerUseProtseqEp(pszProtocolSequence,
                                   RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                   pszEndpoint,
                                   pszSecurity); 
 
    if (status) exit(status);
 
    status = RpcServerRegisterIf(hello_ServerIfHandle,  
                                 NULL,   
                                 NULL); 
 
    if (status) exit(status);
 
    status = RpcServerListen(cMinCalls,
                             RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                             fDontWait);
 
    if (status) exit(status);
 }
```


1. **初始化 RPC 服务**
   * 通过 `RpcServerUseProtseqEp` 指定通信协议和端点。
   * 通过 `RpcServerRegisterIf` 注册 RPC 接口（`hello_ServerIfHandle` 是由 MIDL 编译器对`interface hello`生成的接口句柄，表示服务端的 RPC 接口）。
2. **进入监听状态**
   * 调用 `RpcServerListen`，服务端开始监听客户端的 RPC 调用请求。
3. **处理客户端请求**
   * 当客户端通过 RPC 调用服务器端的远程过程时，RPC 运行时会调用相应的服务器存根代码，进而执行实际的远程方法（`HelloProc`和`Shutdown`）。

#### 2.2 客户端代码

```clike
/* file: helloc.c */
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "hello.h" 
#include <windows.h>

void main()
{
    RPC_STATUS status;
    unsigned char * pszUuid             = NULL;
    unsigned char * pszProtocolSequence = "ncacn_np";
    unsigned char * pszNetworkAddress   = NULL;
    unsigned char * pszEndpoint         = "\\pipe\\hello";
    unsigned char * pszOptions          = NULL;
    unsigned char * pszStringBinding    = NULL;
    unsigned char * pszString           = "hello, world";
    unsigned long ulCode;
 
    status = RpcStringBindingCompose(pszUuid,
                                     pszProtocolSequence,
                                     pszNetworkAddress,
                                     pszEndpoint,
                                     pszOptions,
                                     &pszStringBinding);
    if (status) exit(status);

    status = RpcBindingFromStringBinding(pszStringBinding, &hello_ClientIfHandle);
 
    if (status) exit(status);
 
    RpcTryExcept  
    {
        HelloProc(pszString);
        Shutdown();
    }
    RpcExcept(1) 
    {
        ulCode = RpcExceptionCode();
        printf("Runtime reported exception 0x%lx = %ld\n", ulCode, ulCode);
    }
    RpcEndExcept
 
    status = RpcStringFree(&pszStringBinding); 
 
    if (status) exit(status);
 
    status = RpcBindingFree(&hello_IfHandle);
 
    if (status) exit(status);

    exit(0);
}
```


1. **构造字符串信息**
   * 通过`RpcStringBindingCompose`将协议序列、端点等信息合并为一个字符串信息。
     * `pszEndpoint`：端点名称，指定为 `\pipe\hello`，与服务端的端点一致。
2. **创建绑定句柄**
   * 通过`RpcBindingFromStringBinding`从上述字符串信息创建一个 RPC 绑定句柄，用于与服务端进行通信。
3. **调用远程方法**
   * 在 `RpcTryExcept` 异常处理块中，客户端调用服务端的远程方法（`HelloProc` 和 `Shutdown`）。

### 三、FAX服务

`Windows Fax Server`是`Windows Server`中的一个服务器角色，可被用来远程发送和接收传真。

 ![](/attachments/2025-03-05-windows-rpc/60c92eca-07cc-44e5-a49c-556f3cfffe4b.png " =540.5x384")

微软为传真服务定义了一套基于RPC的交互协议，提供多种传真相关功能，并提供了详细的[说明文档](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/dabce486-05b1-4ea4-95fe-f2c3d5315ff4)。

 ![](/attachments/2025-03-05-windows-rpc/49dba302-fdbf-4780-b10a-79f650078252.png " =729x425.5")

#### 3.1 Fax Server Interface

[Fax服务端接口](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/1a1b8940-d97a-434e-83de-1db31d56214e)存在`105`个方法可被远程调用

 ![](/attachments/2025-03-05-windows-rpc/3f3bee49-791d-452c-b55c-878fe72658de.png " =561x363")


**CVE-2023-21694 Windows 传真服务远程代码执行漏洞**

通过查看微软文档，`FAX_CreateAccount`似乎是个有趣的方法，该方法会验证客户端用户是否有权限创建账户，若验证成功，则会根据传入的参数`Buffer`创建对应账户。如下是该方法声明：

```clike
 error_status_t FAX_CreateAccount(
   [in] handle_t hBinding,
   [in] DWORD level,
   [in, ref, size_is(BufferSize)] const LPBYTE Buffer,
   [in, range(0,FAX_MAX_RPC_BUFFER)]
     DWORD BufferSize
 );
```

可以看到`Buffer`是`LPBYTE`类型，大小由`BufferSize`决定，而[文档](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/e0fd2035-1162-4282-81fd-c5d8f7fc2dfa)上说`Buffer`应该是`FAX_ACCOUNT_INFO_0`指针类型，那么意味着在`FAX_CreateAccount`内部肯定会有类型转换。

> **Buffer:** A pointer to a **FAX_ACCOUNT_INFO_0** that contains fax account information. The **lpcwstrAccountName** member of the **FAX_ACCOUNT_INFO_0** MUST be set to the name of the operating system user account for which the new fax user account is to be created, using the same account name. The format of the user account name string is described in section 2.2.24 (**FAX_ACCOUNT_INFO_0**).

> **BufferSize:** A **DWORD** value that indicates the return size, in bytes, of the buffer that is pointed to by the *Buffer* parameter. The maximum size is **FAX_MAX_RPC_BUFFER**(section [2.2.82](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/8bb4ba82-db45-44ea-9caa-af64d7448e6d)).

`FAX_ACCOUNT_INFO_0`类型由`Fixed_Portion`和`Variable_Data`两部分组成。

 ![](/attachments/2025-03-05-windows-rpc/df089517-8d0e-4a77-ac5a-71feb34928b6.png " =466.5x151")


`Fixed_Portion`由`dwSizeOfStruct`字段（当前Fixed_Portion结构大小，固定为8）和`lpcwstrAccountNameOffset`字段（`Variable_Data`相对`FAX_ACCOUNT_INFO_0`的偏移）组成。这里需要注意的是`lpcwstrAccountNameOffset`字段后续会被转换为存放指向`Variable_Data`指针，64位下指针类型占用8字节，加上`dwSizeOfStruct`字段的4字节，一共是12字节，对齐后`Fixed_Portion`的大小为16字节，后续也是按16字节进行处理。

 ![](/attachments/2025-03-05-windows-rpc/f702b8f4-1e10-4cbd-b2bb-93a659a4d35d.png " =466.5x178.5")

`Variable_Data`只有`lpcwstrAccountName`字段，以0结尾的字符串。

 ![](/attachments/2025-03-05-windows-rpc/c70f1941-2c05-4cad-9216-d336db116467.png " =449.5x212")

分析`FAX_CreateAccount`里将`Buffer`转换为`FAX_ACCOUNT_INFO_0`的逻辑，根据`BufferSize`分配一段内存，并拷贝`Buffer`内容，接着调用`MarshallUpStructure`。此时只检查`BufferSize`不为0。

 ![](/attachments/2025-03-05-windows-rpc/3c11f4bc-1e99-415d-aaef-4d439e5f249b.png " =444.5x424.5")

`MarshallUpStructure`调用`IsBufferSizeEnough`来判断原有的`Buffer`大小是否足够，值得注意的是，整个过程并没有对`BufferSize`进行检查，调用`IsBufferSizeEnough`也不带`BufferSize`。

 ![](/attachments/2025-03-05-windows-rpc/51d671e6-1443-4f6d-a2e3-cc03c6ea6d5f.png " =584.5x424.5")

分析`IsBufferSizeEnough`，发现只要`lpcwstrAccountNameOffset`等于`0x10`即可满足要求，使`IsBufferSizeEnough`返回`True`。

 ![](/attachments/2025-03-05-windows-rpc/4ae2ecea-f596-48ba-a5ee-fad0af60b822.png " =396x452.5")

那漏洞就很明显了，当`BufferSize`为8，`lpcwstrAccountNameOffset`为0x10时，即可在后续`AjustPointersInStructuresArray`中将`lpcwstrAccountNameOffset`转换成指针时触发越界写。

 ![](/attachments/2025-03-05-windows-rpc/46dade77-e44a-43fe-9048-85f742d4ac13.png " =443x412.5")

**type_strict_context_handle**

通过查看数据类型idl文件[faxdatatypes.idl](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/5ee794d2-5962-4fff-ae09-aece836efadc)，发现定义了多种`context_handle`类型：

```clike
 typedef [context_handle] HANDLE RPC_FAX_HANDLE;
 typedef [ref] RPC_FAX_HANDLE* PRPC_FAX_HANDLE;
  
 typedef [context_handle] HANDLE RPC_FAX_PORT_HANDLE;
 typedef RPC_FAX_PORT_HANDLE* PRPC_FAX_PORT_HANDLE;
  
 typedef [context_handle] HANDLE RPC_FAX_SVC_HANDLE;
 typedef RPC_FAX_SVC_HANDLE* PRPC_FAX_SVC_HANDLE;
  
 typedef [context_handle] HANDLE RPC_FAX_MSG_ENUM_HANDLE;
 typedef RPC_FAX_MSG_ENUM_HANDLE* PRPC_FAX_MSG_ENUM_HANDLE;
  
 typedef [context_handle] HANDLE RPC_FAX_COPY_HANDLE;
 typedef RPC_FAX_COPY_HANDLE* PRPC_FAX_COPY_HANDLE;
  
 typedef [context_handle] HANDLE RPC_FAX_EVENT_HANDLE;
 typedef RPC_FAX_EVENT_HANDLE* PRPC_FAX_EVENT_HANDLE;
  
 typedef [context_handle] HANDLE RPC_FAX_EVENT_EX_HANDLE;
 typedef RPC_FAX_EVENT_EX_HANDLE* PRPC_FAX_EVENT_EX_HANDLE;
```

不同方法间混用不一样的`context_handle`，会不会存在类型混淆问题呢？实际上微软早就考虑到了这种问题，并在一开始就规定了必须使用[type_strict_context_handle](https://learn.microsoft.com/zh-cn/windows/win32/rpc/strict-and-type-strict-context-handles?redirectedfrom=MSDN)。

> This protocol MUST specify to the RPC runtime via the **type_strict_context_handle** attribute, which rejects the use of context handles created by a method that creates a different type of context handle  (\[MS-RPCE\] section 3).

 ![](/attachments/2025-03-05-windows-rpc/4b4cc31b-b212-4060-9b6b-7334a1baab21.png)

但类型混淆问题在Fax服务协议中就真的不存在吗？

#### 3.2 Fax Client Interface

[Fax客户端接口](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/9bf2e0b7-964d-4c11-b396-082f0cabc7c6)存在`4`个方法可被远程调用

 ![](/attachments/2025-03-05-windows-rpc/35b5966f-1047-4cf4-b424-7a660eb7b81a.png " =545x359")

客户端连接服务端后，为了获取服务端主动发送的事件消息，也会注册对应的RPC接口，等待服务端回连传送消息。

 ![](/attachments/2025-03-05-windows-rpc/a5412cd9-d8f2-40f9-b8b9-0a0cbaf71453.png " =456x393.5")

客户端在调用`FAX_StartServerNotification`之后会监听`1024`端口等待服务端调用`FAX_OpenConnection`回连。值得注意的是此时`1024`端口是监听在`0.0.0.0`上，所有人都可以访问该端口。

 ![](/attachments/2025-03-05-windows-rpc/64e08702-825c-4745-86a7-ed10a393a9e7.png " =677x105")


**CVE-2024-38104 Windows 传真客户端远程代码执行漏洞**

根据[文档](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-fax/6a8d8440-25a7-49aa-a4a1-7043b040dde4)说明，`Context` 参数是一个 `ULONG64` 类型的句柄，其值应与通过 `FAX_StartServerNotification` 发送的值保持一致。

```javascript
 error_status_t FAX_OpenConnection(
   [in] handle_t hBinding,
   [in] unsigned __int64 Context,
   [out] PRPC_FAX_HANDLE FaxHandle
 );
```

> **Context:** A **ULONG64** ([\[MS-DTYP\]](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-dtyp/cca27429-5689-4a16-b2b4-9325d93e4ba2) section [2.2.51](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-dtyp/32862b84-f6e6-40f9-85ca-c4faf985b822)) containing a context information handle. This handle SHOULD match the one supplied to the server when using the **FAX_StartServerNotification** family of calls. For more information, see the following topics:
>
> § **FAX_StartServerNotification**
>
> * **FAX_StartServerNotificationEx**
> * **FAX_StartServerNotificationEx2**

但逆向分析`FAX_OpenConnection`发现并没有对`Context`做任何检查，就直接作为指针使用。

 ![](/attachments/2025-03-05-windows-rpc/7ab680fe-7835-47e0-a1c4-e1184804bf2e.png " =717x402")

并且在注册RPC接口时虽然调用`RpcServerRegisterAuthInfoW`提供了认证选项，但实际上`RpcServerRegisterAuthInfoW`并不拒绝未认证的连接。

 ![](/attachments/2025-03-05-windows-rpc/582f1752-0a1f-45c8-929e-33dc56750a01.png " =762x355")

所以任何人通过`1024`端口连接，发送`FAX_OpenConnection`，都可以触发任意地址解引用。

 ![](/attachments/2025-03-05-windows-rpc/50a35f01-31bc-408a-b1f0-aa9fd995f367.png " =403x444")

### 四、StorSvc服务

#### 4.1 CVE-2024-38248 Windows 存储特权提升漏洞

`StorSvc`服务并不像传真服务一样具有完整而详细的文档说明。此时可以通过借助`RpcView`来反编译其接口方法说明。

 ![](/attachments/2025-03-05-windows-rpc/99eb1d72-fac6-4fc3-bb6d-349428a824cf.png " =804.5x359")

逆向其RPC接口注册过程，可以看到通过`RpcServerRegisterIf3`注册了两个接口。

 ![](/attachments/2025-03-05-windows-rpc/cfe71d39-0d9b-4969-b01e-b99ad3a2a234.png " =623.5x407.5")

分别具有如下方法：

 ![](/attachments/2025-03-05-windows-rpc/af6318c0-30ae-4d56-a53e-ae32e774cd0b.png " =327.5x157")

 ![](/attachments/2025-03-05-windows-rpc/d9bdb059-96d7-4d65-943a-745ea992b058.png " =367.5x437.5")

RPC接口方法具有高度的规范化特点，那么是否可以使用静态工具自动化扫描这些接口方法呢？

考虑最简单的条件竞争漏洞模式：在未加锁的情况下，存在一条路径对全局变量执行释放操作。

 ![](/attachments/2025-03-05-windows-rpc/09c3fb82-3279-40d7-879d-9339aa5f33e7.png " =463.5x300.5")

首先通过破壳平台查找会被free释放的全局变量

 ![](/attachments/2025-03-05-windows-rpc/b68b90c0-c749-4c82-bf50-d5698ca99215.png " =644.5x449.5")

增加约束条件，仅考虑那些可通过RPC接口方法调用的路径。

 ![](/attachments/2025-03-05-windows-rpc/c0a3f324-e2d8-4932-b1ae-73e5df5d3c90.png " =949x104.5")

 ![](/attachments/2025-03-05-windows-rpc/88c6aa10-56f9-4967-aa27-1ac78d4a2c73.png " =949x92")

当两个线程同时进入`StorageService::GetLastFailedSaveLocationPath`会导致条件竞争，全局变量`Block`会被释放两次。

 ![](/attachments/2025-03-05-windows-rpc/c1082900-95e6-45c0-bbba-43b2961dfa10.png " =542x343")

 ![](/attachments/2025-03-05-windows-rpc/d863480d-b2f8-4256-8578-f1840cb87462.png " =538x569")

### 五、**总结**

通过本文，我们简单探讨了RPC服务的工作原理、漏洞挖掘方法以及具体案例分析。RPC服务作为Windows系统的核心组件，其安全性和稳定性对于整个系统的安全至关重要。在实际的漏洞挖掘过程中，我们需要关注RPC服务的以下特点：


1. **丰富的攻击面**：RPC服务提供了大量的潜在攻击点，需要仔细分析每个接口方法的实现和调用过程。
2. **高权限运行**：RPC服务通常以高权限运行，一旦被利用，攻击者可以实现提权等恶意操作。
3. **复杂的通信机制**：RPC的通信机制涉及参数的序列化与反序列化、网络传输等多个环节，容易出现安全漏洞。