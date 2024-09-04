---
slug: tiangongarticle018
date: 2024-02-21
title: WebAssembly安全研究总结
author: ha1vk
tags: [WebAssembly]
---

# WebAssembly安全研究总结

## 一、前言

WebAssembly（简称wasm）是一种可移植、体积小、加载快并且能够在浏览器上运行的一种程序文件。其能够在JavaScript通过接口进行调用执行。开发者们一直都比较关心JS的运行速度问题，V8引擎在JS的运行速度方面做了巨大的优化，但是少数情况下我们进行大量本地运算的时候，仍然可能遇到性能瓶颈，这个时候webassembly的作用就凸现出来了。例如AutoCAD利用编译器将其沉淀了30多年的代码直接编译成WebAssembly，同时性能基于之前的普通Web应用得到了很大的提升。

C/C++/Rust源代码可以被编译为WebAssembly文件，然后JS层就可以对其进行调用。WebAssembly文件中存储着字节码，位于JavaScript引擎中的WebAssembly虚拟机将会执行字节码。字节码的执行有两种方式，一种是在运行时边读取opcode边执行，另一种则是在执行前将整个WebAssembly JIT翻译为本地汇编代码，然后直接跳转到汇编代码执行。V8采用的是第二种方式。

<!-- truncate -->

## 二、WebAssembly虚拟机

WebAssembly虚拟机是一种栈虚拟机，变量使用栈进行传递。WebAssembly虚拟机有两个栈，即数据栈和指令栈。

 ![](/attachments/2024-02-21-webassembly/56b5ed8a-ccfa-4ad9-8216-4e80690f9b07.png)

WebAssembly的数据栈只用于存储数据，**不会存储任何指针**；指令栈只用于存储指令和数据在数据栈中的**下标**，**不会存储任何数据**，并且在执行opcode时会对取出的下标进行边界检查。由于WebAssembly将数据和程序流用栈给分隔开了，也就不会发生像汇编代码中的栈溢出劫持返回地址的漏洞利用手法。简而言之，WebAssembly中的所有指令都无法操作指针，也就不存在任意地址读写。但是传统的漏洞仍然存在，只是不能直接劫持程序流了。

## 三、WebAssembly文件格式

编译代码 `emcc hello.c -s WASM=1 -o hello.html`

```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
   char buf[100];
   memset(buf,0,100);
   scanf("%s",buf);
   printf("hello world: %s\n",buf);
   return 0;
}
```

将得到的hello.wasm使用wabt项目中的wasm2wat转为S表达式 `./wasm2wat hello.wasm > hello.wat` S-表达式是一个非常简单的用来表示树的文本格式，跟wasm二进制文件是简单的对应关系。

```clike
(module
  (type (;0;) (func (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func (;0;) (type 9)))
  (func (;0;) (type 8)
    i32.const 1
    i32.const 2
    i32.add
    ....
  )
  (table (;0;) 9 9 funcref)
  (memory (;0;) 256 256)
  (global (;0;) (mut i32) (i32.const 65536))
  (export "memory" (memory 0))
  (elem (;0;) (i32.const 1) func 13 12 14 39 40 43 44 46)
  (data (;0;) (i32.const 100) "hello")
  (start 0))
)
```

使用010-Editor打开hello.wasm文件，可以看到对应的结构：

 ![](/attachments/2024-02-21-webassembly/d0c3a498-1c9f-46d6-a5c9-e98bde408d90.png)

S表达式和WASM二进制之间是简单的翻译关系。由于S表达式的比较容易理解，在逆向WASM时可以直接阅读S表达式。

## 四、传统漏洞模式在WebAssembly中的变化

### 4.1 格式化字符串

编译代码 emcc hello.c -s WASM=1 -o hello.html

```clike
#include <stdio.h>
#include <string.h>

int main() {
   char buf[100];
   memset(buf,'a',100);
   printf("%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p\n");
   return 0;
}
```

运行结果

 ![](/attachments/2024-02-21-webassembly/8236e07c-1836-4306-8ada-c600b5c7a771.png)

编译后查看S表达式，我们重点关注一下S表达式的import表，这是WASM用于导入外部函数、库函数用的，有点类似于ELF的GOT表，不同的是import表即可以导入WASM虚拟机实现的内部的库函数，还能导入用户用JS写的函数。

```clike
  (import "wasi_snapshot_preview1" "fd_write" (func (;0;) (type 9)))
  (import "env" "emscripten_memcpy_js" (func (;1;) (type 12)))
  (import "wasi_snapshot_preview1" "fd_close" (func (;2;) (type 0)))
  (import "wasi_snapshot_preview1" "fd_read" (func (;3;) (type 9)))
  (import "env" "emscripten_resize_heap" (func (;4;) (type 0)))
  (import "wasi_snapshot_preview1" "fd_seek" (func (;5;) (type 10)))
```

在这里我们没有看到printf，该函数被编译进了WASM。通过测试，格式化字符串漏洞仍然存在，`%p%p%p%p%p%p%p%p%p%p%p`能够泄漏出一些数据，但是运行结果并未泄漏出栈上的buf，这跟printf在不同的WebAssembly编译器中实现有关。

### 4.2 堆溢出

```clike
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fun() {
   printf("fun\n");
}

void fun2() {
   printf("fun2\n");
}

typedef struct Node {
   void (*f)();
   char buf[100];
} Node;

int main() 
{
   char *p = (char* *)malloc(0x10);
   Node *node = (Node *)malloc(sizeof(Node));
   node->f = fun;
   strcpy(node->buf,"hello world\n");
   node->f();
   printf("before ptr=%p,buf=%s\n",node->f,node->buf);
   memset(p,'a',0x100);
   printf("after ptr=%p,buf=%s\n",node->f,node->buf);
   node->f();
   return 0;
}
     
```

运行结果

 ![](/attachments/2024-02-21-webassembly/8db4fb57-dbdb-4f14-8f37-a149838e5334.png)

堆溢出仍然存在，可以覆盖堆中的数据。根据前面的介绍，WASM数据区不可能存储指针，因此结构体中的f函数指针实际上是一个偏移值，可以利用溢出覆盖偏移值，进而能够去执行其他的wasm函数。但是这里无法像汇编那样能够跳转到任意函数以及gadgets，这里只能跳转到在函数表(func表)中存储的函数。

### 4.3 栈溢出

```clike
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fun() {
   printf("fun\n");
}

void fun2() {
   printf("fun2\n");
}

typedef struct Node {
   void (*f)();
   char buf[100];
} Node;

int main() {
   Node node;
   char buf[10];
   node.f = fun;
   strcpy(node.buf,"hello world\n");
   node.f();
   printf("before ptr=%p,buf=%s\n",node.f,node.buf);
   memset(buf,'a',100);
   printf("after ptr=%p,buf=%s\n",node.f,node.buf);
   node.f();
   return 0;
}
```

运行结果

 ![](/attachments/2024-02-21-webassembly/439f2621-1863-487c-91f9-ad853cef7764.png)

栈溢出与堆溢出类似，可以覆盖后方的一些数据结构，有函数指针的话可以覆盖函数的index，但是返回地址没有保存在数据栈中，因此不影响程序的返回执行。与汇编不同的是，WASM的栈空间溢出会把 **前面的变量覆盖**，这是因为WASM开辟栈时是按照代码顺序来的，遇到node时，先压栈，遇到buf时，再压栈，这也就会导致buf在node的内存前面，可以覆盖到。

### 4.4 数组越界

```clike
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
   int x = 0;
   char buf[16];
   memset(buf,'a',0x10);
   size_t data[1];
   for (int i=-100;i<100;i++) {
      printf("%p\n",data[i]);
   }
   return 0;
}
```

运行结果

 ![](/attachments/2024-02-21-webassembly/e3adfcc2-a9ad-496a-a210-a6b883fa296c.png)

数组越界可以泄漏数据区的任何数据，但是只会限定在数据区，因为下标的上下限就是数据栈的边界，这种边界检查在对应的访存opcode的handler中会进行。

## 五、WebAssembly的一些利用思路

### 5.1 前端XSS

```clike
#include <stdio.h>
#include <string.h>
#include <emscripten.h>

int main() {
    char msg[100];
    char buf[10];
    strcpy(msg,"alert('Hello, world!');");
    scanf("%s",buf);
    emscripten_run_script(msg);
    return 0;
}
```

输入`aaaaaaaaaaalert('hacked');`，可以将`emscripten_run_script`的参数覆盖，执行任意的JS代码。

运行结果

 ![](/attachments/2024-02-21-webassembly/55bf9870-af90-4d0c-9d50-5d367576da04.png)

如结果所示，可以利用溢出覆盖一些能够执行JS脚本的函数的参数，当然也可以覆盖结构体中的函数偏移指向`emscripten_run_script`函数，并控制好参数去执行JS脚本。

### 5.2 服务器端RCE

WebAssembly不仅可以在浏览器中使用，还能够在服务器端被nodejs使用。与浏览器不同的是，nodejs可以支持系统操作API，例如`system、open`等函数，都能够在nodejs的`WebAssembly`中正常使用，那么就可以利用溢出等漏洞控制`system的参数`来达到命令执行 编译以下代码`emcc 1.c -o 1.js -s EXPORTED_FUNCTIONS="["_vuln"]" -s "EXTRA_EXPORTED_RUNTIME_METHODS=['ccall']"`

```clike
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <emscripten.h>

int EMSCRIPTEN_KEEPALIVE vuln(char *p) {
    char msg[100];
    char buf[10];
    strcpy(msg,"echo hello");
    strcpy(buf,p);
    system(msg);
    return 0;
}
```

在nodejs中调用

```javascript
const m = require('./1.js');
m.ccall('vuln','int',['string'],['aaaaaaaaaals /;echo hacked;'])
```

运行结果

 ![](/attachments/2024-02-21-webassembly/02e22721-3e38-4320-99ee-afdd8c98817d.png)

还可以利用漏洞改写函数偏移，指向system并控制好参数，主动执行命令。或者是system函数参数部分可控，则可以命令注入。

### 5.3 思路总结

首先需要关注WebAssembly附带的js文件，看看里面写了哪些导入和导出函数，如果是在nodejs中的WebAssembly，要是导入函数中有一些能够操作系统的函数如`system、open`等，则重点关注，然后利用`wasm2wat`将wasm文件转换为wat S表达式，审计这些函数的参数是否存在或者可以注入等漏洞；要是有溢出漏洞，则看能否覆盖参数，或者覆盖函数偏移值。

## 六、WebAssembly虚拟机逃逸

在BlackHat USA 2022的议题上我发表了一篇名为`Is WebAssembly Really Safe? - WasmVMEscape andRCEVulnerabilities Have Been Found in New Way`的议题，讲的就是WebAssembly的虚拟机逃逸。WebAssembly虚拟机逃逸漏洞重点关注三个方面：**字节码的执行漏洞、WASM二进制结构解析漏洞、导入表库函数实现中的漏洞。** 这三个关注的是虚拟机的本身而不是位于虚拟机里的WASM代码，因此又可以回到传统漏洞模式的思路。

### 6.1 CVE-2022-48503

#### 漏洞信息

位于Apple WebKit的`Source/JavaScriptCore/wasm/WasmInstance.cpp`中，对WebAssembly进行加载解析时，`m_module->moduleInformation().dataSegmentsCount()`的值未检查大小，是直接从WASM文件中读取的，从而导致`dataSegmentIndex`可以越界。

```cpp
Instance::Instance(VM& vm, JSGlobalObject* globalObject, Ref<Module>&& module)
......

    for (unsigned dataSegmentIndex = 0; dataSegmentIndex < m_module->moduleInformation().dataSegmentsCount(); ++dataSegmentIndex) {
        const auto& dataSegment = m_module->moduleInformation().data[dataSegmentIndex];
        if (dataSegment->isPassive())
            m_passiveDataSegments.quickSet(dataSegmentIndex);
    }
......
}
```

#### 修复

在`Source/JavaScriptCore/wasm /WasmSectionParser.cpp`文件中添加了一个`numberOfDataSegments > maxDataSegments`的检查。

```cpp
auto SectionParser::parseDataCount() -> PartialResult
{
    uint32_t numberOfDataSegments;
    WASM_PARSER_FAIL_IF(!parseVarUInt32(numberOfDataSegments), "can't get Data Count section's count");
    //HERE
    WASM_PARSER_FAIL_IF(numberOfDataSegments > maxDataSegments, "Data Count section's count is too big ", numberOfDataSegments , " maximum ", maxDataSegments);</font>
    m_info->numberOfDataSegments = numberOfDataSegments;
    return { };
}
```

### 6.2 CVE-2022-28990

WebAssembly的导入库函数是一个可研究的方向，导入函数可以从wasm转为S表达式后的`import` 表中看到。

```clike
  (import "env" "system" (func (;0;) (type 0)))
  (import "wasi_snapshot_preview1" "fd_close" (func (;1;) (type 0)))
  (import "wasi_snapshot_preview1" "fd_read" (func (;2;) (type 10)))
  (import "env" "emscripten_resize_heap" (func (;3;) (type 0)))
  (import "env" "emscripten_memcpy_js" (func (;4;) (type 13)))
  (import "wasi_snapshot_preview1" "fd_seek" (func (;5;) (type 12)))
```

有的导入函数来自于JS层写的自定义函数，有点则来自于虚拟机自身实现的库函数。例如在上面我们看到`system`函数是从`env`导入的，而`fd_read`则是从`wasi_snapshot_preview1`导入的，对应的我们在js文件中看到。

```clike
var wasmImports = {
  /** @export */
  emscripten_memcpy_js: _emscripten_memcpy_js,
  /** @export */
  emscripten_resize_heap: _emscripten_resize_heap,
  /** @export */
  fd_close: _fd_close,
  /** @export */
  fd_read: _fd_read,
  /** @export */
  fd_seek: _fd_seek,
  /** @export */
  system: _system
};

function createWasm() {
  // prepare imports
  var info = {
    'env': wasmImports,
    'wasi_snapshot_preview1': wasmImports,
  };
...
  instantiateAsync(wasmBinary, wasmBinaryFile, info, receiveInstantiationResult);
...
```

可以看到emcc生成的WASM JS接口文件同时指定了`env`和`wasi_snapshot_preview1`表。实际上`wasi_snapshot_preview1`库是`WebAssembly System Interface(WASI)`标准的库，`WASI`是一套系统API接口，拥有像`fd_write、fd_read、sock_accept`等系统函数，某些WebAssembly虚拟机会在内部实现自己的一套WASI，对于这种有自己实现WASI接口的WebAssembly虚拟机，在JS层就无需再去实现`wasi_snapshot_preview1`的导入函数。

Wasm3是一款能够在嵌入式设备上运行的WebAssembly虚拟机，在嵌入式设备上使用WebAssembly的优点是可以做到类似于Java一样的**一次编译到处运行**，无需考虑嵌入式设备的底层适配。

 ![](/attachments/2024-02-21-webassembly/27f45fc0-fa9c-4851-9214-202ae65c94ca.png)

Wasm3内部实现了`WASI`标准，而漏洞则出现在库函数`fd_write、fd_read`中。

```cpp
# define m3ApiOffsetToPtr(offset)   (void*)((uint8_t*)_mem + (uint32_t)(offset))
#  define m3ApiReadMem32(ptr)        m3_bswap32((* (uint32_t *)(ptr)))

static inline
void copy_iov_to_host(void* _mem, struct iovec* host_iov, wasi_iovec_t* wasi_iov, int32_t iovs_len)
{
    // Convert wasi memory offsets to host addresses
    for (int i = 0; i < iovs_len; i++) {
        host_iov[i].iov_base = m3ApiOffsetToPtr(m3ApiReadMem32(&wasi_iov[i].buf));
        host_iov[i].iov_len  = m3ApiReadMem32(&wasi_iov[i].buf_len);
    }
}

m3ApiRawFunction(m3_wasi_generic_fd_read)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArg      (__wasi_fd_t          , fd)
    m3ApiGetArgMem   (wasi_iovec_t *       , wasi_iovs)
    m3ApiGetArg      (__wasi_size_t        , iovs_len)
    m3ApiGetArgMem   (__wasi_size_t *      , nread)

    m3ApiCheckMem(wasi_iovs,    iovs_len * sizeof(wasi_iovec_t));
    m3ApiCheckMem(nread,        sizeof(__wasi_size_t));

#if defined(HAS_IOVEC)
    struct iovec iovs[iovs_len];
    copy_iov_to_host(_mem, iovs, wasi_iovs, iovs_len);

    ssize_t ret = readv(fd, iovs, iovs_len);
......
```

在函数`copy_iov_to_host`中，使用`m3ApiOffsetToPtr`对WASM字节码传过来的`offset`进行转换，即加上`_mem`的地址，得到要读取的目标地址，漏洞出现在没有对`offset`进行检查，可以传入任意的offset从而溢出`_mem`，实现任意地址写；同理，`fd_write则可以实现任意地址读` 如下的`POC`读取了`_mem + 0x10000`处的数据。

 ![](/attachments/2024-02-21-webassembly/a563c477-4690-468f-a9ff-141cd71e12f3.png)

### 6.3 Off by One in WasmEdge

#### 漏洞分析

WasmEdge是另一款WebAssembly虚拟机。

 ![](/attachments/2024-02-21-webassembly/0a449191-695d-45c4-8f49-9cc5a7b03f44.png)

在其迭代的开发版本中曾经出现过一个字节码的off by one漏洞。Executor::execute函数是WasmEdge解释执行WebAssembly字节码的函数。

```cpp
Expect<void> Executor::execute(Runtime::StoreManager &StoreMgr,
                               Runtime::StackManager &StackMgr,
                               const AST::InstrView::iterator Start,
                               const AST::InstrView::iterator End) {
  AST::InstrView::iterator PC = Start;
  AST::InstrView::iterator PCEnd = End;
  auto Dispatch = [this, &PC, &StoreMgr, &StackMgr]() -> Expect<void> {
    const AST::Instruction &Instr = *PC;
    switch (Instr.getOpCode()) {
    ......
    case OpCode::Br:
      return runBrOp(StackMgr, Instr, PC);
   ......
 };
  while (PC != PCEnd) {
    OpCode Code = PC->getOpCode();
    ......
    if (auto Res = Dispatch(); !Res) {
      return Unexpect(Res);
    }
    PC++;
  }
......
```

重点关注`OpCode::Br`指令的实现。

```cpp
Expect<void> Executor::runBrOp(Runtime::StackManager &StackMgr,
                               const AST::Instruction &Instr,
                               AST::InstrView::iterator &PC) noexcept {
  return branchToLabel(StackMgr, Instr.getJump().StackEraseBegin,
                       Instr.getJump().StackEraseEnd, Instr.getJump().PCOffset,
                       PC);
}

Expect<void> Executor::branchToLabel(Runtime::StackManager &StackMgr,
                                     uint32_t EraseBegin, uint32_t EraseEnd,
                                     int32_t PCOffset,
                                     AST::InstrView::iterator &PC) noexcept {
  // Check stop token
  if (unlikely(StopToken.exchange(0, std::memory_order_relaxed))) {
    spdlog::error(ErrCode::Interrupted);
    return Unexpect(ErrCode::Interrupted);
  }
  StackMgr.stackErase(EraseBegin, EraseEnd);
  PC += PCOffset;
  return {};
}
```

branchToLabel会把`PC`加上`PCOffset`，但是在`Executor::execute`的尾部还有一个`PC++`

```javascript
Expect<void> Executor::execute(Runtime::StoreManager &StoreMgr,
                               Runtime::StackManager &StackMgr,
                               const AST::InstrView::iterator Start,
                               const AST::InstrView::iterator End) {
......
  AST::InstrView::iterator PC = Start;
......
  while (PC != PCEnd) {
    OpCode Code = PC->getOpCode();
    ......
    if (auto Res = Dispatch(); !Res) {
      return Unexpect(Res);
    }
    PC++; //Here
  }
```

在某种情况下，`auto Res = Dispatch()`处理`Br`指令，将PC加上`PCOffset`，此时PC的值将等于`PCEnd`，但是循环还没结束，后面还有一条`PC++`语句，执行后，`PC == PCEnd + 1`，此后`while (PC != PCEnd)`将永远成立，那么就会继续读取`PCEnd + 1`处的数据结构来执行。

#### 漏洞利用

WasmEdge在运行WASM时首先会进行解析编译，构造出两个栈，一个执行栈`_pc stack`，另一个则是数据栈`_sp stack`，`_pc stack`是在解析时生成的，字节码无法操作`_pc stack`，只能操作数据栈`_sp stack`，正如WebAssmebly标准定义的那样。`_pc stack`中的所有数据，例如`下标`，都是在解析时检查通过的，如果某个下标能够溢出数据栈，将在解析时被检查到，从而终止wasm的解析，进而也不会执行。

 ![](/attachments/2024-02-21-webassembly/f3c8dec7-d8ff-47da-842a-72fe5b0e66c9.png)

漏洞的情况表现如下：

 ![](/attachments/2024-02-21-webassembly/08972fe8-e0eb-4f74-b7aa-07ea546520b9.png)

对于WebAssmebly虚拟机自己来说，PCEnd+1在`_pc stack`这块堆内存之外，如果能够在`PCEnd + 1`处布置自定义的数据，漏洞将得以利用。这是因为前面提到，`PC`栈里的数据都是经过检查的，这里再补充一条就是在运行时，这些`Opcode`的处理函数`Handler`将不会再次检查参数。 例如`global.set`指令的处理函数如下：

```cpp
Expect<void> Executor::runGlobalSetOp(Runtime::StackManager &StackMgr,
                                      uint32_t Idx) const noexcept {
  auto *GlobInst = getGlobInstByIdx(StackMgr, Idx);
  assuming(GlobInst);
  GlobInst->getValue() = StackMgr.pop();
  return {};
}
Runtime::Instance::GlobalInstance *
Executor::getGlobInstByIdx(Runtime::StackManager &StackMgr,
                           const uint32_t Idx) const {
......
  return ModInst->unsafeGetGlobal(Idx);
}

GlobalInstance *unsafeGetGlobal(uint32_t Idx) const noexcept {
    return GlobInsts[Idx];
}
```

unsafeGetGlobal直接使用了从`PC`栈中获取的下标来读取数据，并不检查下标是否越界，因为在WASM解析时就已经做过了下标边界的检查，无需再检查。 现在由于漏洞溢出的原因，`PC`将继续从后面的内存进行取值，而后面的内存我们是可以在一定程度上控制的，比如我们伪造一条`global.set`的指令结构体，并将Idx下标设置为我们想要的任意值，将能够实现**任意地址写**。

我们可以**使用i64.const来进行堆风水的布局**。

 ![](/attachments/2024-02-21-webassembly/0b8a232b-998e-4fed-8c56-a687f7744444.png)

这是因为运行时，此类opcode的处理就是向C++的`vector`中push一个新的数据，而`vector`是可以进行内存分配的，只要不断的压入数据，就能分配很多的内存。

```cpp
case OpCode::I32__const:
case OpCode::I64__const:
case OpCode::F32__const:
case OpCode::F64__const:
StackMgr.push(Instr.getNum());
return {};
```

因此我们在POC中写了很多的`i64.const`指令，最终的效果如下：

 ![](/attachments/2024-02-21-webassembly/8e21c1c1-3deb-461b-824c-3898f6ba8d85.png)

不幸的是End后面的内存并不完全可控，幸运的是我们能够控制`End + 1`的位置的第三个字段的值，查看指令结构体：

```cpp
struct Instruction {
      uint32_t JumpEnd;
      uint32_t JumpElse;
      BlockType ResType;
      uint32_t Offset = 0;
      OpCode Code;
      struct {
         bool IsAllocLabelList : 1;
         bool IsAllocValTypeList : 1;
      } Flags;
};
```

可控位置正好对应了指令结构体中的`Code`成员，也就是opcode能够任意指定，能够跳转到任何的opcode的handler中去执行，但是相关参数不可控制。一个好的思路是看能否执行某条`Opcode Handler`,将`PC`指向完全可控区。其中一条`Else`指令可以被利用。

```cpp
Expect<void> Executor::execute(Runtime::StoreManager &StoreMgr,
......
    case OpCode::Else:
......
      PC += PC->getJumpEnd();
      [[fallthrough]];
    case OpCode::End:
      PC = StackMgr.maybePopFrame(PC);
      return {};
......
```

处理Else指令时，会将`PC`加上`getJumpEnd()`。

 ![](/attachments/2024-02-21-webassembly/af609951-a7ea-48f5-9657-04019867be64.png)

在内存中看到对应`JumpEnd`的位置数据为`0x154`，意味着我们可以让`PC += 0x154`，这已经足够让我们将`PC`指向可控区了。

由于`Instruction`结构体的大小为32字节，而数据栈中的32字节的数据类型有`v128.const i64x2`，因此我们可以用`v128.const i64x2`来伪造整个`Instruction`结构体。最终的效果如下，在`PCEnd+1`处伪造一条`Else`指令，将`PC`转移到数据栈中，并执行伪造的一系列指令。

 ![](/attachments/2024-02-21-webassembly/22aff027-6458-431a-b211-67a2c6621142.png)

例如`global.get`和`global.set`的伪造如下：

```python
def Global_Get(index):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (index)
   code += 'nop\n'
   code += 'v128.const i64x2 0x2300000000 0\n'
   return code
def Global_Set(index):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (index)
   code += 'nop\n'
   code += 'v128.const i64x2 0x2400000000 0\n'
   return code
def i32_const(value):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (value)
   code += 'nop\n'
   code += 'v128.const i64x2 0x4100000000 0\n'
   return code
......
```

通过设置index，能够实现任意地址读写，进而构造后续RCE。

## 七、总结

目前还很少爆出WebAssmebly相关产品的漏洞，或许未来会有更多使用WebAssmebly的产品，本文为其研究提供了一种思路。对代码本身的漏洞，在WebAssmebly里会受到限制进而导致传统漏洞模式变得难以利用，但是仍然具有挖掘的方面。对于WebAssmebly虚拟机，不同的厂商可能实现不一样，可以针对其中的**数据结构解析、指令执行、导入函数的底层实现**入手，挖掘虚拟机本身的漏洞进而达到虚拟机逃逸控制主机的目的。

## 八、参考

[WebAssembly完全入门——了解wasm的前世今身](https://zhuanlan.zhihu.com/p/68048524)

[编译C/C++ 为 WebAssembly](https://developer.mozilla.org/zh-CN/docs/WebAssembly/C_to_Wasm)

[理解 WebAssembly 文本格式](https://developer.mozilla.org/zh-CN/docs/WebAssembly/Understanding_the_text_format)

[us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web-wp](https://i.blackhat.com/us-18/Thu-August-9/us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web-wp.pdf)

[us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web](https://i.blackhat.com/us-18/Thu-August-9/us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web.pdf)

[us-18-Silvanovich-The-Problems-and-Promise-of-WebAssembly](https://i.blackhat.com/us-18/Thu-August-9/us-18-Silvanovich-The-Problems-and-Promise-of-WebAssembly.pdf)

[Everything Old is New Again: Binary Security of WebAssembly](https://www.usenix.org/system/files/sec20-lehmann.pdf)

[US-22-Hai-Is-WebAssembly-Really-Safe-wp](https://i.blackhat.com/USA-22/Wednesday/US-22-Hai-Is-WebAssembly-Really-Safe-wp.pdf)

[US-22-Hai-Is-WebAssembly-Really-Safe](https://i.blackhat.com/USA-22/Wednesday/US-22-Hai-Is-WebAssembly-Really-Safe.pdf)

[WASI API](https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md)
