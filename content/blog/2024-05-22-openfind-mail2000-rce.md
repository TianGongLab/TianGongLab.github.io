---
slug: tiangongarticle031
date: 2024-05-22
title:  Openfind Mail2000 认证前 RCE 漏洞分析
author: noir
tags: [Openfind, Mail Server]
---


## 一、前言

Mail2000 是一套由台湾厂商 Openfind 所开发，简单易用的电子邮件系统，被广泛使用于台湾的公家机关、教育机构，如台北市教育局、中科院，以及台湾科技大学都有使用 Mail2000 作为主要的邮件服务器。本文以研究学习为目的对 Mail2000 的一个漏洞的成因和利用进行详细分析。

该漏洞是Mail2000的Web服务在处理多个文件的http数据包时未对全局结构体中的数组进行边界检查，导致越界写堆地址。针对原作者使用堆喷+爆破的利用手法，本文将介绍一种仅爆破地址即可利用的更加稳定的手法。

<!-- truncate -->

## 二、服务器架构

邮件系统的攻击面一般是邮件服务（imap、pop3、smtp）和Web服务。

Mail2000的Web服务器采用的是Apache httpd和CGI (Common Gateway Interface)的架构，实现如图： ![图片来源：参考链接\[1\]](/attachments/2024-05-22-openfind-mail2000-rce/31052d65-e683-40ad-a229-4c75eb22129b.png)

当客户端向Web服务器（httpd）发送一个http请求时，httpd对数据包作简单的路由鉴权等处理，之后fork一个子进程。子进程中调用execve运行对应的CGI程序，CGI程序处理完请求后通过httpd发送响应给客户端。CGI程序会使用一些动态库，其中`libm2k.so`和`libm2kc.so`是由Openfind开发实现的两个核心库。本文分析的漏洞就存在`libm2kc`中。

## 三、漏洞成因

首先了解http发送多个文件的格式。在http格式中如果要发送多个文件首先需要`Content-Type`指定是`multipart`以及指定`boundary`，http正文中每两个`boundary`之间表示一个文件内容。文件内容是http头加上http正文的格式。

```http
Content-Type: multipart/form-data; boundary="--AaBbCcDd"

--AaBbCcDd
Content-Disposition: form-data; name="files"; filename="file1.txt"
Content-Type: text/plain

aaaabbbbcccc
--AaBbCcDd
Content-Disposition: form-data; name="files"; filename="file2.txt"
Content-Type: text/plain

ddddeeeeffff
--AaBbCcDd
```

在处理多个文件的请求时，`libm2kc`使用`stCGIEnv`结构体来存储相关文件信息。这里重点关注`multipart_file_arr`变量，该变量是`MultipartFileVar`结构体数组，个数固定为200。`MultipartFileVar`中的`name`和`filaname`对应文件内容中的`Content-Disposition`中的`name`和`filename`。

```c
00000000 stCGIEnv        struc ; (sizeof=0xD308, align=0x8, mappedto_126)
00000000 cgi_var_content dq ?
00000008 cgi_var_str_len_from_content_length_or_strlen dq ?
00000010 cgi_var_arr     dq 6144 dup(?)
0000C010 multipart_file_arr MultipartFileVar 200 dup(?)
0000D2D0 file_arr        dq ?
0000D2D8 file_max_count  dd ?
0000D2DC file_cur_count  dd ?
0000D2E0 cgi_var_count   dd ?
0000D2E0 field_D2E0      dq ?
0000D2E8 cgi_var_type    dd ?
0000D2EC http_method     dd ?
0000D2F0 is_multipart    dq ?
0000D2F8 MFCGI_ReaderCB  dq ?
0000D300 unk_flag        dq ?
0000D308 stCGIEnv        ends
    
00000000 MultipartFileVar struc ; (sizeof=0x18, align=0x8, copyof_127)
00000000 name            dq ?                    ; offset
00000008 filename        dq ?                    ; offset
00000010 flag            dd ?
00000014 reserved        dd ?
00000018 MultipartFileVar ends
```

`libm2kc`中首先跟据`boundary`找到每个文件内容，之后在解析`Content-Disposition`的`name`和`filename`，存放到对应的`MultipartFileVar`结构体，一个文件对应一个`MultipartFileVar`结构体。

漏洞点在于在使用`stCGIEnv.file_cur_count`作为index获取`stCGIEnv.multipart_file_arr`数组元素时并没有检查个数是否大于200。当我们发送的http请求中的文件个数超过200时会导致越界写。因为`name`和`filename`是堆地址所以实际上是越界写堆地址。

## 四、漏洞利用

既然能够越界写堆地址，肯定要看能够覆盖哪些变量。

### 4.1 覆盖函数指针

最先想到的是`MFCGI_ReaderCB`变量，这是一个函数指针，功能是在CGI初始化时读取http请求数据。因为越界写的是堆地址，而程序又开启了NX导致堆不可执行，所以该思路无法利用。

### 4.2 覆盖含有_IO_FILE结构体

接下来看正好在溢出数组的下方的三个变量

```c
0000C010 multipart_file_arr MultipartFileVar 200 dup(?)
0000D2D0 file_arr       dq ?
0000D2D8 file_max_count dd ?
0000D2DC file_cur_count dd ?
```

前面提到`MultipartFileVar`存的是`Content-Disposition`的内容，除此之外，`Content-Type`，文件内容等会存放在`file_arr`指向的结构体数组。

`file_arr`指向的结构体数组：

 ![](/attachments/2024-05-22-openfind-mail2000-rce/12e60668-ae8c-4cc1-bf40-2552e68d3af3.png)

POST file结构体大致如下：

```c
struct PostFile{
    char *content_type;
    char *body;
    int flag;
    ...
    FILE* fp;
    ....
}
```

注意到其中有一个`FILE`结构体，很容易想到ctf中`_IO_FILE`的利用。

**_IO_FILE 利用**

`_IO_FILE`的利用原理是glibc中一些操作文件的函数会调用FILE结构体中的`vtable`中的函数。

```c
//fclose
int
_IO_new_fclose (_IO_FILE *fp)
{
    ...
    _IO_acquire_lock (fp);
    if (fp->_IO_file_flags & _IO_IS_FILEBUF)
        status = _IO_file_close_it (fp);
    else
        status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
    _IO_release_lock (fp);
    _IO_FINISH (fp); // <----
    ...
    return status;
}
```

如上是glibc中`fclose`的部分源码，12行的`_IO_FINISH`展开实际上是调用`fp`的`vtable`中的函数。

```c
((_IO_FILE_plus*)fp)->vtable->__finish
```

如果我们可以控制fp，那么就可以控制vtable从而控制执行流。

在漏洞本身中的利用链如下：

 ![](/attachments/2024-05-22-openfind-mail2000-rce/13283460-7a81-42af-953a-d8cc4b54fd00.png)

回到漏洞本身，如何从file_arr可控到func可控？

程序开启了PIE和ASLR，按照ctf的常规思路是：泄露堆和libc地址，进行堆布局伪造相关架构体，最后劫持执行流。

实际泄露地址没有意义。

前文提到，该web服务器架构是，当发送一个http请求时，httpd fork子进程，运行CGI程序处理请求。

假设此时我们获得堆和libc地址，计算好实际地址后，再次发送请求。再次发送请求时，http又会重新fork一个进程处理请求，此时的子进程与处理上一个请求的进程是不同的进程，所以泄露出的地址就没有意义。

那么如何绕过ASLR？

**32位**

首先讨论32位下的利用。

在32位程序中，即使开启了ASLR，地址也只有12位是随机的。理论上有1/4096的概率爆破成功。所以通过爆破我们能够获得堆或libc的地址。

一种思路是，堆喷POSTfile、_IO_FILE等结构体来绕过ASLR，再修改vtable中的函数为libc中的函数（如system），libc中的函数地址需要通过爆破获得。这也是原作者的做法。

第二种思路，因为最后劫持执行流时需要无论如何都需要爆破libc地址，所以可以把需要伪造的结构体放到libc的正上方。

glibc中的malloc申请超过128k的内存时会使用mmap分配内存（而不是brk的内存）。mmap分配的内存会正好在libc的上方。单个请求包大小最大是128M，可以满足128k的条件。

我们可以把要伪造的结构体放进文件内容中，在解析文件时会分配空间从而将伪造的数据写到libc的正上方。

 ![](/attachments/2024-05-22-openfind-mail2000-rce/c83e4c71-14f1-4536-901b-64d5336cd59e.png)

通过这种方式，伪造结构体所需要的地址和vtable函数的地址**全部可以由libc地址加上一段偏移计算得出**。

在成功劫持程序执行流后，此时的函数调用是`func(fp)`。此时eax指向`_IO_FILE_plus`，通过下方第一个gadget将esp指向`_IO_FILE_plus`内部，在通过第二个gadget使`esp`指向gadget。之后就是利用ROP完成RCE。

```assembly
xchg esp, eax ; ret      //[1]
add esp, 0x12c ; ret     //[2]
```

**原作者做法**

首先原作者发现栈是可执行（笔者环境是不可执行的）。

 ![](/attachments/2024-05-22-openfind-mail2000-rce/0658ac1d-2c45-46d6-891a-9c8e1f27dfce.png)

此外httpd会将一些变量通过环境变量传递给cgi程序，比如`HTTP_HOST`、`REQUEST_METHOD`、`QUERY_STRING`。

例如我们发送数据包`POST /url?shellcode`，`shellcode`会通过`QUERY_STRING=shellcode`这个环境变量存放在cgi程序栈上。通过这种方式可以把shellcode布置到栈上。

之后类似第一种做法，堆喷POSTfile、_IO_FILE结构体，爆破stack地址把vtable中的函数指针指向存放shellcode的栈地址。

**64 位**

64位程序开启aslr后随机位数是28位，爆破不现实，虽然可以通过堆喷来布置POSTfile、_IO_FILE结构体，但是劫持执行流时必须要用到libc的地址，所以无法利用。

## 五、总结

一般而言，类似Mail2000的web服务器的架构的内存类漏洞利用难度较大，因为一个请求对应一个进程，这要求我们一个请求就完成利用。本文分析的漏洞正好能够控制`_IO_FILE`结构体，从而通过_IO_FILE的利用实现RCE，而且因为程序开启了ASLR，利用也只能在32位下完成。

## 六、参考链接

\[1\] [紅隊演練中的數位擄鴿](https://devco.re/blog/2019/12/23/how-binary-dog-survives-in-web-world/)
