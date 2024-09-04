---
slug: tiangongarticle014
date: 2024-01-10
title: 破壳分析：Linksys设备多个0-day漏洞
author: w00d
tags: [破壳, Linksys, 0 day]
---

# 破壳分析：Linksys设备多个0-day漏洞

## 一、前言

Linksys E8450是销量较高的一款多功能路由器。本文会讲解下该目标的攻击面选取策略，以及如何结合逆向分析和破壳平台，对目标进行漏洞发现。最终提交至CNVD漏洞平台，并获得12个漏洞编号。

### 固件下载

[https://www.linksys.com/us/support-article?articleNum=317332](https://www.linksys.com/us/support-article?articleNum=317332)

版本：Ver. 1.2.00.273012

<!-- truncate -->

## 二、攻击面分析

### 2.1 固件解压

最新版本固件进行了加密，通过分析Ver. 1.1.01.272918 (Unsigned)固件中的升级流程，在其upgrade.cgi文件中可以得知固件解密流程如下：

 ![](/attachments/2024-01-10-linksys0-day/c2a87b6f-455b-4f57-a615-eeb424144807.png)

在arm架构设备中，chroot到其根目录后，如上执行gpg命令，可以得到最新版固件解密后的版本，名为raw.bin。

### 2.2 分析目标选择

解压后直接进入`_raw.bin.extracted/squashfs-root-0/etc`目录查看其可能使用的web服务器，发现了lighttpd文件夹，由此可以判断系统使用的web服务器是lighttpd。

一般来说直接分析开源的web服务器如lighttpd不是我们的首要选择，我们更关心Linksys自定义的一些功能。比如cgi程序（公共网关接口，是外部扩展应用程序与Web 服务器交互的一个标准接口）。

从下图大致就是cgi与web服务的关系，并且对于cgi程序`环境变量`及`标准输入` 是用户的输入。

 ![](/attachments/2024-01-10-linksys0-day/071bc4e5-118b-4864-8c47-5880a962f534.png)

根据lighttpd配置文件可知服务器的文件目录在www目录下

```plaintext
server.modules = (
)

server.document-root        = "/www"
server.upload-dirs          = ( "/tmp" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/var/run/lighttpd.pid"
```

由下面的文件可知.cgi文件会被直接访问解析

```plaintext
server.modules += ( "mod_cgi" )

##
## Plain old CGI handling
##
## For PHP don't forget to set cgi.fix_pathinfo = 1 in the php.ini.
##
cgi.assign                 = ( ".pl"  => "/usr/bin/perl",
                               ".cgi" => "",
                               ".rb"  => "/usr/bin/ruby",
                               ".erb" => "/usr/bin/eruby",
                               ".sh"  => "/bin/sh",
                               ".py"  => "/usr/bin/python" )
```

我们选取www/cgi-bin/portal.cgi为目标进行漏洞挖掘，由上配置文件信息可得，我们可以通过访问`http://target/cgi-bin/portal.cgi`的路径来访问该二进制文件。

## 三、漏洞扫描

在对目标进行逆向之前，或者逆向的过程中大家可能经常会用到一些工具来辅助逆向，帮助我们来更快的理解程序逻辑，发现容易出现漏洞的位置。常用的思路有：

1. 使用IDA脚本搜集自己定义好的一些危险函数的交叉引用。优点：可以快速帮助定位一些危险函数的调用位置。缺点：有的文件中危险函数调用处过多。且没有数据流信息，无法准确判断该位置是否是漏洞；
2. 使用参数回溯的IDA脚本或ghidra脚本。优点：更好的判断危险函数是否存在漏洞，同时提供了数据流相关的信息。缺点：对多架构支持有限，进程间调用分析效果差，展示效果差。

下图是一个破壳平台格式化字符串漏洞的污点查询结果，可以看到破壳平台的污点查询功能过程间分析及展示效果都很好，因此这里使用破壳平台来进行我们的辅助分析。

 ![](/attachments/2024-01-10-linksys0-day/64430e6a-195d-4e55-bd41-99e119f90b0e.png)

### 3.1 初步污点追踪

在未对要进行漏洞挖掘目标的二进制进行逆向分析之前，可以使用破壳平台的内置`is_source`，`is_sink`的属性进行污点追踪。

这里我们可以将portal.cgi单独上传到平台，也可以将cgi-bin目录下的文件打包成zip统一上传分析。在将待分析目标上传分析完毕后，执行命令如下：

```cypher
MATCH(n:identifier) WHERE n.is_source=1 
WITH collect(id(n)) as sourceSet 
MATCH (m:identifier) WHERE m.is_sink=1 
WITH sourceSet,collect(id(m)) as sinkSet 
CALL VQL.taintPropagation(sourceSet, sinkSet,1) 
YIELD taintPropagationPath 
RETURN taintPropagationPath 
```

可能没有接触过cypher语句的同学不是很清楚上面查询语句的含义，这里进行一下解释：

```cypher
MATCH (n:identifier) where n.is_source=1 
WITH collect(id(n)) as sourceSet
```

这条语句表示匹配分析目标中变量类型（identifier）的元素，且这些变量都被系统标志过`is_source` 的属性。（包括read函数的第二个参数，recv函数的第二个参数等常见的被认为是source点的变量），匹配到的点的集合被重命名为sourceSet，作为我们source点的集合。

```cypher
MATCH (m:identifier) where m.is_sink=1 
WITH sourceSet,collect(id(m)) as sinkSet
```

这条语句表示匹配分析目标中变量类型（identifier）的元素，且这些变量都被系统标志过`is_sink` 的属性。（包括system的第一个参数，strcpy函数的第二个参数等常见的被认为是sink点的变量），匹配到的点的集合被重命名为sinkSet，作为我们sink点的集合。

```cypher
CALL VQL.taintPropagation(sourceSet, sinkSet,1) 
YIELD taintPropagationPath 
RETURN taintPropagationPath 
```

具有sourceSet和sinkSet后我们使用平台中的函数taintPropagation来对sourceSet到SinkSet中的所有数据流路径进行查询，返回的结果重命名为taintPropagationPath。

最终查询后可得38条结果，点击查看一下数据流。经过粗略的浏览我们发现大致查出了两种数据流。

#### 数据流类型1 fgets为source

 ![](/attachments/2024-01-10-linksys0-day/decc2aae-bee7-40cb-a95e-3a695c9b4fc1.png)

可以看到是用fgets到sprintf的一条数据流，疑似缓冲区溢出。可以通过点击左上角，将显示方式从系统默认切换为全部显示。

 ![](/attachments/2024-01-10-linksys0-day/da3245a6-94af-409b-a4ec-910d66277d07.png)

可以看到fgets的第三个参数，也就是fd是来自于popen函数的返回值。功能基本都是在查看一些配置文件及网卡信息。因此这种数据流可以排除掉。

 ![](/attachments/2024-01-10-linksys0-day/3e0a1c5d-cf28-4931-9b9d-ac9f4fbe24b6.png)

#### 数据流2  getenv为source

在我们查询的第三条结果中出现了另外一种类型的数据流，从getenv到sprintf。可能是潜在的栈溢出。

 ![](/attachments/2024-01-10-linksys0-day/2041eace-ef30-43db-b30d-36763b47b017.png)

虽然对于lighttpd来说REMOTE_ADDR环境变量一般不是由用户提供的，所以此处不是漏洞。但是有很多环境变量还是用户可控的，我们可以更改下source点，专门查一下`getenv`相关的数据流进行一下审计

```cypher
MATCH (n:identifier) 
WHERE n.callee="getenv" and n.index=-1 
WITH collect(id(n)) as sourceSet 
MATCH (m:identifier) 
WHERE m.is_sink=1 
WITH sourceSet,collect(id(m)) as sinkSet 
CALL VQL.taintPropagation(sourceSet, sinkSet,1) 
YIELD taintPropagationPath 
RETURN taintPropagationPath
```

通过这种方式我们可以查询到10条相关数据流，快速进行一下审计判断发现都没有什么危险。

### 3.2 进阶数据流分析

在第一步我们对可能的危险函数以及危险的source进行简单的扫描和快速审计后，看起来没有扫到什么漏洞。目前大多数漏洞扫描工具可能也是到此为止，后面只能人眼慢慢看了。不过对于破壳平台来说我们仍然可以通过对于程序的进一步逆向分析来选取新的source点进行污点分析。

我们之前的分析其实只找到了getenv相关的数据流。但对于cgi来说我们还可以分析post请求中的content内容，这部分cgi一般都是通过stdin来进行读取的。

```c
    do {
      content_len = fgets(buffer,iVar1,stdin); //从stdin中读取数据
    } while (content_len != (char *)0x0);
    ...
    iVar1 = FUN_0042f418(buffer,__s2)//处理拿到的post请求中的content数据
    ...
  }
  int FUN_0042f418(undefined8 param_1,undefined8 param_2)
  {
    ...
    lVar3 = cJSON_Parse(param_1);           //对json进行解析
    if (lVar3 == 0) {
    puts("Failed to get root data.");
    return 1;
  }
  iVar1 = FUN_00424238(lVar3,acStack256);  
    ...
  }
  undefined8 FUN_00424238(undefined8 param_1,char *param_2)

{
    ...
    pcVar1 = (char *)FUN_004241d0(param_1,"action");   //根据键值取json结果体里对应的内容
    ...
}
```

其实根据上述代码，我们从`stdin`读取了数据，然后使用了库函数`cJSON_Parse`进行了解析返回给了v4。也就是说我们传入的post数据都会被解析为json。

再结合一些我们抓的包，post数据如下。可以看到`FUN_004241d0`处理了action字段，可以猜测该函数的功能为`get_from_json`。

```json
{
    "action": "set",
    "page": "dashboard_configuration_security"
}
```

因为`cJSON_Parse` 函数是外部函数，ghidra对于`FUN_004241d0` 函数的签名也无法正确分析，因此之前的查询数据流就会在这两处时断掉，无法顺利的查询到数据流。

我们需要重新找一个合理的source点来避开中断的地方。这时可以猜测json字段中的内容都是用户可控的。再次以`FUN_004241d0`函数**(注意是在ghidra)下的函数名**，作为source点进行污点查询。

```cypher
MATCH (n:identifier) 
WHERE n.callee="FUN_004241d0" and n.index=-1 
WITH collect(id(n)) as sourceSet 
MATCH (m:identifier) 
WHERE m.is_sink=1 
WITH sourceSet,collect(id(m)) as sinkSet 
CALL VQL.taintPropagation(sourceSet, sinkSet,1) 
YIELD taintPropagationPath 
RETURN taintPropagationPath
```

查询后可得结果150项，我们审计其中第6项结果可以看到userEmail字段会经过sprintf进行拼接，这里会造成栈溢出。经过逆向分析后发现拼接后的字符串还会作为system参数进行执行。

 ![](/attachments/2024-01-10-linksys0-day/64475633-26ed-4bb8-b764-537adf49e6e6.png)

向potral.cgi发送post请求，content如下

```json
{
    "action": "register_email",
    "page": "register_email_wizard",
    "userEmail": "';ls;# '",
    "id_email_check_btn": ""
}
```

成功进行了命令注入

 ![](/attachments/2024-01-10-linksys0-day/0e1adff9-3319-4522-9c58-498b06950bd0.png)

### 3.3 添加自定义的数据流关系

上述命令已经可以查询到我们想要的命令注入漏洞了，不过对于我们来说结果的数量还是有一些多。经过分析可知，有些处理json数据的操作处理的其实并不是我们用户读入的。其实是在处理一些配置文件的json数据。只有这里的v4是真正处理request的json数据。

 ![](/attachments/2024-01-10-linksys0-day/d1c6ef8d-824d-4007-aa68-c3f27ed3fcaa.png)

因此我们可以以上述函数的第一个参数为source点，同时使用merge命令，将之前的`FUN_004241d0` 函数（也就是分析的get_from_json）的第一个参数与返回值之间创建数据流。这样我们就可以查询

`FUN_00424238→get_from_json→危险函数` 这样的数据流了。保证了此时的json数据都是来源于我们用户可控的。

```cypher
//创建FUN_004241d0 的第一个参数和返回值之间的数据流
MATCH (n:identifier{callee:"FUN_004241d0", index:0})-[:ast*]-(m:identifier{callee:"FUN_004241d0", index:-1}) 
MERGE (n)-[:dfg{type:"same"}]->(m)
//以FUN_00424238的第一个参数为source进行污点查询
MATCH (n:identifier) 
WHERE n.callee="FUN_00424238" and n.index=0 
WITH collect(id(n)) as sourceSet 
MATCH (m:identifier) where m.is_sink=1 
WITH sourceSet,collect(id(m)) as sinkSet 
CALL VQL.taintPropagation(sourceSet, sinkSet,2) 
YIELD taintPropagationPath 
RETURN taintPropagationPath
```

此时我们查询的结果只剩下24条，可以从这些结果里很轻松的找到一些命令注入漏洞和缓冲区溢出漏洞

## 四、总结

破壳平台是一款自由度很高的漏洞挖掘工具，其灵活性能也能帮助我们具有一定逆向分析过程后减轻人工逆向数据流的工作量。除了使用平台的内置规则进行查询，还可以经过我们人工逆向分析后灵活地添加自己感兴趣的source，sink点以及相关的数据流。不仅如此还可以利用其中的ast，call graph等其他属性更好的帮助我们进行查询。
