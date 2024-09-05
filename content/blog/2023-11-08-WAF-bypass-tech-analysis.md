---
slug: tiangongarticle005
date: 2023-11-08
title: WAF防护绕过技巧分析
author: ink
tags: [WAF]
---


## 一、WAF介绍与分类

### （一）WAF简介

Web应用防护系统（Web Application Firewall，网站应用级入侵防御系统），是通过执行一系列针对HTTP/HTTPS的安全策略来专门为Web应用提供保护的产品。

市场上的WAF产品有很多，像腾讯云，阿里云，长亭等，目前世界上常年排名第一的是以色列的 Imperva。

<!-- truncate -->

### （二）WAF分类

#### 规则实现

语义分析引擎WAF，国内大多数都是正则引擎，此外还有机器学习引擎。

#### 部署方式

网络层WAF、应用层WAF、云WAF

#### WAF部署方式

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/afec3247-2aa3-424f-8b89-eff0e861a82f.png)

WAF大多是串联在这个链路中，起到一个阻断作用。就比如在Web Server和CGI之间的WAF，CGI这里特指PHP和ASP，像JSP一般就统一tomcat中间件了，就不需要CGI层了。

云部署一般先会起一个高防IP，然后用这个IP去连接WAF集群，一般来说都是从四层的流量解除七层的流量，然后再将正常的流量向后端转发，像这些企业A企业B可能在云上也可能不在。

## 二、网络层WAF Bypass

### （一）分包分组

#### 通过调整MSS控制分包

控制MSS去调整TCP分包的大小 

单个TCP会话可能含有多个HTTP会话：比如TCP先建立一个三次握手，建立之后发送多个HTTP请求，并没有断开，一般的设备都会去很好的解析处理，但是有一些古老的设备只会去解析第一个，现在已经很少了。

单个TCP包发送多组HTTP报文（Pipeline技巧以及HTTP请求走私）：就是在DATA部分写多个http请求，有的设备就会认为第一个正常，那么后面的就类似于body部分，就会出现解析错误。

HTTP请求走私和Pipeline的区别就是请求走私利用不同的Content-Length引发歧义，比如下面这个，第一个content-length是包括了下面两个，或者content-length写一个1或者2，到底Web Server会取哪一个，需要针对不同的去研究，所以取值的解析差异，就会认为他是一整个或者是三个，利用这种方式就可以去迷惑WAF。

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/923bdb52-c5db-47cf-805a-eaf649f480a8.png)

在标准的HTTP走私里面，一般content-length和Transfer-Encoding只会采纳一个，大部分优先是 Transfer-Encoding: chunked，当然也有一些两个都支持，就会出现一些问题。

#### chunked

利用chunked切分，比如下面是个最简单的chunked，对关键字进行一个拆分。

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/e7afbb3e-3a1f-47b7-a975-0b03679fbca2.png)

这里的5,4,3是以16进制写的，最后以0来结尾，如果是10个字符的话就要写A。

这种是只针对于网络层，应用层就不会出现这种问题，因为应用层是在完成chunked组包之后，才去解析，所以对应用层无效。

## 三、应用层WAF Bypass

### （一）multipart/form-data

#### 理论知识

HTTP协议POST请求，除了常规的application/x-www-form-urlencoded以外，还有multipart/form-data这种形式，主要是为了解决上传文件场景下文件内容较大且内置字符不可控的问题。multipart/form-data格式也是可以传递POST参数的。对于Nginx+PHP的架构，Nginx实际上是不负责

解析multipart/form-data的body部分的，而是交由PHP来解析，因此WAF所获取的内容就很有可能与后端的PHP发生不一致。

使用以下脚本来进行测试

```javascript
<?php

echo file_get_contents("php://input");

var_dump($_POST);

var_dump($_FILES);

?>
```

正常POST请求如下：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/0ff64f40-166c-4e4f-9661-d7103bda20bb.png)

change body encoding，如下：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/13abf27f-5ba5-40f2-80bd-6607cec89d87.png)

只有input不太一样，一个有f=1一个没有，参数并没有进入Files数组，而是进入了_POST数据。那么，何时是上传文件？何时是POST参数呢？这个关键点在于有没有一个完整的filename=。这9个字符是经过反复测试的，缺一个字符不可，替换一个字符也不可，在其中添加一个字符更不可。

加上filename=之后：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/464b3aa6-5de7-466d-9d43-0bf0f992f085.png)

可以看到这次并没有传给POST数组，而是传给了FILES数组变成了一个文件。

Bypass WAF的核心思想在于，一些WAF产品处于降低误报考虑，对用户上传文件的内容不做匹配，直接放行，比如一些压缩包图片之类的，在二进制流下面任意字符是不可控的，所以里面出现一些危险函数是很正常的。事实上，这些内容在绝大多数场景也无法引起攻击。所以让POST过去的数据去过那些规则，让FILES的只要符合白名单即可。

但关键问题在于，WAF能否准确有效识别出哪些内容是传给POST数组的，哪些传给_FILES数组？如果不能，那我们是否就可以想办法让WAF以为我们是在上传文件，而实际上却是在POST一个参数，这个参数可以是命令注入、SQL注入、SSRF等任意的一种攻击，这样就实现了通用WAF Bypass。

#### 基础案例

##### 0x00截断filename

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/91de88d7-b5a5-48c5-9895-8fe64f9b7773.png)截断之后发现传给了POST数组

有的WAF在处理包之前会将00删掉，再去解析会产生差异，所以有的地方00是不能删的，所以会产生bypass

##### 双写上传描述行

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/347cc9aa-3a0f-42dc-8b86-6292e93f1625.png)双写后，一些WAF会取第二行，而实际PHP会获取第一行

##### 双写整个part开头部分

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/7b67dc36-477b-4e81-86fd-02e8c9cf758c.png)可以看到取的还是第一行，只不过会将第二部分全部当成f的值，这里做SQL注入比较麻烦，需要将前面全都闭合掉，但是命令注入就很简单，直接将1给改成payload即可优先执行。

这里可以延伸出构造一个假的part

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/7a946a53-2a90-4765-bcc6-47db092d2f92.png)

##### 构造假的part

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/dfd5f278-a367-45e0-b4f0-73ffbc6f6cdc.png)和上一个类似，少了一个换行，这样原本干扰的部分就不会取了

##### 双写boundary

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/9bbf5693-9c08-44e9-8b62-cf728ab8625a.png)

可以看到是以a为主

##### 双写Content-Type

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/03ac2393-b053-4fcf-9ebd-26d3202a10bc.png)

还是以a为主

##### 空boundary

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/28361d93-cd48-4e8e-9bc2-db0a5ddac9ba.png)

有些WAF可能会认为boundary是；但是实际上boundary是空的

##### 空格boundary

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/81633a33-e191-48ab-bd76-dbcd4d4029b9.png)

有些WAF会把空格给去掉

##### boundary中的逗号

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/69566fca-f2b8-4f8c-b02e-aa397f5c1d31.png)boundary遇到逗号就结束了，所以取到的是a

同理，如果是 **==,; ==**，如下：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/c426ea3e-afab-43a2-a111-98fc8a1bd03c.png)

此时boundary还是空

#### 进阶案例

##### 0x00进阶

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/213c19e5-9305-4358-9b98-118904401e74.png)

如果是这样双写，其实是以第一行为主的，这样就是上传文件。但如果我们在适当的地方加入0x00、空格和 \\t ， 就会破坏第一行，让PHP反以第二行为主：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/ce29712c-f8d9-4016-8df7-a217c210d2ac.png)

如上图，随便在这三个地方加上空格，都会以第二行为主，这样防御是比较困难的，将其替换为0x00和0x20与之同理， 可自行测试

此外，在filename前面，和参数名f后面，加上0x00也是可以绕过的

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/795dc3e3-2abf-47a4-92fb-9c2e537617e2.png)

##### boundary进阶

boundary的名称是可以前后加入任意内容的，WAF如果严格按boundary去取，就可以绕过

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/71481c18-21e4-47cb-b5eb-458722cd4a7e.png)

如何取boundary也是一个问题，如下：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/76435c2b-f86f-4547-a34b-a73460c64499.png)

这里取boundary=b为boundary

##### 单双引号混合进阶

需要考虑的问题是，Content-Disposition中的字段使用单引号还是双引号

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/42991e56-19ae-4e5b-89bc-642e023077d3.png)

##### urlencoded伪装成为multipart

实际上是urlencoded，但是伪装成了multipart，通过&来截取前后装饰部分，保留id参数的完整性。理论上multipart/form-data 下的内容不进行urldecoded，一些WAF也正是这样设计的，这样做本没有问题，但是如果是urlencoded格式的内容，不进行url解码就会引入%0a这样字符，而这样的字符不解码是可以直接绕过防护规则的，从而导致了绕过。

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/425f3c95-67ee-4e0c-80b6-e173042efd9d.png)

##### skip_upload

在php源码 rfc1867.c line 909

```php
/* If file_uploads=off, skip the file part */
            if (!PG(file_uploads)) {
                skip_upload = 1;
            } else if (upload_cnt <= 0) {
                skip_upload = 1;
                sapi_module.sapi_error(E_WARNING, "Maximum number of allowable file uploads has been exceeded");
            }
```

Maximum number of allowable file uploads has been exceeded ，如何达到Maximum？ 发现在php 5.2.12和以上的版本，有一个隐藏的文件上传限制是在php.ini里没有的，就是这个max_file_uploads的设定，该默认值是20, 在php 5.2.17的版本中该值已不再隐藏。文件上传限制最大默认设为20，所以一次上传最大就是20个文档，所以超出20个就会出错了。

如下：

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/29f41f21-6fbc-40ba-9efd-7b699fac9828.png)

拼接了从a-t这20个part，实际上就填满了Maximum，导致最后一个upload无法生效，就只能从FILES转化为POST了

### （二）其他技巧

#### Host替换

host如果是一个域名，可以在最后面加一个点 ==.== ，大多数情况下表示的还是当前域名，比如之前阿里云，防护的话是用过域名控制的，传过来一个域名会先看一下有没有受到保护，假如原来的域名受到了保护，但是加了一个点，就不在名单内了，就会被认为没有开WAF

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/6ec1b459-5ec9-4418-8800-6fe12111677e.png)

还可以把Host的IP转为16进制

 ![](/attachments/2023-11-08-WAF-bypass-tech-analysis/0317a668-73cf-4061-aad9-f8b28a61480f.png)

#### URL#与../替换

如果有时候加上#引发歧义的话，可以使用../跳出

如果#不可以的话，可以尝试?#

#### HTTP参数污染

比如双参数

```sql
?id = 1 & id = and 1=1
```

有些架构会将两个拼接在一起，单独任何一个都没有问题，拼在一起就有问题了，这种的话要看后端的业务逻辑

#### HTTP/0.9

在HTTP/0.9中是没有响应头的

#### 利用chuncked构造content-length为0

```http
Content-Length:0

Transfer-Encoding: chuncked
```

两个同时出现一般会报错，如果像上面这样的话，body部分可以随便写，不会被过滤

#### 加入中文字符

针对于特殊框架，会被替换为空

#### HTTP方法构造

使用一些存在的，常用HEAD

#### 添加XFF头

127\.0.0.1或者localhost

理论可行，需要看网络架构

## 四、总结

以上这些技巧是根据原理、实践所得，参考了网上部分文章总结所得，WAF绕过并没有固定的模式，在黑盒情况下甚至你可以将所有技巧同时运用以达到目的，总之，要在不断的尝试中去绕过，然后再通过“控制变量”法去探测到底是哪一种方法奏效，以达到“通杀”的目标。
