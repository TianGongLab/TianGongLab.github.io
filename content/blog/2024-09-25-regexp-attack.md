---
slug: tiangongarticle047
date: 2024-09-25
title: 正则表达式安全研究
author: kemooo
tags: ["正则表达式"]
---

## 一、前言

当探讨计算机科学中的模式匹配技术时，正则表达式（Regular Expressions，通常简称regexp）无疑是一项强大的工具。它广泛应用于文本处理的各个方面，如搜索、编辑或者操控字符串。正则表达式允许用户通过定义特定的字符组合来查找、替换以及操作文本，其应用范围从简单的数据校验到复杂的系统日志分析等不一而足。正则表达式使用广泛，如果使用不当，会带来一些安全问题。

本文主要讨论正则表达式引起的ReDoS拒绝服务，侧信道泄露，权限绕过，数据校验，回溯限制以及正则执行问题。

## 二、ReDoS 拒绝服务

正则表达式底层通常会使用NFA非确定性有限自动机来实现，将正则匹配转换为路径匹配。举几个例子：

表达式一`a`：消耗1个字符a，可以从`起始0`到达`终态1`实现`match`

 ![](/attachments/2024-09-25-regexp-attack/834ad9ce-45d7-4884-af31-9ea1fa684432.png " =285x68")

表达式二`a*`：消耗0个或多个字符a，可以从`起始0`到达`终态1`实现`match`，图中ε表示空串

 ![](/attachments/2024-09-25-regexp-attack/1ae7c85f-e49e-4243-b93e-3817709dbcb2.png " =637x169")

`空字符串`可以直接从`0->1`找到一条访问路径, `aa`形式的字符串可以`0->2->3->4->2->3->4->1`的方式找到一条访问路径实现`match`

到此时似乎一切都没什么问题？看接下来的一个表达式

表达式三`(a*)*b`：其NFA图如下：

 ![](/attachments/2024-09-25-regexp-attack/73bd1f29-b760-482e-9eb0-e933f660fd42.png " =1346x271")

可以看到现在的`6-..>7`之间的所有路径本质和`表达式二`一致，如果把它当作一个整体并从更高层次看`0->4`之间的所有路径像是一个更大的`表达式二`，`11->12`路径形式则与`表达式一`等同。即`表达式三`由两个`表达式二`的图以"父图和子图"的方式嵌套并添加一个表达式一构成。

现在考虑如下输入及测试：

```python
# 后续文中使用的search都是该函数
# 主要用于打印正则匹配消耗的时间，单位s
def search(r,s):
    a=time.time()
    re.match(r,s)
    b=time.time()
    c=b-a
    print("use:"+str(c))

>>> search("(a*)*b","a"*22)
use:0.24314594268798828
>>> search("(a*)*b","a"*23)
use:0.4825863838195801
>>> search("(a*)*b","a"*24)
use:1.0666351318359375
>>> search("(a*)*b","a"*25)
use:2.1269423961639404
```

可以看到输入每增加一个a字符，那么正则表达式消耗时间约增加一倍。

**回溯问题**：正则表达式匹配的时候，先按照贪婪匹配所有的a，之后尝试匹配b的时候发现匹配失败，说明当前路径不匹配，那么会进行路径回退，然后尝试另一条路径，由于"表达式二"的重复嵌套，会造成回退的路径非常多，计算量非常大，最终造成了`ReDoS`拒绝服务。

对于满足如下几条性质的正则表达式，会存在指数回溯问题 【时间负载度为`O(2^n)`，n是字符的个数】

> ReDos是一种算法复杂度攻击，通过提供最坏情况输入来利用算法的攻击。
>
> 
> 1. 将 +/\* 应用到一个子正则表达式A
> 2. 子正则表达式A可以多种方式重复匹配相同的输入，比如 a|a / a+ / a|aa 等就能重复匹配输入
> 3. 在重复的表达式之后要存在一个无法与输入匹配的表达式B 【以便让匹配失败，从而路径回退】

因此之前的测试`search("(a*)*b","a"*25)`就满足上面的3个性质，下面看一些其它例子：

### 2.1 情形一：邮件格式匹配

正则表达式：

```none
^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@) {1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$
```

分析：表达式中片段`(([\-.]|[_]+)?([a-zA-Z0-9]+))*` ， 其中的`+`满足条件1，`*`满足条件2，条件3只要构造特定输入数据就能满足。

测试：

```python
>>> search("^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))* (@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$", "a"*25)
use:2.2077696323394775
```

### 2.2 情形二：Java类名匹配

正则表达式：

```none
^(([a-z])+.)+[A-Z]([a-z])+$
```

分析：表达式片段`(([a-z])+.)+`  ，第一个`+`满足条件1，第二个`+`满足条件2，条件3只要构造特定输入数据就能满足。

测试：

```python
>>> search("^(([a-z])+.)+[A-Z]([a-z])+$","a"*35)
use:1.9039454460144043
```

## 三、侧信道问题

时间延迟通常可以作为一种侧信道技术来泄露目标信息，SQL时间盲注就是一种典型的场景。

之前介绍的ReDoS拒绝服务就存在时间延迟，那在某种程度上ReDoS能否作为侧信道来使用呢？

考虑下面场景，允许用户控制正则表达式，且来匹配一个固定的字符串。

```python
# 假设可以反复控制正则表达式r,并且匹配的内容是固定的 
>>> s="your_secret."

# (?=R)称为先行断言，此处表示开头必须匹配R表达式，才会进一步执行后续正则匹配
# R如果在开头匹配，那么会进行后续的((.*)*)*bbbbb$匹配，会出现超时现象
# R如果不匹配，后续正则不会进行匹配，因此不会超时
>>> r="^(?=R)((.*)*)*bbbbb$"

# 这里开头要求a才进行后续((.*)*)*bbbbb$匹配
>>> r1="^(?=a)((.*)*)*bbbbb$"
# 这里开头要求y才进行后续((.*)*)*bbbbb$匹配
>>> r2="^(?=y)((.*)*)*bbbbb$"

# search使用和前文一样的search函数，进行正则匹配，并返回匹配消耗的时间，单位为秒
# 立马返回 注意结尾e-05意味着将小数点要向左移动5位
>>> search(r1,s)
use:1.8596649169921875e-05 
# 延迟 1.6s 才返回
>>> search(r2,s)
use:1.6887531280517578
```

通过上面的例子，可以看到在允许用户控制正则表达式的情况下，ReDoS反而变成了一种基于时间的侧信道泄露。当然这里只是一个理想中的情况，但思想上比较有意思分享一下。

## 四、权限绕过问题

Apache Shiro是一个安全框架，提供了认证、授权、加密、会话管理等一系列安全功能，可以简化应用程序中的身份验证和授权操作。

Shiro有两种表达式可以匹配路径，一种是`AntPathMatcher`，另一种是`RegExPatternMatcher`，其中`RegExPatternMatcher`用于路径的正则匹配。

这里以CVE-2022-32532为例，在Shiro<1.9.1前，若使用`RegExPatternMatcher`，且需权限检查的路由类似`/user/.*`时（存在.\*），会造成权限绕过。

上述问题产生的[源码](https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247486173&idx=1&sn=76403aaf176c3fad623215d5063845f4&chksm=c3571c51f420954777d5956b12111361558ca9eabd58ac41827968a7d258b333d70908895ad7&token=1754788930&lang=zh_CN)：

 ![](/attachments/2024-09-25-regexp-attack/f3cda53e-0e32-4066-88dd-71bbd74e98c6.png " =864x639")

JAVA默认的`Pattern.compile(pattern)`模式中.默认不匹配换行，除非启用了DOTALL模式。

因此当用户使用`/user/%0d`或者`/user/%0a`类似的url请求时，`%0d`和`%0a`会被解码为`\r\n`，`/user/%0d`或者`/user/%0a`因而不会匹配`/user/.*`，也就不需要进行权限检查，可以直接访问类似如下的路由：

```java
//后面的%0d和%0a在如下的Spring请求中可以通过如下方式被消费赋值给name
@RequestMapping(value="/user/{name}")
void info(@PathVariable String name)
{
    //...
}
```

## 五、数据校验问题

```php
# preg_match 用于正则匹配， 其中$idata是输入字符串
# function check(int seq) 会判断参数是否为特定数字格式（比如长度/大小等限制）
# $matches[1] 就是(.*)的匹配， 一个合法的输入类似 seq-3212412
!preg_match("/^seq-(.*)/", $idata, $matches)||!check($matches[1])
```

在PHP中，由于DOT .不匹配换行，所以只要构造`seq-3212412\ncustom_data`就可以绕过这里的检测，`$matches[1]`将会是3212412。若$idata被后续直接用于SQL拼接（认为检查通过），则通过custom_data造成SQL注入。

`/^seq-(.*)/s`这种方式`DOT .`才会匹配换行。

## 六、回溯限制问题

之前说过正则表达式存在ReDoS问题，但各语言也提供各种方法去缓解这个问题，比如超时设置，比如回溯次数限制，php就提供了`pcre.backtrack_limit`默认 "100000" 的限制，超过了就停止回溯。通过下面几个测试用例来理解回溯限制：

### 6.1 情形一：回溯次数不超过最大限制，且不匹配

```php
var_dump(ini_get('pcre.backtrack_limit'));
$data='abcedf';
$res=preg_match('/.*(-).*/is', $data);  
var_dump($res); 

输出
string(7) "1000000"
int(0)
```

可以看到最大回溯限制为1000000，且不匹配返回值为0。

### 6.2 情形二：回溯次数不超过最大限制，且匹配

```php
var_dump(ini_get('pcre.backtrack_limit'));
$data='abc-edf'
$res=preg_match('/.*(-).*/is', $data);  
var_dump($res);

输出
string(7) "1000000"
int(1)
```

可以看到最大回溯限制为1000000，且匹配返回值为1。

### 6.2 情形三：回溯次数超过最大限制，且匹配

```php
var_dump(ini_get('pcre.backtrack_limit'));
# 构造输入，让回溯次数超过1000000
$data='abc-edf'.str_repeat('c',1000000);
$res=preg_match('/.*(-).*/is', $data);  
var_dump($res);

输出
string(7) "1000000"
bool(false)
```

可以看到最大回溯限制为1000000，原始数据理论上是匹配的，但**当超过回溯限制1000000次时，可以看到匹配返回值为bool(false)**。如果`/.*(-).*/is`意图本身是黑名单检测，那么这种场景就会造成黑名单的绕过。

## 七、正则执行问题

正则替换函数`preg_replace`配合`/e`可产生代码执行，是PHP专有参数。

```php
preg_replace(  
    string|array $pattern,  
    string|array $replacement,  
    string|array $subject,  
    int $limit = -1,  
    int &$count = null  
): string|array|null
    
一个例子：
    $pattern="/xxx/ie" 
    // $replacement可控
    $replacement="phpinfo()"
    $subject="xxxaaa"
	上述参数做为参数，在执行preg_replace替换的时候，会触发phpinfo()执行
```

`preg_replace() - /e modifier is deprecated since PHP 5.5 and removed since PHP 7.0`

注意：这里的`/e`从php7.0开始被移除。

## 八、总结

综上所述，正则表达式作为文本处理的重要工具，在提高工作效率的同时，也要求使用者具备一定的安全意识与实践技巧。通过合理设计与应用正则表达式，不仅可以增强数据处理的准确性和效率，还能有效避免潜在的安全问题。