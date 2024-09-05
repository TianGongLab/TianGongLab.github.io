---
slug: tiangongarticle007
date: 2023-11-22
title: IoT 设备中的认证绕过漏洞分析
author: noir
tags: [IoT, Authentication Bypass]
---


## 一、前言

在IOT设备中，认证漏洞出现频率较高，能够造成的很大危害。通过认证的绕过，攻击者可以访问到很多敏感接口，甚至可以结合其他漏洞直接获取设备 shell。本文将通过一些设备分析认证过程以及认证绕过。

## 二、分析

小设备认证可分为两个部分，一是登录逻辑，设备通常会要求用户输入用户名和密码来进行身份验证；二是对路由的鉴权，其作用是限制用户对不同功能和资源的访问权限。

<!-- truncate -->

### （一）登录

对于IOT设备中的Web界面，通常在未认证前仅能访问登录界面。为了找到后端登陆逻辑，我们可以借助工具如Burp Suite来进行流量抓包分析。

以某设备A为例，用Burp Suite抓包发现，登陆时请求了`/cgi/login`路由

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/43bd737d-60e0-4525-b5ac-f7fdad85df18.png)

在`/usr/bin/httpd`的ida文件中搜索`/cgi/login`，可以快速定位到注册CGI的函数。其中`http_alias_addEntryByArg`的功能是为cgi注册处理函数并设置访问所需要的权限。因此登录的逻辑`http_rpm_login`中。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/65854689-bdf2-46d2-88bf-346019f9c593.png)

有的设备会有专门的cgibin来处理cgi。例如某设备B在cgibin的main函数中使用strcmp比较请求的cgi，如果是`authentication_logout.cgi`就会进入登录逻辑。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/34decfda-e657-440e-8fcb-fe5d02bbfa68.png)

还有一些设备的路由则是在配置文件中定义，下图是一个nginx+lua的路由器的配置文件，其中定义了在在访问`/authenticate`时，在`content_by_lua`阶段加载web模块处理登陆请求。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/ce38e882-6df9-4382-b942-ca6fe3473338.png)

### （二）鉴权

一般来讲，http对路由都会有访问限制，一般在配置文件或者httpd初始化的时候会定义访问规则。

以某设备A为例，httpd在初始化时调用`http_alias_addEntry_ByArg`注册CGI处理函数。`http_alias_addEntry_ByArg`的最后一个参数，表示访问这个路由需要的权限。`g_http_author_admin`、`g_http_author_default`、`g_http_author_all`分别表示访问该CGI需要超级用户权限、普通用户权限、无需权限。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/6fa3f8b1-5d8a-4d47-8fbe-45b7a9c188e5.png)

httpd中每个请求都会通过`http_author_hasAuthor`鉴权，参数a1是一个全局变量，记录会话相关信息，其中的`user_id`表示该会话登录的用户，默认为0，在登陆成功后会赋值；a2是包含访问的路由，对应的处理函数和访问所需权限信息的结构体。该函数通过`user_id`判断`a2->author`对应bit是否为1进而确定当前用户是否有权限访问。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/85ce2731-0e84-41e5-93fd-73d66f7971d7.png)

在某设备C中则是为路由鉴权定义了一个`mime_handlers`结构体数组，

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/5f216007-6f1b-40cc-8c06-9d6a14d19ed7.png)`mime_handler`定义如下，`patten`是匹配的模式，`handler`就是路由对应的处理函数。第四个参数`auth`表示访问这个路由是否需要鉴权。

```javascript
struct mime_handler {
char *patten; // **.cgi **.html

    char *mime_type;

    void *handler;

    int auth;

};
```

 每次httpd接收到请求时会做如下处理：遍历`mime_handlers`，获取对应的`patten`字段，调用`match_one`匹配，匹配成功则获取对应的`handler`。最后在调用`handler`前根据`auth`字段判断是否需要鉴权。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/c2700e5f-1d11-45b5-87db-717715917324.png)

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/964f4cac-a987-4ecb-9e31-80dceb644c85.png)

这里有一个点，匹配所用到的patten有些是只匹配文件扩展名，例如对于`**.cgi`，`*`表明可以匹配0个或多个字符，不管.`cgi`前有多少个字符都会匹配进去，有可能后续会造成溢出。

在某设备D中，httpd使用strstr来匹配请求的是否是不需要认证的路由，当匹配到白名单路由时设置`do_not_need_auth`为1，未匹配到白名单则需要认证。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/f9d05b8b-0332-4c06-8245-48fbbac9d24b.png)

在某设备E中，在配置文件`nginx.conf`中定义，`access_by_lua`阶段加载sessioncontrol模块,重新加载用户信息,获取会话管理器`mgr`,检查请求并处理认证。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/fc15972e-d080-41a0-aacc-fa140204638a.png)

## 三、绕过

下面通过一些真实漏洞分析认证绕过。

**登录功能对于用户名/密码处理不恰当**

最简单的绕过方式是首先登陆时有默认密码，有的是硬编码在程序中，或者调试可以发现。

### 案例一：CVE-2020-8864

D-LINK DIR-882设备，在登陆时密码比较的逻辑中，28行获取我们输入的密码，第47行会调用`strlen`获得我们输入的密码的长度，之后使用`strncmp`进行比较，如果我们输入空密码，strncmp的第三个参数为0，返回值一定是0，表示比较成功，即可绕过认证。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/400905a7-3c49-4f49-9641-b9a6a9d77896.png)

漏洞修补：比较前判断用户输入密码是否为空

**会话管理存在问题，控制 Cookie 值绕过会话检查。**

### 案例二：CVE-2021-32030

ASUS RT-AX56U设备，需要鉴权的接口都会从请求获取cookie参数，之后传入auth函数。auth函数中，从nvram获取ifttt_token。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/4b996b8c-f125-41c0-ba6a-07ca6df988c4.png)

在默认情况IFTTT没有开启，ifttt_token为空，通过请求中传入空的cookie可绕过认证。

漏洞修补：比较cookie前判断cookie是否为空

### 案例三：CVE-2021-35973

Netgear wac104设备，在访问需要认证的cgi时会对session进行认证，在第42、49行首先从POST请求中获取id和sp字段的值，之后第53行snprintf将/tmp/SessionFile和sp_from_post拼接在一起作为get_id_from_session_file的参数。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/99b7f573-3462-4225-8f34-544258b9508d.png)`get_id_from_session_file`中，首先返回值赋值为0，打开`session_file`， 从`sesseion_file`读取id，如果文件不存在则直接接返回初始化为0的id。`session_file`用户可控的，通过构造`id=0&sp=AAA`这种，把`sessionfile`设置成一定不存在的文件路径，那么返回值就一定是0，可绕过`id_from_post == id_from_session_file`的检查。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/75c68998-8fa4-4bf4-acd6-2143ff210a00.png)

漏洞修补：判断session文件是否存在

**对用户访问的资源路径处理不恰当，访问到敏感接口。**

### 案例四：CVE-2021-35973

Netgear wac104设备，httpd中data段存放着无需认证的页面

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/5d9ea872-f144-4f70-8a27-3060837c306c.png)

在判断是否需要路由认证时使用`strstr`来匹配，如果匹配到了就设置`do_not_need_auth`为1，表示请求的页面不需要认证。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/892ea3ab-5c52-41b9-8372-2b63e9c1fbf4.png)

绕过方式是使用`/AAA%00currentsetting.htm`请求，`AAA`是需要认证的页面，因为匹配使用的是`strstr`，可以成功匹配。在成功之后整个url会解码，%00截断，实际访问`/AAA`页面，从而无需认证也能访问需要认证的页面。

漏洞修补：url解码前检测%00

### 案例五：CVE-2021-20090

同样有一个白名单，

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/39bcb58b-316b-46b9-9fd3-f596d1772d6e.png)

匹配时使用`strncmp`，n是白名单中字符串的长度，只匹配前几个字符，配合路径穿越，使用`/images/..%2finfo.html`可绕过认证访问`info.html`页面。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/684ac624-8737-4fef-9ac8-7cb41e65bdf4.png)

**暴露了敏感接口或接口权限设置不当**

### 案例六

还是某设备A，`/cgi/setpwd`的功能是重置密码，但是设置了`g_http_author_all`无需授权访问，导致无需认证重置密码。

 ![](/attachments/2023-11-22-analysis-of-authentication-bypass-vulnerabilities-in-IoT-devices/c9d6921a-fef0-452d-832d-89b6761814ff.png)

### 案例七

MI router ac2600设备，nginx的配置文件中，第12行变量`$http_host`可以包含不受信任的用户输入，导致存在CSRF攻击。

```javascript
server {
 listen 8197;
 # resolver 8.8.8.8;
 resolver 127.0.0.1 valid=30s;
 log_format log_subfilter '"$server_addr"\t"$host"\t"$remote_addr"\t"$time_local"\t"$request_method $request_uri"\t"$status"\t"$request_length"\t"$bytes_sent"\t"$request_time"\t"$sent_http_ MiCGI_Cache_Status"\t"$upstream_addr"\t"$upstream_response_time"\t"$http_referer"\t"$http_user_agent"';
 access_log off;
 #access_log /userdisk/data/proxy_8197.log  log_subfilter;
 #error_log /userdisk/sysapihttpd/log/error.log info;

 location / {
    proxy_set_header Accept-Encoding "";
    proxy_pass http://$http_host$request_uri;
    add_header  XQ-Mark 'subfilter';
    proxy_connect_timeout 600;
    ...
```

在`\usr\lib\lua\luci\dispatcher`关于鉴权的判断中，当`ip == "127.0.0.1" and host == "localhost"`时可绕过鉴权。

```javascript
local ip = http.getenv("REMOTE_ADDR")
local host = http.getenv("HTTP_HOST")
local isremote = ip == "127.0.0.1" and host == "localhost"
if _sdkFilter(track.flag) and not isremote then
    local sdkutil = require("xiaoqiang.util.XQSDKUtil")
    if not sdkutil.checkPermission(getremotemac()) then
        context.path = {}
        luci.http.write([[{"code":1500,"msg":"Permission denied"}]])
        return
    end
end
```

在`/usr/lib/lua/luci/controller/api/xqsystem.lua`中的`renewToken`接口,可以泄露token，从而绕过认证。

```javascript
entry({"api", "xqsystem", "renew_token"}, call("renewToken"), (""), 136)

function renewToken()
    local datatypes = require("luci.cbi.datatypes")
    local sauth = require "luci.sauth"
    local result = {}
    local ip = LuciHttp.formvalue("ip")
    if ip and not datatypes.ipaddr(ip) then
        ip = nil
    end
    local session = sauth.available(ip)
    if session and session.token then
        result["token"] = session.token
    else
        local token = luci.sys.uniqueid(16)
        sauth.write(token, {
            user="admin",
            token=token,
            ltype="2",
            ip=ip,
            secret=luci.sys.uniqueid(16)
        })
        result["token"] = token
    end
    result["code"] = 0
    LuciHttp.write_json(result)
end
```

## 四、总结

借助此文简单分析总结了IOT的一些认证绕过，可以看到这些漏洞更多的是缺少对特定条件的检查，从而攻击者可以利用这些特定条件绕过检查。通过本文能够更好地帮助大家分析IOT设备中的认证逻辑，希望在IOT漏洞挖掘中能够帮助到大家。

## 五、参考

[https://www.anquanke.com/post/id/247597](https://www.anquanke.com/post/id/247597)

[CVE-2021-35973：Netgear wac104 身份认证绕过](https://paper.seebug.org/1640/)
