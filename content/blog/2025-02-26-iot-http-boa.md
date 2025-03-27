---
slug: tiangongarticle65
date: 2025-02-26
title: IoT小设备HTTP漏洞挖掘研究：BOA篇
author: OneShell
tags: ["iot","boa"]
---


BOA是IoT小设备上常见的HTTPD之一。本文将从源码分析、漏洞挖掘、真实漏洞分析三个部分总结BOA的相关特性。其中，源码分析部分涉及到Linux网络编程，漏洞挖掘部分主要关注于如何快速恢复请求结构体、了解数据包处理逻辑以及CGI如何传递数据，真实漏洞分析部分则是分析了三个典型的BOA认证前漏洞，其中两个能够导致认证前任意代码执行，一个认证前信息泄漏。

### 一、BOA简介

BOA是一个单任务的HTTPD，简单说，BOA不像常见的HTTPD，为每一个连接使用fork创建子进程进行处理，也不会提前创建一个进程池、线程池用于同时处理多个连接。它在内部采用了多路复用和请求链表来处理所有来自客户端的连接，并且仅仅针对CGI程序、自动目录生成和自动文件压缩采用fork子进程的形式进行处理。简而言之，BOA是一个轻量级的HTTP服务器，主要设计用于嵌入式系统，以高效的性能和小巧的代码体积著称，通常被应用于资源受限的设备，例如路由器、智能家居或者其他的嵌入式环境。

BOA具有如下的一些特点：

* 单线程架构：BOA采用了单线程、事件驱动的架构来处理多个HTTP请求。传统的WEB服务器会为每一个请求使用fork创建子进程进行处理，每次请求都会造成进程创建的开销。BOA的架构避免了这种操作，从而节省了系统资源。但是，只能说BOA适合嵌入式这种请求速度慢、并发少的情景。
* 资源占用低：BOA的代码体积非常小，内存和CPU的使用效率高，适用于资源受限的嵌入式设备。
* 配置简单：BOA的配置文件简单明了，容易调整和优化，可以快速进行部署。
* 快速响应：单线程事件驱动模型使得在轻负载情况下响应迅速，适用于处理少量并发连接。

BOA的源码和官方文档都可以在[Boa Webserver](http://www.boa.org/)处找到。

### 二、BOA源码分析（**TL;DR**）

本章节从源码分析BOA，主要从常规分析HTTPD源码的角度，例如信号量处理、socket从创建到复用、CGI数据传递等，帮助更好理解BOA的运行特性。该部分篇幅过长，对Linux网络编程已经较为熟悉的师傅可以跳过到2.4节BOA的请求结构体说明部分和2.5节状态机处理数据包示意图部分。

#### 2.1 信号量处理

HTTPD服务器会处理一些常见的信号量，以免HTTPD发生异常终止。在BOA中也是如此，main函数中调用函数`init_signals`，收到指定的信号时，执行预先设定的处理函数。

信号量的处理一般是如下流程：

* 创建信号量处理相关的结构体变量。
* 初始化清空信号量集合。
* 将需要关注的信号量以及对应信号量的处理函数加入到信号量集合中。
* 当HTTPD接收到相应的信号量时，执行预先设定的处理函数。

BOA源码中，对信号量的处理也是满足如上的流程。

```clike
/*
 * Name: init_signals
 * Description: Sets up signal handlers for all our friends.
 */

void init_signals(void) // 初始化信号处理函数，收到指定信号的时候，执行预定义的处理函数
{
	struct sigaction sa;

	// 不使用任何特殊标志
	sa.sa_flags = 0;

	// 初始化信号屏蔽集sa_mask
	// 将如下的几个信号量，添加到sa_mask中
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV); // 段错误
	sigaddset(&sa.sa_mask, SIGBUS); // 总线错误
	sigaddset(&sa.sa_mask, SIGTERM); // 终止信号
	sigaddset(&sa.sa_mask, SIGHUP); // 挂起信号
	sigaddset(&sa.sa_mask, SIGINT); // 中断信号
	sigaddset(&sa.sa_mask, SIGPIPE); // 管道破裂信号
	sigaddset(&sa.sa_mask, SIGCHLD); // 子进程状态变化信号
	sigaddset(&sa.sa_mask, SIGUSR1); // 用户自定义信号

	sa.sa_handler = sigsegv; // TODO 可以去研究一下信号处理，有时候在调试的时候可能会需要
	sigaction(SIGSEGV, &sa, NULL);

	sa.sa_handler = sigbus;
	sigaction(SIGBUS, &sa, NULL);

	sa.sa_handler = sigterm;
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = sighup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sigint;
	sigaction(SIGINT, &sa, NULL);

	// TODO 这个地方需要注意一下
	// 对于SIGPIPE信号，将其信号处理函数设置成SIG_IGN，防止往已经关闭的管道或者往断开的socket连接写入程序奔溃返回
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sigchld;
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = sigusr1;
	sigaction(SIGUSR1, &sa, NULL);
}
```

从细节来看，对于一些常见的信号量例如`SIGSEGV`、`SIGBUS`、`SIGINT`、`SIGUSR1`都是采取打印日志消息，然后调用函数`abort`直接终止掉自身。需要注意的信号量例如`SIGTERM`、`SIGHUP`、`SIGCHLD`、`SIGPIPE`，在下面会额外详细说明。

##### SIGTERM信号

`SIGTERM`是终止信号，该信号不同于`SIGKILL`，可以被捕获和处理，允许程序在终止前执行一些清理操作，例如释放资源、保存或关闭文件状态等等。在BOA的信号处理中，对于`SIGTERM`信号设置了函数`sigterm`，当接收到该信号时，设置全局变量`lame_duck_mode`值。该变量标志着BOA进入了停止接受新连接，但是继续处理已经接受过的连接的状态。

```clike
void sigterm(int dummy)
{
	lame_duck_mode = 1;
	// NOTE lame_duck_mode变量用于进入一种停止接受新任务但是继续完成当前任务的状态
}

void lame_duck_mode_run(int server_s2)
{
	log_error_time();
	fputs("caught SIGTERM, starting shutdown\n", stderr);
	// 从block_read_fdset集合中移除server_s描述符，表示不再监听新的连接请求
	FD_CLR(server_s, &block_read_fdset);
	// 释放掉socket
	close(server_s);
	// 进入关闭模式，停止接受新的请求，但是可能会继续处理已经开始的工作
	lame_duck_mode = 2;
}
```

##### SIGHUP信号

当挂起进程的控制终端时，`SIGHUP`信号就会被触发。对于HTTPD此类没有控制终端的后台程序，通常会利用`SIGHUP`信号来强制重新读取配置文件。

在BOA源码中，当`SIGHUP`信号被触发，设置全局变量`sighup_flag=1`。在函数`main`的`while`循环中，检测到该变量被设置，则调用函数`sighup_run`释放请求队列中的所有就绪请求，重新加载、读取配置文件。

```clike
void sighup(int dummy)
{
	sighup_flag = 1;
	// 如果捕捉到SIGHUP信号，设置该全局标志位
}

// NOTE SIGHUP信号用于通知boa需要重新加载配置文件
// TODO 可以小结一下boa中的信号量处理
void sighup_run(void)
{
	sighup_flag = 0;
	// 重新将该标志位设置成0
	// QUESTION 我没有明白，是在哪儿重新运行的
	log_error_time();
	fputs("caught SIGHUP, restarting\n", stderr);

	/* Philosophy change for 0.92: don't close and attempt reopen of logfiles,
	 * since usual permission structure prevents such reopening.
	 */

	dump_mime();
	dump_passwd();
	dump_alias();
	free_requests();

	log_error_time();
	fputs("re-reading configuration files\n", stderr);
	read_config_files();

	log_error_time();
	fputs("successful restart\n", stderr);
}
```

##### SIGCHLD信号

当进程的子进程状态发生变化，例如退出或暂停，该信号量会被触发。`SIGCHLD`信号量的作用一般是用于防止僵尸进程的产生或者使子进程的僵尸状态结束。僵尸态指的是子进程处于结束之后、但是父进程还没有读取退出状态；或者是父进程退出，子进程还没退出。

BOA的架构决定了，只有在CGI的时候才会使用`fork+exec`创建子进程，`SIGCHLD`信号也主要是对于CGI子进程。当`SIGCHLD`信号产生，设置变量`sigchld_flag=1`。在函数`main`的`while`循环中，同样会检测该变量是否被设置，如果设置则调用函数`sigchld_run`，其中调用函数`waitpid`读取子进程返回状态。

```clike
void sigchld(int dummy)
{
	sigchld_flag = 1;
}

// 清理已经终止的子进程，防止产生僵尸进程，并且记录子进程的终止信息
void sigchld_run(void)
{
	int status;
	pid_t pid;

	sigchld_flag = 0;
	
	// 调用waitpid函数等待子进程的状态变化，确实也就是cgi才会有子进程
	// NOTE 如果是在武器化的时候，也可以关注一下这个log，如果cgi中发生缓冲区溢出漏洞，也可以稍微处理清除相应的日志条目
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		if (verbose_cgi_logs) {
			log_error_time();
			fprintf(stderr, "reaping child %d: status %d\n", pid, status);
		}
	return;
}
```

##### SIGPIPE信号

当进程向一个已经关闭的管道或者已经关闭的socket写入数据时，会触发`SIGPIPE`信号。这种情况在HTTPD中是可能发生的，例如来自客户端的连接从客户端直接关闭了，或者是和CGI使用管道通信，但是CGI关闭了相应的管道。

在BOA代码中，将`SIGPIPE`信号的处理函数设置成`SIG_IGN`，也就是忽略`SIGPIPE`信号。通过忽略该信号，可以防止BOA因为意外的写入操作而奔溃终止。

```clike
sa.sa_handler = SIG_IGN;
sigaction(SIGPIPE, &sa, NULL);
```

#### 2.2 socket相关

BOA中负责创建、设置、监听socket的逻辑都在函数`main`中。`main`函数的`while`死循环，调用函数`get_request`，函数`get_request`调用`accept`接受来自客户端的连接。`accept`接受的连接存放在请求结构体的成员`request->fd`中，后续接受来自客户端的数据、发送处理完毕的数据都使用`request->fd`。

在这个部分主要关注BOA是如何对socket进行编程的，不会具体涉及其他具体的代码。

代码符合Linux网络编程的一般逻辑的，稍微需要注意的一些技术点包括：

* 设置`socket`为非阻塞
* 使用`select`设置多路复用
* 使用`setsockopt`设置较大的发送缓冲区
* 设置TCP_NODELAY禁用Nagle算法，减少数据传输延迟

以下是在函数`main`中和`socket`相关的代码片段：


1. 创建socket

```clike
	if ((server_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) // NOTE 创建socket
		die(NO_CREATE_SOCKET);
		// AF_INET：IPv4
		// SOCK_STEAM：TCP
		// IPPROTO_TCP：指定协议为TCP，这个参数一般是指定不变的
```


2. 将socket设置成非阻塞

```clike
	/* server socket is nonblocking */ // 设置为非阻塞模式
	if (fcntl(server_s, F_SETFL, NOBLOCK) == -1) // socket还是属于文件的一种，Linux的万物皆文件思想
		die(NO_FCNTL);
		// 
		// F_SETFL：
		// NOBLOCK：设置非阻塞模式
```


3. 设置端口复用

```clike
	if ((setsockopt(server_s, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt, // 设置运行端口复用
					sizeof (sock_opt))) == -1)
		die(NO_SETSOCKOPT);
```


4. 使用`bind`命名socket，将socket与socket地址绑定。

```clike
	/* internet socket */
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(server_port); // NOTE 这个地方或许可以使用hook的方式来修改端口
	// 命名socket，实际上也是绑定socket
	if (bind(server_s, (struct sockaddr *) &server_sockaddr, // 绑定端口
			 sizeof (server_sockaddr)) == -1)
		die(NO_BIND);
```


5. 使用`listen`监听socket

```clike
	// 绑定端口
	/* listen: large number just in case your kernel is nicely tweaked */
	if (listen(server_s, backlog) == -1) // 监听端口
		die(NO_LISTEN);
```


6. 使用`accept`接受来自客户端的连接请求 在函数`main`的`while`死循环中，调用函数`get_request`，在该函数中使用`accept`接受来自客户端的连接请求，并且初始化`conn`结构体，加入到就绪队列中。

```clike
	fd = accept(server_s, (struct sockaddr *) &remote_addr, 
		    &remote_addrlen);
		    
	conn = new_request(); // 初始化conn结构体
	conn->fd = fd;
```

##### 使用select实现I/O复用

在HTTPD中通常需要同时处理监听socket和连接socket，这就是I/O复用的一种应用场景：**同时监听多个文件描述符**。I/O复用虽然能够同时监听多个文件描述符，但是是阻塞的，而且如果有多个文件描述符同时就绪的话，不采取额外的措施（例如多进程、多线程）的话，只能串行依次处理。Linux中能够实现I/O复用的系统调用主要有`select`、`poll`和`epoll`。

BOA仅仅单纯使用了select来实现I/O复用。变量`block_read_fdset`可以读取的文件描述符集合，`block_write_fdset`可以写入的文件描述符集合。如下的代码位于函数`main`的`while`循环中，能够一直监控可读写的文件描述符集合。并且通过宏`FD_ISSET`判断文件描述符是否处于可读写的状态，如果满足则进行相应的读写，在如下的代码中，能够判断监听`socket：server_s`是否可读，如果可读，则调用函数`get_request`读取来自客户端的请求。

```clike
if (!request_ready) { // NOTE request_ready是用于存放已经准备好进行处理的请求，或许以后可以通过修改相关队列和结构体来实现hook
	if (select(OPEN_MAX, &block_read_fdset,
				&block_write_fdset, NULL,
			(request_block ? &req_timeout : NULL)) == -1) // 监控描述符集合，并进行处理
		if (errno == EINTR || errno == EBADF)
			continue;	/* while(1) */
		else
			die(SELECT);
	if (FD_ISSET(server_s, &block_read_fdset))
	// 检查socket是否处于可读状态
		get_request();
```

总体来说，BOA的I/O复用还是比较简单，没有采用多进程、多线程机制来对客户端连接进行并发处理，而是使用在函数`main`中通过`while`轮询，监听可读写的socket。可读的情况一般是客户端发起了新的连接和数据，可写的状态则是可以往客户端写入数据或者写入到CGI数据等等。

#### 2.3 CGI可控数据源

BOA在执行CGI时会使用`fork + exec`创建执行CGI子进程，其中，通过设置环境变量数组和通过标准输入传递请求体的方式将数据给CGI，CGI处理完毕数据之后，通过标准输出再传递到BOA以发送给客户端。

CGI所需的环境变量数组，在函数`create_common_env`中被初始化。这个函数在实际的设备中可能会根据需求添加一些额外的环境变量键值对。

```clike
void create_common_env()
{
	int index = 0;

	common_cgi_env = (char **) malloc(sizeof (char *) * COMMON_CGI_VARS); // 全局变量，cgi相关的环境变量数组common_cgi_env
	common_cgi_env[index++] = env_gen("PATH", DEFAULT_PATH);
	common_cgi_env[index++] = env_gen("SERVER_SOFTWARE", SERVER_VERSION);
	common_cgi_env[index++] = env_gen("SERVER_NAME", server_name);
	common_cgi_env[index++] = env_gen("GATEWAY_INTERFACE", CGI_VERSION);
	common_cgi_env[index++] = env_gen("SERVER_PORT", simple_itoa(server_port));

	/* NCSA and APACHE added -- not in CGI spec */
	common_cgi_env[index++] = env_gen("DOCUMENT_ROOT", document_root);

	/* NCSA added */
	common_cgi_env[index++] = env_gen("SERVER_ROOT", server_root);

	/* APACHE added */
	common_cgi_env[index++] = env_gen("SERVER_ADMIN", server_admin);
}
```

随后，在函数`create_env`中会继承全局变量`common_cgi_env`中的环境变量键值对，并且额外添加一些真正可控的环境变量键值对，例如：

* `SCRIPT_NAME`
* `QUERY_STRING`
* `PATH_INFO`
* ...

```clike
	if (req->path_info) {
		req->cgi_env[req->cgi_env_index++] =
		  env_gen("PATH_INFO", req->path_info);
		/* path_translated depends upon path_info */
		req->cgi_env[req->cgi_env_index++] =
		  env_gen("PATH_TRANSLATED", req->path_translated);
	}
	req->cgi_env[req->cgi_env_index++] =
	  env_gen("SCRIPT_NAME", req->script_name);

	if (req->query_string) {
		req->cgi_env[req->cgi_env_index++] =
		  env_gen("QUERY_STRING", req->query_string);
	}
	req->cgi_env[req->cgi_env_index++] =
	  env_gen("REMOTE_ADDR", req->remote_ip_addr);

	req->cgi_env[req->cgi_env_index++] =
	  env_gen("REMOTE_PORT", simple_itoa(req->remote_port));
```

CGI中可控的数据源大概就是如上的环境变量键值对和请求体转换而成的标准输入了。

#### 2.4 BOA的数据结构及其含义

```clike
struct request {				/* pending requests */
    // 来自客户端的连接请求，通过accept创建的socket，用于和客户端进行读写通信
	int fd;						/* client's socket fd */
	// 请求文件路径
	char *pathname;				/* pathname of requested file */
	// 请求结构体的状态，内部存在有限状态机
	int status;					/* see #defines.h */
	// 是否为简单请求，在函数process_logline中设置
	int simple;					/* simple request? */
	// 管理keeplive状态和计数
	int keepalive;				/* keepalive status */
	int kacount;				/* keepalive count */

    // 和管道相关，应该是和CGI传递数据相关
	int data_fd;				/* fd of data */
	// 和处理请求体相关的文件大小和位置
	unsigned long filesize;		/* filesize */
	unsigned long filepos;		/* position in file */
	// GET请求中会将请求文件映射到内存中，能加快读取性能
	char *data_mem;				/* mmapped/malloced char array */
	// 时间戳
	time_t time_last;			/* time of last succ. op. */
	// 请求方法
	int method;					/* M_GET, M_POST, etc. */

    // logline，请求行
	char *logline;				/* line to log file */
    // 向客户端写入的缓冲区定位
	int client_stream_pos;		/* how much have we read... */
	int pipeline_start;			/* how much have we processed */
    // 标记请求头的开始结束
	char *header_line;
	char *header_end;
	int buffer_start;
	int buffer_end;
    // http版本
	char *http_version;			/* HTTP/?.? of req */
	// 返回状态码
	int response_status;		/* R_NOT_FOUND etc. */
    // IF_MODIFIED_SINCE请求头
	char *if_modified_since;	/* If-Modified-Since */
	// REMOTE_ADDR请求头，但是不可控
	char remote_ip_addr[20];	/* after inet_ntoa */
	// REMOTE_PORT请求头，同样不可控
	int remote_port;			/* could be used for ident */
    // 客户端缓存文件的最后修改时间
	time_t last_modified;		/* Last-modified: */

	/* CGI needed vars */
    // cgi相关变量
	int cgi_status;				/* similar to status */
	// 是否为CGI请求
	int is_cgi;					/* true if CGI/NPH */
	// CGI环境变量数组
	char **cgi_env;				/* CGI environment */
	// 用于辅助遍历CGI环境变量数组
	int cgi_env_index;			/* index into array */
    // BOA会将请求体写入到一个临时文件中，CGI会使用重定向到标准输入进行处理
	int post_data_fd;			/* fd for post data tmpfile */
	// 如上的临时文件的文件名
	char *post_file_name;		/* only used processing POST */

    // 如下的几个变量都是CGI相关
	char *path_info;			/* env variable */
	char *path_translated;		/* env variable */
	char *script_name;			/* env variable */
	char *query_string;			/* env variable */
	char *content_type;			/* env variable */
	char *content_length;		/* env variable */

    // 请求结构体队列前驱和后继节点，emm，是链表结构
	struct request *next;		/* next */
	struct request *prev;		/* previous */
    // 
	char buffer[BUFFER_SIZE + 1];	/* generic I/O buffer */
	// 请求的URI
	char request_uri[MAX_HEADER_LENGTH + 1];	/* uri */
	// 从客户端接受的数据流
	char client_stream[CLIENT_STREAM_SIZE];		/* data from client - fit or be hosed */
#ifdef ACCEPT_ON
	char accept[MAX_ACCEPT_LENGTH];		/* Accept: fields */
#endif
};
```

#### 2.5 BOA的状态机

一个简单的HTTP请求格式大概如下，主要分成4个部分：

* 请求行：包括请求方法、请求URI、HTTP版本。
* 请求头：包含多个头部字段，由冒号分隔的键值对组成。
* 空行：用于分隔请求头和请求体。。
* 请求体：如果是POST请求包含请求头。

```none
POST /submit-form HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Connection: keep-alive

name=John+Doe&age=30&city=NY
```

BOA使用了有限状态机（finite state machine）来处理HTTP协议请求，笔者根据源码把状态机分成了三个部分来理解：

* 第一个部分是解析请求行和请求头。这个部分比较简单，实现的原理就是逐个字符处理HTTP请求，如果发现第一个`\r\n`，说明已经出现了请求行，后续出现`\r\n`则是每个请求头字段的键值对，如果出现`\r\n\r\n`则是说明到请求体了。
* 第二个部分是CGI部分。BOA和CGI之间的数据是通过传递环境变量数组和管道来进行数据交互的，在状态机中主要是BOA通过管道传递待处理数据到CGI的标准输入，待CGI处理完毕之后通过标准输入再到管道传递到BOA中，最后再发送到客户端。
* 第三个部分是非CGI部分。实际业务中，需要将BOA的GET/POST请求处理部分源码进行扩展，BOA源码中，仅仅是将POST请求保存到临时文件，以及，读取并返回GET请求的文件。

 ![](/attachments/2025-02-26-iot-http-boa/39eb7298-4077-4bd6-8351-7046bac7a865.png " =1492x757")

### 三、从漏洞挖掘角度看BOA

该部分对BOA架构的设备进行漏洞挖掘提出了一些建议，主要是如何快速从获取到BOA版本、提供了一些价值较高的函数可以辅助快速恢复请求结构体、根据数据包处理特性指出了大概率会根据业务二次开发（可能存在认证前漏洞）的几个重要函数，以及分析了三个较为典型的认证前漏洞。

#### 3.1 结构体恢复

在BOA的二进制程序中，可以通过搜索字符串`SERVER_SOFTWARE`或者直接搜索`boa`，定位到引用函数`create_common_env`进而快速定位到BOA版本。同时在这个函数中还可以恢复环境变量数组`common_cgi_env`。

 ![](/attachments/2025-02-26-iot-http-boa/452dd7a1-af5a-4be6-bfc7-e2e850db3970.png)

定位到BOA版本之后，就可以下载对应的源码，进而恢复二进程中的重要结构体和函数。BOA是单线程模型，在对HTTP请求进行处理的过程中，会将具体的请求转换成请求结构体`request`，并且后续的数据包请求函数都会接受该结构体指针作为传参。

恢复结构体`request`可以更好帮助我们理解相关的处理逻辑，那么如何更快、更好根据源码恢复该结构体的内容呢？一个浅显的原则就是去找到那些满足如下条件的函数，在二进制中定位到这些函数后，然后结构源码创建、恢复结构体。

* 条件1：尽可能更多使用到该结构体成员。
* 条件2：和业务代码关联不大，避免业务代码逻辑干扰恢复。
* 条件3：在源码中不大可能被大篇幅修改到。
* 条件4：有尽可能多的字符串辅助恢复。

经过筛选，挑出了如下的一些比较合适的函数。

| 函数名 | 功能 | 原则 |
|----|----|----|
| create_env | 执行CGI之前，初始化环境变量数组 | 涉及到环境变量键值对赋值，有字符串辅助 |
| complete_env | 将请求中的Header处理添加到环境变量数组 | 在处理cgi和form的时候调用，可以恢复请求中的重要Header内容，尤其是CGI传递环境变量 |
| free_request | 释放已经处理完毕的请求 | 使用到挺多结构体成员，但是基本没有字符串辅助 |
| process_logline | 处理请求行 | 请求类型、方法、版本等其他信息，有字符串辅助 |
| process_option_line | 处理请求头字段 | 请求头字段，有字符串辅助 |
| translate_uri | 将请求的URI转换成服务器文件系统路径 | 可以通过代码逻辑，恢复相关的结构体成员 |

以上四个函数，恢复结构体`request`基本上已经够用了，因为该结构体组成基本上是线性的，而且没有涉及到复杂的条件编译，基本上定位到重要的一些结构体成员后，就可以将上下相邻的成员也恢复。但是成员相对位置不绝对，可能在编译优化的时候导致偏移发生变化，还是需要根据二进制中的位置结合源码，才能完全确定。除此之外，可能开发者会对结构体中的成员进行扩展，例如某些SDK会对BOA进行了额外的开发。

实际上通过函数`complete_env`、函数`process_logline`、函数`process_option_line`，基本上可以恢复绝大部分的结构体成员，包括二次开发添加的一些成员。还有一些重要的结构体成员可以通过指定的函数恢复，例如`prev`和`next`可以通过函数`dequeue`和函数`enqueue`恢复。这两个函数用于维护结构体`request`组织成的双链结构，在请求、释放请求的时候被相应调用。

#### 3.2 数据包处理

数据包处理主要发生在函数`main`的`while`循环，调用函数`process_requests`处理接收到的请求数据。 函数`process_requests`由调用了如下的几个重要函数：

* 函数`read_header`：处理请求头
  * `process_option_line`：处理请求头中的字段，可能形成一些可控的环境变量
  * `process_logline`：处理请求行，一般不大可能会更改额外代码
  * `process_header_end`：请求头处理完毕之后继续处理数据，在这个函数中可能存在鉴权。例如reltek sdk的BOA有在这个函数中使用函数`auth_authorize`进行鉴权。
* 函数`webs*Define`：常见的二次开发的BOA版本，使用该函数注册API的回调函数进一步处理客户端的请求，其中包含了许多业务相关的代码，存在漏洞的概率较高。

### 四、真实漏洞分析

#### 4.1 案例一：vivotek认证前栈溢出

这个案例虽然没有找到具体的CVE编号，但是涉及的漏洞是个典型，漏洞发生在Vivotek多个设备型号中，是程序BOA的一个认证前缓冲区溢出漏洞，攻击效果可以达到认证前RCE。

该漏洞的典型在于，一是漏洞发生在认证前，是`strncpy`导致的，比较具有代表性；二是BOA没有符号，连函数符号都没有，只能根据关键字符串从源码对应着去恢复相关函数、相关结构体。漏洞的相关资源都在如下：

* 漏洞信息：[Vivotek IP Cameras - Remote Stack Overflow (PoC) - Multiple remote Exploit](https://www.exploit-db.com/exploits/44001)。
* 固件下载：[CC8160-VVTK-0100d.flash.zip](https://github.com/mcw0/PoC/files/3128058/CC8160-VVTK-0100d.flash.zip)

首先是先定位到版本号，然后下载源码以辅助恢复符号。通过搜索字符串：`SERVER_SOFTWARE`，可以得到版本0.94.14rc21，并从git下载[源码](https://github.com/gpg/boa)，checkout到相应的分支。

 ![](/attachments/2025-02-26-iot-http-boa/65e5a9f8-8ed4-4497-bccc-ed3311be39f6.png)

根据漏洞信息搜索字符串Content-Length定位到漏洞。经过函数恢复和请求结构体恢复之后，可以知道漏洞调用链从近到远依次是：

* `read_header`：处理请求首行、请求头字段
* `process_requests`：按照状态机，对请求进行处理
* `loop`：`main`函数中的死循环，一直监听来自客户端的连接，如果有就绪的则调用函数`process_request`处理

如下是反编译代码，参考源码，此时的数据包处理状态，应该是解析完毕了请求首行，但是还没有到该处理请求体的状态，也就是位于该处理请求头字段的时候。漏洞触发条件是：

* 判断请求方式是POST或PUT，`req->client_stream`存储的是整个数据包，指针`haystack`和`client_stream_post`用来辅助遍历该数据包。
* 然后通过`strstr`找是否包含Content-Length字段。按照正常逻辑来说，冒号和回车之间的值就是该字段的值。
* 最后将值复制到该函数栈上的变量`dest`，值的大小是回车和冒号之间的字节大小。

 ![](/attachments/2025-02-26-iot-http-boa/e18dbcb0-0325-46a3-abb7-47dee1c51fa4.png)

 ![](/attachments/2025-02-26-iot-http-boa/26a5f237-e4ed-4ba0-ba64-ecab91156b6b.png)

函数`strncpy`中，最后一个传参没有对数据长度进行校验，导致缓冲区溢出，甚至可以达到任意代码执行的效果。参数PoC：

```bash
echo -en "POST /cgi-bin/admin/upgrade.cgi HTTP/1.0\nContent-Length:AAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIXXXX\n\r\n\r\n"  | ncat -v 192.168.57.20 80
```

案例小结：漏洞发生在状态机处理请求头的时候，在函数`read_header`厂商自定义的代码中，由于对`Content-Length`请求头字段的数据没有校验，导致缓冲区溢出，进而可以达到任意命令执行的效果。

#### 4.2 案例二： CVE-2019-19822 敏感信息泄漏漏洞

CVE-2019-19822是发生在以Realtek SDK开发的路由器设备中的敏感信息泄漏漏洞，此处以设备TOTOLINK A3002RU，固件版本2.0.0为例，分析该漏洞。

* 漏洞信息：[Full Disclosure: Multiple vulnerabilities in TOTOLINK and other Realtek SDK based routers](https://seclists.org/fulldisclosure/2020/Jan/36)
* 固件下载：[A3002RU-V2.0.0-B20190227.zip](https://www.totolink.net/data/upload/20190430/32f1f1b3e063e738b5417f4fc56e254f.zip)

Realtek SDK中的BOA经过了二次开发，加入了较多的业务代码，无法通过之前说的环境变量SERVER_SOFTWARE获取到版本，但是可以通过搜索字符串boa获取到版本，然后找到源码，再根据关键的字符串，大体可以恢复出来请求结构体辅助理解反编译代码。

 ![](/attachments/2025-02-26-iot-http-boa/7f9ff849-84e0-4953-831e-4f4739f99c88.png)

漏洞的PoC是直接访问config.dat文件。这个漏洞的触发逻辑稍微复杂一点，笔者原本计划尝试通过仿真搭建环境，但是失败了，本文就直接结合源码和反编译代码进行分析。

```bash
curl http://routerip/config.dat
```

在BOA的状态机中，当处理完请求头之后，就会执行函数`process_header_end`。这个函数的主要作用是为执行cgi或GET请求做准备工作，例如转换URI、获取文件真实路径等工作。在二次开发中，经常将鉴权相关的逻辑集成到这个函数中，因此很多师傅对BOA进行漏挖的时候会直接定位到这个函数。此次分析的BOA就是这种情况。

该BOA相对源码新增了用于认证的字段`req->user`、`req->pass`、`req->auth_flag`，如果请求中的账号、密码与本地保存的账号、密码一致，则设置认证通过标志`auth_flag`。

 ![](/attachments/2025-02-26-iot-http-boa/db894098-25fc-4368-b2fe-11c3b9c6f26a.png)

如果认证未通过，会进入认证前的URI判定，指定用户认证前可以访问的资源。但是在判断的时候，能够触发的`return`是白名单的机制，只有特定的几种情形才会导致函数结束，例如：

* 大前提条件是：URI包含`.html`、`.asp`、是POST请求
* URI中包含字符串`login`、`forget.asp`、`Login`

剩余的场景则会继续执行后续的代码。

 ![](/attachments/2025-02-26-iot-http-boa/057713d2-7a3b-4edd-8419-918b56ffcdc8.png)

接下来就是根据请求方式，如果是GET请求，如果URI中不包含`.htm`、`.asp`、`.navigation.js`、`.cgi`，`cgi_type`就会是初始的`req->cgi_type`，该字段在函数`translate_uri`中被赋值，赋值是根据请求PATH的类型判断的，感兴趣的师傅可以进一步到函数`get_mime_type`中查看。在函数`translate_uri`中仅仅当PATH中包含CGI，才会被赋值，除此之外默认是值0。

 ![](/attachments/2025-02-26-iot-http-boa/032c277f-17a1-4ddf-a0ef-e94ed22cbe6f.png)

函数`init_get`负责将请求的资源读取，并返回给客户端。

案例小结：那么该认证前信息泄漏的成因就很显然了，在处理完毕请求头后，执行函数`process_header_end`时，认证失败后的可访问资源判定采用了白名单退出机制，导致可绕过，获取到配置文件。

#### 4.3 案例三：CVE-2018-20056 Dlink认证前栈溢出

漏洞CVE-2018-20056是发生在设备D-LINK DIR-605L 300M wireless cloud routing 和 DIR-619L 300M wireless cloud routing中的缓冲区溢出漏洞。漏洞成因是在程序`/bin/boa`的`formLanguageChange`接口存在`sprintf`导致缓冲区溢出漏洞，攻击者可以通过参数`currTime`构造数据包，可以导致任意代码执行。

* 漏洞信息：[CVE - CVE-2018-20056](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20056)
* 固件下载：[DIR-619L_REVB_FIRMWARE_PATCH_2.06.B01_WW.ZIP](https://support.dlink.com/resource/products/DIR-619L/REVB/DIR-619L_REVB_FIRMWARE_PATCH_2.06.B01_WW.ZIP)

这个BOA也是典型的二次开发的BOA，使用了函数`wabAspInit`用来解析、处理Form表单逻辑和ASP请求。如下通过函数`websFormDefine`来定义form接口和处理用到的回调函数；通过函数`websAspDefine`来定义asp接口和处理用到的回调函数。

 ![](/attachments/2025-02-26-iot-http-boa/a84b5bfd-39a4-4167-8ab5-855c95a576ba.png)

在函数`websFormDefine`中，维持一个全局的链表用于保存API和API对应的回调函数。如下，每次调用该函数，都会在全局链表`root_form`中插入一个新的节点，节点中有三个字段分别是：API、API对应的回调函数、指向的下一个节点。插入节点采用的是尾插法。

 ![](/attachments/2025-02-26-iot-http-boa/6c2d67a6-d6f3-499a-a0f1-f83de6d50729.png)

注册的回调函数会在函数`form_handler`中被调用，该函数又被函数`init_form`<-函数`write_body`调用。在BOA的源码中，函数`write_body`的调用时机是向客户端写入BODY内容的时候。也就是说，该程序BOA是在向客户端写入BODY内容的时候，根据请求时的API，执行相应的回调函数，并且将回调函数的结果也写入到BODY中。

 ![](/attachments/2025-02-26-iot-http-boa/c3b7bce7-97c6-4dc5-8049-809f5c7096d3.png)

对此类自定义BOA开展漏洞挖掘，如果是找认证后漏洞则是直接去审计这个函数里面注册的回调函数，并查看其中的数据源是否可控、是否可导致漏洞。如果是找认证前漏洞则是去分析鉴权逻辑，通常来说，鉴权逻辑发生在函数`process_header_end`中。该函数发生在状态机处理数据包时，已经处理完请求行和请求头的阶段。

继续回到漏洞，接口`formLanguageChange`对应的回调函数`formLanguageChang`中，通过函数`websGetVa`r获取到用户提交的参数，然后使用函数`sprintf`拼接，拼接的过程中没有对参数长度进行检查，导致栈上的缓冲区溢出。

那么接下来就是分析，该接口为什么可以认证前被触发，触发PoC如下：

```bash
curl -X POST "http://<ip>/goform/formLanguageChange" \
     --data "currTime=<payload>"          
```

该BOA包含了函数符号，因此可以直接定位到函数`process_header_end`中的鉴权处理逻辑。在该函数中一共包含三次路径判定，在第三次会判定失败，进入正常的POST请求处理，在向客户端写入BODY结果的时候调用到form回调函数，进而触发漏洞。漏洞分析如下：

1\. `req_uri_type=0`恒成立，因为POC的URI中不包含如下的字符串：

 ![](/attachments/2025-02-26-iot-http-boa/fbd3a53e-99ec-440c-91a2-4631b36f14bb.png)


2. 进入第二次关键if判定和第三次关键if判断。其中第二次关键if判定会通过，和变量`is_initialized`无关。第三次关键if判定会不通过，在与逻辑判定处URL中包含字符串`formLanguageChange`。随后，程序进入正常的处理POST请求的逻辑。

 ![](/attachments/2025-02-26-iot-http-boa/fcfcabc2-11f7-4ab4-9361-d560674ad245.png)


3. 进入正常的POST请求处理逻辑，随后会进入到BODY_WRITE状态（向客户端写入BODY结果）调用函数`write_body`->函数`init_form`，再执行到`formLanguageChange`的回调函数，导致漏洞触发。

 ![](/attachments/2025-02-26-iot-http-boa/658996db-6e4e-473e-a757-5f1aa40638d1.png)

案例小结：处理完毕请求头之后，执行函数`process_header_end`，由于接口`formLanguageChange`对应的回调函数存在漏洞，且可以认证前访问，导致漏洞触发。漏洞触发的时机是在向客户端写入BODY结果。

### 五、总结

BOA是IoT小设备中常见的HTTPD，从状态机理解数据包处理流程、分析请求数据结构能够帮助安全研究人员快速理解业务逻辑，进而定位到可能发生漏洞的地方。本文的主要贡献是从源码小结了BOA的状态机，结合经验和源码提出了快速恢复BOA请求结构体的方法，以及结合三个典型的BOA认证前漏洞，提供了对BOA进行漏洞挖掘的一般方法，文中给出了案例的固件下载链接，感兴趣的师傅可以尝试交流。