---
slug: tiangongarticle036
date: 2024-06-26
title: Apple 操作系统 - XNU 内核下 FlowDivert 网络协议漏洞分析
author: fmyy
tags: [macOS, FlowDivert]
---

# Apple 操作系统 - XNU 内核下 FlowDivert 网络协议漏洞分析

## 一、前言

Flow Divert 协议在 macOS 中提供了强大的流量管理和重定向功能，广泛应用于 VPN 和其他高级网络控制场景。通过内核扩展和用户态守护进程的协同工作，Flow Divert 允许系统和应用程序动态管理网络流量，增强安全性、隐私保护和网络性能。本文旨在分析FlowDivert模块内出现的历史的漏洞以及引入的新代码所引发的漏洞存在。

<!-- truncate -->

## 二、XNU中网络API函数的调用路径

首先此处拿`connect`函数来进行简单分析下调用路径，后续会有用到其中一些内容。

```cpp
int connect(proc_ref_t p, struct connect_args *uap, int32_ref_t retval)
{
    __pthread_testcancel(1);
    return connect_nocancel(p, (struct  connect_nocancel_args *)uap,
            retval);
}
```

当我们在用户态调用`connect`函数的时候，系统则会在库里面调用对应的系统调用并进入内核中在内核中，它对应函数的名字依旧是`connect()`作为函数名，其中三个参数分别是当前进程结构体的引用，以及此处的uap指针则是用户态传给内核态的相关参数，最后则是一个返回值的指针。

```cpp
int connect_nocancel(proc_t p, struct connect_nocancel_args *uap, int32_ref_t retval)
{
#pragma unused(p, retval)
    socket_ref_t so;
    struct sockaddr_storage ss;
    sockaddr_ref_t  sa = NULL;
    int error;
    int fd = uap->s;
    boolean_t dgram;

    AUDIT_ARG(fd, uap->s);
    error = file_socket(fd, &so);
    if (error != 0) {
        return error;
    }
....
    error = connectit(so, sa);
....
 out:
    file_drop(fd);
    return error;
}
```

进一步进入函数`connect_nocancel`里面，其中会对uap结构体中的内容进行检测，之后则是从uap里面获取所需的一些参数或者结构体。

首先是通过`file_socket`函数，从当前进程中获取对应`fd`值所对应在内核中的套接字结构体指针，之后再获取相关对象数据，并进入`connectit`函数。

```cpp
static int connectit(struct socket *so, sockaddr_ref_t sa)
{
    int error;
...
    socket_lock(so, 1);
    if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
        error = EALREADY;
        goto out;
    }
    error = soconnectlock(so, sa, 0);
    ...
    if (error == 0) {
        error = so->so_error;
        so->so_error = 0;
    }
out:
    socket_unlock(so, 1);
    return error;
}
```

由于之前已经获取到了对应的`socket`结构体指针，所以在一进入`connectit`函数后，则会对当前`socket`加上一个全局的锁，通过`socket_lock`的调用施加一个锁，然后调用`soconnectlock`函数，返回后并根据设置判断是否是阻塞还是非阻塞的套接字，最终完成后则解锁返回。

```cpp
int soconnectlock(struct socket *so, struct sockaddr *nam, int dolock)
{
    int error;
    struct proc *p = current_proc();
    tracker_metadata_t metadata = { };

    if (dolock) {
        socket_lock(so, 1);
    }

......
        if (error != 0) {
            ...
        } else {
            error = (*so->so_proto->pr_usrreqs->pru_connect)
                (so, nam, p);
            if (error != 0) {
                so->so_state &= ~SS_ISCONNECTING;
            }
        }
    }
    if (dolock) {
        socket_unlock(so, 1);
    }
    return error;
}
```

在进入`soconnectlock`函数后，可以很快发现存在一个函数指针的调用 **(\*so->so_proto->pr_usrreqs->pru_connect)** ;对应的指针则是从当前套接字结构体中所获取的。

```cpp
struct pr_usrreqs tcp_usrreqs = {
    .pru_abort =            tcp_usr_abort,
    .pru_accept =           tcp_usr_accept,
    .pru_attach =           tcp_usr_attach,
    .pru_bind =             tcp_usr_bind,
    .pru_connect =          tcp_usr_connect,
    .pru_connectx =         tcp_usr_connectx,
    ...
};
```

下面拿TCP协议来举例，在内核中，会定义一个名为`tcp_usrreqs`的结构体，其中保存了很多的协议实现的接口函数指针，包括前面所提到的`pru_connect`函数指针亦是存在，对应的则是`tcp_usr_connect`函数。

```cpp
static struct protosw inetsw[] = {
    {
        .pr_type =              SOCK_STREAM,
        .pr_protocol =          IPPROTO_TCP,
        .pr_flags =             PR_CONNREQUIRED | PR_WANTRCVD | PR_PCBLOCK |
            PR_PROTOLOCK | PR_DISPOSE | PR_EVCONNINFO |
            PR_PRECONN_WRITE | PR_DATA_IDEMPOTENT,
        .pr_input =             tcp_input,
        .pr_ctlinput =          tcp_ctlinput,
        .pr_ctloutput =         tcp_ctloutput,
        .pr_init =              tcp_init,
        .pr_drain =             tcp_drain,
        .pr_usrreqs =           &tcp_usrreqs,
        .pr_lock =              tcp_lock,
        .pr_unlock =            tcp_unlock,
        ...
    }
    ...
}
```

之后则是将`tcp_usrreqs`结构体指针保存在一个名为`static struct protosw inetsw[]`的结构体中。此处又保存了相关的初始化或者报文处理函数，以及一些配置函数，例如`setsockopt`函数进入后对TCP部分的配置实现则是在`tcp_ctloutput`中。

简单的路径跟踪之后，可以发现，在进入到具体对应的协议实现之前，则会有各种相关的检测，且在进入对应协议的接口之前，就已经调用socket_lock函数对当前的套接字进行加锁处理。

## 三、漏洞案例分析

### 漏洞一：标志位缺失与条件竞争

该漏洞是位于控制块在初始化阶段发生的，在初始化的时候，会通过相关函数对应当前套接字生成一个对应的FlowDivert协议下的控制块结构对象，并保存到相关的group组里面与当前的套接字对象上。

 ![](/attachments/2024-06-26-macos-xnuflowdivert/6bea7a0f-6876-4424-ac50-76a80672787d.png)

根据上述代码的更新情况可以总结出以下变化：

1. 函数进入之后，会根据传入的两个参数计算出一个group_unit；
2. 在insert之前保存参数和标志位，当函数触发error错误返回的时候，则会在分支置空 **so_fd_pcb** 和 **SOF_FLOW_DIVERT**标志位。

**变化 1**

 ![](/attachments/2024-06-26-macos-xnuflowdivert/16dc24c7-7fa7-4f6d-abf1-aa964b81fefc.png)

**flow_divert_derive_kernel_control_unit**是根据传入的参数来计算一个在`GROUP_COUNT_MAX(32)`范围内的值，并返回。

返回的结果是作为`group_unit`变量，同步存放在套接字结构体中`control_group_unit`变量中，而后续则是通过`group_unit`的值来指明具体的group用于存放当前创建的控制块结构体指针**fd_cb**。

但是对漏洞缓解来看并无太大作用，可以确定不是导致漏洞产生的原因，只是在代码更新阶段同步引入了另外的功能。

**变化 2**

而在原代码中可以很轻易的发现存在如下代码：

```c
if (so->so_flags & SOF_FLOW_DIVERT) {
    return EALREADY;
}
```

此处的代码则是用于检测当进入该函数的时候，是否已经存在`SOF_FLOW_DIVERT`标志位，如若存在则会直接返回EALREADY错误值。

而在insert之前会对套接字设置`SOF_FLOW_DIVERT`标志位，在insert触发error之后则会清空`SOF_FLOW_DIVERT`标志位，由此可以猜测此处存在一个条件竞争的漏洞，而`SOF_FLOW_DIVERT`的处理则会用于限制另一个线程在同时间进入到此函数造成竞争漏洞的出现。

```c
static errno_t 
flow_divert_pcb_insert(struct flow_divert_pcb *fd_cb, uint32_t ctl_unit)
{
    errno_t                      error                         = 0;
    struct                       flow_divert_pcb *exist        = NULL;
    struct                       flow_divert_group             *group;
    static uint32_t              g_nextkey                     = 1;
    static uint32_t              g_hash_seed                   = 0;
    int                          try_count                     = 0;

    if (ctl_unit == 0 || ctl_unit >= GROUP_COUNT_MAX) {
        return EINVAL;
    }
    socket_unlock(fd_cb->so, 0);
    ...

    socket_lock(fd_cb->so, 0);
    ...
}
```

在进入分析之前，我们对相关函数进行了简单的跟踪，当时提到过一点，则是在进入对应接口具体实现之前，则已经会对当前套接字进行了一个加锁的处理，其中使用了`socket_lock`函数。

但是在`flow_divert_pcb_insert`函数中，可以发现，使用了`socket_unlock`函数进行暂时性的解锁，之后虽然又将锁加了回去，但是正因为此处的暂时性解锁，假如此时存在另一个线程请求加锁，则会处于阻塞状态，等待锁的释放，那么此处的暂时性解锁则会导致锁一释放的瞬间，另一个请求加锁的通行，则另一个线程则会进入下一步执行，而轮到`flow_divert_pcb_insert`函数会到`socket_lock`函数请求加锁而进入阻塞状态。

```c
static struct flow_divert_pcb * 
flow_divert_pcb_create(socket_t so)
{
    struct flow_divert_pcb  *new_pcb        = NULL;

    MALLOC_ZONE(new_pcb, struct flow_divert_pcb *, sizeof(*new_pcb), M_FLOW_DIVERT_PCB, M_WAITOK);
    if (new_pcb == NULL) {
        FDLOG0(LOG_ERR, &nil_pcb, "failed to allocate a pcb");
        return NULL;
    }

    memset(new_pcb, 0, sizeof(*new_pcb));
    lck_mtx_init(&new_pcb->mtx, flow_divert_mtx_grp, flow_divert_mtx_attr);
    new_pcb->so = so;
    new_pcb->log_level = nil_pcb.log_level;
    FDRETAIN(new_pcb);      /* Represents the socket's reference */
    return new_pcb;
}
```

再来看看`flow_divert_pcb_create`函数是如何创建`fd_cb`结构体的，首先会根据结构体分配对应的空间，申请成功后，则会将当前的socket指针存放于存放于新的控制块结构体中，最后返回之前，别忘记给新申请的控制块指针添加一次引用计数。

因此如若两个线程同时进入`flow_divert_pcb_init_internal`函数，则会导致分别创建一次新的控制块指针，并指向同一个套接字指针。

因此修复方案则是在`insert`函数之前就已经添加`SOF_FLOW_DIVERT`标志位检测，当第二个线程进入`flow_divert_pcb_init_internal`之后，虽然第一个线程进入了`insert`函数，但是第二个线程检测到此标志位就会直接返回了，根本到不了`flow_divert_pcb_create`函数。

### 漏洞二： CVE-2022-26757

在案例一的漏洞中，分析的root cause明确的可以说是`flow_divert_pcb_insert`中由于暂时性解锁和标志位缺失设置共同导致的条件竞争问题，而官方在修复过程中，只是通过设置标志位修复了两个线程同时进入该函数导致漏洞的一种情形。

CVE-2022-26757则是在漏洞一修复之后所产生的漏洞，主要是官方对漏洞产生的场景没有完全的缓解导致依旧可以通过另一条路径进行条件竞争。

 ![](/attachments/2024-06-26-macos-xnuflowdivert/abfe947d-28f4-46ba-aa77-e322c2855db7.png)

在之前跟踪函数调用的过程中，描述过在不同的协议中，内核会有不同的用于存放接口函数实现的结构体，而对于`FlowDivert`函数同样存在类似的结构体，但是此处是从`g_tcp_protosw`拷贝而来，即TCP4对应的相关内容直接拷贝过来的，但是在拷贝后，将其中比较常见的一些函数替换为了FlowDivert协议下独有的接口函数。

```cpp
static int flow_divert_close(struct socket *so)
{
    struct flow_divert_pcb  *fd_cb          = so->so_fd_pcb;
    if (!SO_IS_DIVERTED(so)) {
        return EINVAL;
    }
    
    if (SOCK_TYPE(so) == SOCK_STREAM) {
        soisdisconnecting(so);
        sbflush(&so->so_rcv);
    }
    flow_divert_send_buffered_data(fd_cb, TRUE);
    flow_divert_update_closed_state(fd_cb, SHUT_RDWR, false, true);
    flow_divert_send_close_if_needed(fd_cb);

    /* Remove from the group */
    flow_divert_pcb_remove(fd_cb);

    return 0;
}
```

在其中，可以发现存在函数`flow_divert_close`，保存在`pru_disconnect`对应的指针处，而在此函数中，会首先通过宏定义`SO_IS_DIVERTED`判断是否存在`SOF_FLOW_DIVERT`标志位，若存在则会将`fd_cb`指针从对应的group中删除，添加进group使用的是`flow_divert_pcb_insert`函数，而从group中移除此处使用的是`flow_divert_pcb_remove`函数。

当尝试调用`shutdown`或者`disconnectx`函数时，则会调用到`flow_divert_close`函数。

```c
void flow_divert_detach(struct socket *so)
{
    struct flow_divert_pcb  *fd_cb          = so->so_fd_pcb;
    if (!SO_IS_DIVERTED(so)) {
        return;
    }

...
    FDRELEASE(fd_cb);       /* Release the socket's reference */
}
void
sofreelastref(struct socket *so, int dealloc)
{
#if FLOW_DIVERT
    if (so->so_flags & SOF_FLOW_DIVERT) {
        flow_divert_detach(so);
    }
#endif  /* FLOW_DIVERT */
...
}
```

而在FlowDivert协议代码中，另外有一个函数`flow_divert_detach`，它通常是在`close(socket)`过程中进行的调用，相对于`flow_divert_pcb_close()`函数，此函数则会多出一个`FDRELEASE`引用计数释放的宏定义操作。往上根据函数引用可以发现，当进入`sofreelastref`函数后，若套接字存在`SOF_FLOW_DIVERT`标志位，则会进入`flow_divert_detach`函数。

但是如果是TCP协议的话，能调用到`flow_divert_detach()`方式则可以存在如下路径：

```c
tcp_usr_disconnect -> tcp_disconnect -> 
tcp_close -> sofreelastref -> flow_divert_detach
```

而上述路径，则可以不通过`close(socket)`即可触发，通过`disconnectx(socket,0,0)`则可以执行此路径，但是此路径只是理想状态下，具体如何才能执行到这条路径，下面继续分析。

在漏洞0中，官方在新添加的代码中，调用`flow_divert_pcb_insert`函数之前，已经对相关的参数进行保存到了socket结构体中，尤其是`SOF_FLOW_DIVERT`的标志位的保存以及`so_fd_pcb`指针的保存。

```c
static errno_t
flow_divert_pcb_init_internal(struct socket *so, uint32_t ctl_unit, uint32_t aggregate_unit)
{
    ....
    so->so_fd_pcb = fd_cb;
    so->so_flags |= SOF_FLOW_DIVERT;
    fd_cb->control_group_unit = group_unit;
    fd_cb->policy_control_unit = ctl_unit;
    fd_cb->aggregate_unit = agg_unit;
    error = flow_divert_pcb_insert(fd_cb, group_unit);
    if (error) {
        FDLOG(LOG_ERR, fd_cb, "pcb insert failed: %d", error);
        so->so_fd_pcb = NULL;
        so->so_flags &= ~SOF_FLOW_DIVERT;
        FDRELEASE(fd_cb);
    }
    ......
    if (SOCK_TYPE(so) == SOCK_STREAM) {
        flow_divert_set_protosw(so);
    ...
}
```

若通过创建一个TCP套接字进入`flow_divert_pcb_init_internal`函数，而只有在insert成功之后，才会使用`flow_divert_set_protosw`函数通过`g_flow_divert_in_protosw`指针覆盖原套接字的`so_proto`指针。

那么，若是能够在`so_proto`指针被覆盖之前，调用到`tcp_close`函数，最终则会执行到`flow_divert_detach`函数。

```c
static void flow_divert_set_protosw(struct socket *so)
{
    if (SOCK_DOM(so) == PF_INET) {
        so->so_proto = &g_flow_divert_in_protosw;
    } else {
        so->so_proto = (struct protosw *)&g_flow_divert_in6_protosw;
    }
}
```

1. 首先线程1当发生暂时性解锁的时候，会发生在`flow_divert_pcb_insert`函数中，

   1. socket套接字具有`SOF_FLOW_DIVERT`标志位；
   2. `so->so_proto`未曾覆盖，依旧使用的原TCP协议对应的接口函数；
   3. 新创建的控制块对象已经保存于socket结构体中。

2. 线程2可以通过调用`disconnectx(socket,0,0)`

   1. 由于采用的TCP协议接口函数，则会进入`tcp_close`函数，最终进入`sofreelastref`函数；
   2. 线程满足SOF_FLOW_DIVERT标志位的条件，进入`flow_divert_detach`函数，且`so→so_fd_pcb`指针存在，会对`so_fd_pcb`指针进行引用计数释放操作。

3. 线程1在`flow_divert_pcb_insert`返回失败的时候，再一次调用`FDRELEASE(fd_cb)`，对`fd_cb`进行引用计数释放操作。

环环相扣，在线程1中`fd_cb`创建的时候，会默认引用计数增加一次，但是线程2在进入`flow_divert_detach`函数中，引用计数又会被释放，因此线程2中取出`fd_cb`对象，并对其进行释放回收处理，而线程1在`flow_divert_pcb_insert`函数返回失败的情况下，再次调用`FDRELEASE`释放`fd_cb`对象，而两者是从同一个套接字取出的`fd_cb`对象，对已经释放的对象进行操作，因此存在条件竞争导致的UAF的漏洞。

### 漏洞三：CVE-2024-23208

该漏洞是在新引入的功能分支代码中由于代码书写不规范而导致的，而在新引入的代码中，对于同一个进程，可以通过KernControl协议访问对应服务，并在当前进程的情况下，生成多个group组，对控制块进行管理。

 ![](/attachments/2024-06-26-macos-xnuflowdivert/2bffccd1-324e-4947-a1f1-750fa188e9db.png)

 ![](/attachments/2024-06-26-macos-xnuflowdivert/63514000-2f03-4322-b487-a168769d0f57.png)

 ![](/attachments/2024-06-26-macos-xnuflowdivert/689b5b3f-e164-4f94-b6e6-83014d891287.png)

在更新的macOS14 Sonoma系统后，XNU对于FlowDivert协议加入了新的功能实现，通过KernControl协议即可到达对应功能，另外实现了一条分支，可以注册的管理控制块的group数量可以达到到 (2^32 - 0x10000)数量级，用`g_flow_divert_in_process_group_list`链表进行管理，但是XNU这部分代码应该是不完善，仅仅能保存到用`g_flow_divert_in_process_group_list`链表管理的group中，而在使用的时候，依旧被限制在以前 `GROUP_COUNT_MAX(32)`的数量级中，大多只能访问 `ID == (1 ~ 32)`的group。

```cpp
static struct flow_divert_group *
flow_divert_group_lookup(uint32_t ctl_unit, struct flow_divert_pcb *fd_cb)
{
    struct flow_divert_group *group = NULL;
    lck_rw_lock_shared(&g_flow_divert_group_lck);
    if (g_active_group_count == 0) {
        ...
    } else if (ctl_unit == 0 || (ctl_unit >= GROUP_COUNT_MAX && ctl_unit < FLOW_DIVERT_IN_PROCESS_UNIT_MIN)) {
        ...
    } else if (ctl_unit < FLOW_DIVERT_IN_PROCESS_UNIT_MIN) {
        ...
    } else {
        if (TAILQ_EMPTY(&g_flow_divert_in_process_group_list)) {
            if (fd_cb != NULL) {
                ...
            }
        } else {
            struct flow_divert_group *group_cursor = NULL;
            TAILQ_FOREACH(group_cursor, &g_flow_divert_in_process_group_list, chain) {
                if (group_cursor->ctl_unit == ctl_unit) {
                    group = group_cursor; [1]
                    break;
                }
            }
            if (group == NULL) {
                ...
            } else if (fd_cb != NULL &&
                (fd_cb->so == NULL ||
                group_cursor->in_process_pid != fd_cb->so->last_pid)) { [2]
                FDLOG(...);
            } else { [3]
                FDGRP_RETAIN(group); 
            }
        }
    }
    lck_rw_done(&g_flow_divert_group_lck);
    return group; [4]
}
```

在新添加的代码中，有一段代码是用于新添加的group管理链表所对应的分支，在根据用户传入的`ctl_unit`变量用于查询对应符合条件的group对象时。

如果用户请求到达后，所传入的`ctl_unit`变量的值大于 `FLOW_DIVERT_IN_PROCESS_UNIT_MIN(0xFFFF)`，则会来到下面的分支，根据给定的`ctl_unit`数值，在双向链表中进行遍历匹配。

符合`group_cursor->ctl_unit == ctl_unit`情况下则会将指针`group_cursor` **交给指针group** 保存。

```cpp
...
            if (group == NULL) {
                ...
            } else if (fd_cb != NULL &&
                (fd_cb->so == NULL ||
                group_cursor->in_process_pid != fd_cb->so->last_pid)) { [2]
                FDLOG(...);
            } else { [3]
                FDGRP_RETAIN(group);
            }
...
return group; [4]
```

判断的时候，其实是分为`group == NULL`或者`group ≠ NULL`两种情况

1. 如果`group == NULL`，则会直接跳出循环，返回的group为NULL；
2. 如果`group ≠ NULL`，则会从分支\[2\]和\[3\]再次进行选择，而正常符合情况的分支应该是从\[3\]走，对group指针附加引用计数，并最终返回一个带有引用计数的group指针；
3. 如果`group ≠ NULL`，同时满足分支\[2\]的条件，则会通过`FDLOG`函数打印一段日志，并直接跳出循环，但是没有对残留指针group进行处理，导致group返回的时候\[4\]返回的为不带有引用计数的group指针。

而能用户可控的分支则是满足如下条件即可：

```c
group_cursor->in_process_pid != fd_cb->so->last_pid
```

内核会从当前所对应的`fd_cb`控制块指针保存的套接字获取对应的最近一次使用该套接字的进程的`PID`值。

```cpp
void so_update_last_owner_locked(struct socket *so, proc_t self)
{
    if (so->last_pid != 0) {
        /*
        * last_pid and last_upid should remain zero for sockets
        * created using sock_socket. The check above achieves that
        */
        if (self == PROC_NULL) {
            self = current_proc();
        }

        if (so->last_upid != proc_uniqueid(self) ||
            so->last_pid != proc_pid(self)) {
                so->last_upid = proc_uniqueid(self);
                so->last_pid = proc_pid(self);
                proc_getexecutableuuid(self, so->last_uuid,
                    sizeof(so->last_uuid));
                if (so->so_proto != NULL && so->so_proto->pr_update_last_owner != NULL) {
                        (*so->so_proto->pr_update_last_owner)(so, self, NULL);
            }
        }
        proc_pidoriginatoruuid(so->so_vuuid, sizeof(so->so_vuuid));
    }
}
```

函数`so_update_last_owner_locked`可以用来更新当前套接字对应的pid，很容易就能发现若是当前进程的pid与套接字所对应的套接字是不匹配的，就会更新为当前进程的pid保存到套接字结构体中。

```cpp
int solisten(struct socket *so, int backlog)
{
    struct proc *p = current_proc();
    int error = 0;

    socket_lock(so, 1);

    so_update_last_owner_locked(so, p);
    so_update_policy(so);
...
}
```

最终可以发现可以很多网络协议所用的接口函数，例如`accept`、`connect`、`bind`、`listen`等函数都会在还没有进入具体的对应协议的API接口函数之前，就已经有此函数的调用。

macOS上通过`fork`进程即可传递让子进程继承使用父进程创建的套接字，所以`fork`函数创建子进程后，在子进程中调用`listen`函数，传入父进程创建的`fd`即可。

iOS上触发，则可以通过共享文件，通过两个App绑定到共同可访问的文件，使用`SCM_RIGHTS`方法将套接字发送给另一个App，因为iOS中每个App都是以单进程出现，所以发送到另一个App，即可在另一个App上更新套接字中的进程ID。

### 漏洞四：套接字锁的引用计数与条件竞争

在第三个漏洞案例中，通过KernControl协议能到达对应FlowDivert协议中管理group相关的功能。而新引入的代码中，主要是用于在生成控制块的过程中，在对于group组进行查询的时候所导致的，那么，FlowDivert对于group组服务的相关控制流程，则是会有对应的接口进行管理，下面的漏洞则是在针对group组管理的接口中所出现的。

```c
#define CTL_SIZE sizeof(struct sockaddr_ctl)
#define CTL_INFOSZ sizeof(struct ctl_info)
#define CONTROL_NAME "com.apple.flow-divert"
int sock_kctl[32];
void connect_kctl(int index, int sc_unit) {
    sock_kctl[index] = socket(AF_SYSTEM,SOCK_DGRAM,SYSPROTO_CONTROL);
    if(sock_kctl[index] < 0) {
        perror("[connect_kctl:socket]");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_ctl target;
    target.sc_len     = CTL_SIZE;
    target.sc_family  = AF_SYSTEM;
    target.ss_sysaddr = AF_SYS_CONTROL;
    
    struct ctl_info info;
    memset(&info,0,CTL_INFOSZ);
    strlcpy(info.ctl_name,CONTROL_NAME,sizeof(info.ctl_name));
    if(ioctl(sock_kctl[index],CTLIOCGINFO,&info) == -1) {
        perror("[ioctl]");
        exit(EXIT_FAILURE);
    }
    target.sc_id      = info.ctl_id;
    target.sc_unit    = sc_unit;
    //printf("SC_UNIT: \t%d\n",target.sc_unit);
    if (connect(sock_kctl[index], (struct sockaddr *)&target, CTL_SIZE) == -1) {
        perror("[connect_kctl:connect]");
        exit(EXIT_FAILURE);
    }
}
```

Kern Control（内核控制）是 macOS 操作系统中的一种通信机制，用于在内核和用户空间之间传递控制和数据信息。它提供了一种可扩展的方式，允许用户空间程序与内核进行交互和通信，以实现自定义的网络协议、网络服务或其他内核功能的扩展。

通过KernControl协议，指定连接对象参数，首先通过`ioctl`根据传入的name进行查询对应服务的ID，然后获取ID之后，即可通过`connect`函数直接连接上对应的FlowDivert服务。

```c
static int flow_divert_kctl_init(void)
{
    struct kern_ctl_reg     ctl_reg;
    int                     result;
    memset(&ctl_reg, 0, sizeof(ctl_reg));
    strlcpy(ctl_reg.ctl_name, FLOW_DIVERT_CONTROL_NAME, sizeof(ctl_reg.ctl_name));
    ctl_reg.ctl_name[sizeof(ctl_reg.ctl_name) - 1] = '\0';
    ctl_reg.ctl_flags = CTL_FLAG_REG_EXTENDED | CTL_FLAG_REG_SETUP;
    ctl_reg.ctl_sendsize = FD_CTL_SENDBUFF_SIZE;
    ctl_reg.ctl_connect = flow_divert_kctl_connect;
    ctl_reg.ctl_disconnect = flow_divert_kctl_disconnect;
    ctl_reg.ctl_send = flow_divert_kctl_send;
    ctl_reg.ctl_rcvd = flow_divert_kctl_rcvd;
    ctl_reg.ctl_setup = flow_divert_kctl_setup;

    result = ctl_register(&ctl_reg, &g_flow_divert_kctl_ref);
...
}
```

在FlowDivert模块内，根据服务名，交叉引用即可发现如上代码，设置了FlowDivert服务对应的KernControl协议下的相关网络协议API接口函数，`flow_divert_kctl_setup`函数则是之前所提到的Apple新添加功能的主要内容之一，扩大了可供管理控制块的group数量级。

每一个连接到`FlowDivert`服务的客户端，则可以对应在内核中生成一个group对象，而其中用于指明group位置的则是通过connect过程中所传入的`sc_unit`变量作为特征，在之后查询的时候，会与查询时传入的参数进行匹配，匹配成功则会返回对应的group对象。

```c
static errno_t
flow_divert_kctl_send(__unused kern_ctl_ref kctlref, uint32_t unit, __unused void *unitinfo, mbuf_t m, __unused int flags)
{
    errno_t error = 0;
    struct flow_divert_group *group = flow_divert_group_lookup(unit, NULL);
    // 此处unit对应之前所传入的sc_unit值，会由系统保存管理到对应结构体上
    if (group != NULL) {
        error = flow_divert_input(m, group);
        FDGRP_RELEASE(group);
    } else {
        error = ENOENT;
    }
    return error;
}
```

当然，在通过`send`函数可以发送自定义字段的数据报文，在`flow_divert_input`函数中进行解析。

当所传入的数据包类型为`FLOW_DIVERT_PKT_CONNECT_RESULT`时，则会进入`flow_divert_handle_connect_result`函数。

 ![](/attachments/2024-06-26-macos-xnuflowdivert/3cf6dac2-1221-4253-afdf-b64293d0f7b8.png)

在XNU的某版本更新中，可以发现此函数是由`socket_lock(so, 0)`变更为`socket_lock(so, 1)`；而此处的套接字指针so又是从当前group中保存的其中一个`fd_cb`结构体中获取的，也是首次获取，因此此处属于第一次对该套接字加锁。

```c
void socket_lock(struct socket *so, int refcount)
{
    void *lr_saved;
    lr_saved = __builtin_return_address(0);

    if (so->so_proto->pr_lock) {
        (*so->so_proto->pr_lock)(so, refcount, lr_saved);
    } else {
#ifdef MORE_LOCKING_DEBUG
        LCK_MTX_ASSERT(so->so_proto->pr_domain->dom_mtx,
            LCK_MTX_ASSERT_NOTOWNED);
#endif
        lck_mtx_lock(so->so_proto->pr_domain->dom_mtx);
        if (refcount) {
            so->so_usecount++;
        }
        so->lock_lr[so->next_lock_lr] = lr_saved;
        so->next_lock_lr = (so->next_lock_lr + 1) % SO_LCKDBG_MAX;
    }
}
```

在之前的代码中，所提到两点：

1. FlowDivert协议控制块对应的套接字，是从原协议所对应的相关协议接口中拷贝过来，替换其中部分实现函数后成为对应于FlowDivert的函数表；
2. 某个具体的协议会有功能函数，不论是面向用户态还是内核所使用的函数，会存放相关结构在

   **\<struct protosw inetsw\[\]\>** 结构体中。

那么此处的`socket_lock()`函数的调用，若当前控制块对应的是TCP协议转换过来的，则会调用`tcp_lock()`

```c
int tcp_lock(struct socket *so, int refcount, void *lr)
{
    void *lr_saved;
    if (lr == NULL) {
        lr_saved = __builtin_return_address(0);
    } else {
        lr_saved = lr;
    }
    ...
    if (refcount) {
        so->so_usecount++;
    }
    so->lock_lr[so->next_lock_lr] = lr_saved;
    so->next_lock_lr = (so->next_lock_lr + 1) % SO_LCKDBG_MAX;
    return 0;
}
```

在`tcp_lock()`函数中，可以发现`refcount`参数的使用是用于对当前套接字的持有的引用计数增加，用于表明当前的套接字是被持有状态，而在刚才`flow_divert_handle_connect_result`函数中，首次获取套接字想要使用的时候，传入的参数2却为0，因此有个问题则是当前系统无法通过引用计数来判断当前套接字是否被持有。

当然，套接字是处于加锁状态，正常使用正常释放，处于使用状态用户是没有办法通过`close`函数，对其进行关闭回收的。

```c
static void flow_divert_disable(struct flow_divert_pcb *fd_cb)
{
...
    so = fd_cb->so;
    if (so == NULL) {
        goto done;
    }
...
    /* Dis-associate the socket */
    so->so_flags &= ~SOF_FLOW_DIVERT;
    so->so_flags1 |= SOF1_FLOW_DIVERT_SKIP;
    so->so_fd_pcb = NULL;
    fd_cb->so = NULL;

    FDRELEASE(fd_cb); /* Release the socket's reference */

    /* Revert back to the original protocol */
    so->so_proto = pffindproto(SOCK_DOM(so), SOCK_PROTO(so), SOCK_TYPE(so));

    /* Reset the socket state to avoid confusing NECP */
    so->so_state &= ~(SS_ISCONNECTING | SS_ISCONNECTED);

    last_proc = proc_find(so->last_pid);

    if (do_connect) {
        /* Connect using the original protocol */
        error = (*so->so_proto->pr_usrreqs->pru_connect)(so, remote_endpoint, (last_proc != NULL ? last_proc : current_proc()));
        if (error) {
            FDLOG(LOG_ERR, fd_cb, "Failed to connect using the socket's original protocol: %d", error);
            goto done;
        }
    }
}
```

在`flow_divert_handle_connect_result`函数中，会有一个分支会调用到`flow_divert_disable`函数，此函数可以知道是用于关闭FlowDivert相关功能的实现，其中会对控制块的释放，标志位的清除，以及通过`pffindproto`函数 还原该套接字原协议的接口函数。

那么后续`(*so->so_proto->pr_usrreqs->pru_connect)`函数的调用，则会调用到原协议的`connect`函数，此处若原协议为TCP4协议，那么转到TCP4协议对应的`connect`函数中。

```c
static int
tcp_connect(struct tcpcb *tp, struct sockaddr *nam, struct proc *p)
{
...
    socket_unlock(inp->inp_socket, 0);
    oinp = in_pcblookup_hash(inp->inp_pcbinfo,
        sin->sin_addr, sin->sin_port,
        inp->inp_laddr.s_addr != INADDR_ANY ? inp->inp_laddr : laddr,
        inp->inp_lport, 0, NULL);

    socket_lock(inp->inp_socket, 0);
    ...
}
```

很明显，此处同样存在一个暂时性解锁，那么可以总结出以下三点：

1. 进入`flow_divert_handle_connect_result`函数，通过控制块`fd_cb`对象，加锁套接字，但是持有的引用计数未+1；
2. 在解锁之前，调用了`flow_divert_disable`函数，还原到原协议接口函数；
3. 其中会调用原协议接口函数，例如`tcp_connect`函数，其中存在`socket_unlock`函数对套接字暂时性解锁，那么此时的套接字引用计数不变，且不曾处于加锁状态。

那么即可通过`close`函数对套接字进行关闭，系统则会对套接字进行垃圾回收，当然close流程中，依旧存在各种检测，但是由于此时是通过`fd_cb`控制块取出的套接字，并不是通过常规的路径对文件描述符进行操控的，所以可以缺少对文件描述符使用过程中的各种检测的施加。

## 四. 总结

本文根据近年在FlowDivert模块中出现的历史漏洞分析，主要从四个漏洞入手进行分析，总结漏洞产生的原因，可以通过审计产品新添加的功能或者从历史漏洞的patch入手，能对产出有一定的正收益效果。

第一个案例的漏洞产生是由于条件竞争且标志位设置的缺失，导致能够多个线程同时进入同一个路径调用同一个函数。

第二个案例的漏洞是在第一个案例的漏洞基础上进一步开发，发现的另一路径的绕过，官方在修复方案中，并没有对其具体的root cause进行彻底的根除，导致仅仅修复了同时进入该函数产生的一种情况，但是暂时性解锁的问题却没有修改，因此产生了第二个案例的漏洞。

第三个案例的漏洞是由于开发过程中的小细节，对残留变量没有处理好，导致返回指针是一个残留指针，而残留指针是处于未添加引用计数的状态，因此导致后续的UAF漏洞。

第四个案例的漏洞是在当前模块另一个方面进行考虑，前面的漏洞都是在控制块相关的进行考虑，而第四个案例的漏洞则是从group的解析入手，发现属于被动取出套接字进行使用的时候，没有严格按照主动使用套接字相关接口的方法进行合理的使用。
