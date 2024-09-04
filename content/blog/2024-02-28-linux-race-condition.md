---
slug: tiangongarticle019
date: 2024-02-28
title: 关于Linux内核条件竞争的探讨
author: lm0963
tags: [Linux, Race Condition]
---

# 关于Linux内核条件竞争的探讨

## 一、前言

在linux内核中，条件竞争一直是一个经久不息的问题，本文就几种简单的条件竞争模式进行探讨，希望能起到抛砖引玉的效果。

 ![](/attachments/2024-02-28-linux-race-condition/82eccd06-f3bd-4477-822e-21250e2f359a.png)

<!-- truncate -->

## 二、未加锁

`CVE-2016-2546`就是一个未正确加锁导致的条件竞争问题，允许多个进程同时对同一共享资源进行访问，未充分考虑加锁导致的条件竞争。

如下是`snd_timer`相关的文件操作，重点关注`snd_timer_user_ioctl`函数。

```c
static const struct file_operations snd_timer_f_ops =
{
    .owner =    THIS_MODULE,
    .read =     snd_timer_user_read,
    .open =     snd_timer_user_open,
    .release =  snd_timer_user_release,
    .llseek =   no_llseek,
    .poll =     snd_timer_user_poll,
    .unlocked_ioctl =   snd_timer_user_ioctl,
    .compat_ioctl = snd_timer_user_ioctl_compat,
    .fasync =   snd_timer_user_fasync,
};
```

```c
static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
                 unsigned long arg)
{
    struct snd_timer_user *tu;
    void __user *argp = (void __user *)arg;
    int __user *p = argp;

    tu = file->private_data;
    switch (cmd) {
    case SNDRV_TIMER_IOCTL_PVERSION:
        return put_user(SNDRV_TIMER_VERSION, p) ? -EFAULT : 0;
    case SNDRV_TIMER_IOCTL_NEXT_DEVICE:
        return snd_timer_user_next_device(argp);
    case SNDRV_TIMER_IOCTL_TREAD:
    {
        int xarg;

        mutex_lock(&tu->tread_sem);
        if (tu->timeri) {   /* too late */
            mutex_unlock(&tu->tread_sem);
            return -EBUSY;
        }
        if (get_user(xarg, p)) {
            mutex_unlock(&tu->tread_sem);
            return -EFAULT;
        }
        tu->tread = xarg ? 1 : 0;
        mutex_unlock(&tu->tread_sem);
        return 0;
    }
    case SNDRV_TIMER_IOCTL_GINFO:
        return snd_timer_user_ginfo(file, argp);
    case SNDRV_TIMER_IOCTL_GPARAMS:
        return snd_timer_user_gparams(file, argp);
    case SNDRV_TIMER_IOCTL_GSTATUS:
        return snd_timer_user_gstatus(file, argp);
    case SNDRV_TIMER_IOCTL_SELECT:
        return snd_timer_user_tselect(file, argp);
    case SNDRV_TIMER_IOCTL_INFO:
        return snd_timer_user_info(file, argp);
    case SNDRV_TIMER_IOCTL_PARAMS:
        return snd_timer_user_params(file, argp);
    case SNDRV_TIMER_IOCTL_STATUS:
        return snd_timer_user_status(file, argp);
    case SNDRV_TIMER_IOCTL_START:
    case SNDRV_TIMER_IOCTL_START_OLD:
        return snd_timer_user_start(file);
    case SNDRV_TIMER_IOCTL_STOP:
    case SNDRV_TIMER_IOCTL_STOP_OLD:
        return snd_timer_user_stop(file);
    case SNDRV_TIMER_IOCTL_CONTINUE:
    case SNDRV_TIMER_IOCTL_CONTINUE_OLD:
        return snd_timer_user_continue(file);
    case SNDRV_TIMER_IOCTL_PAUSE:
    case SNDRV_TIMER_IOCTL_PAUSE_OLD:
        return snd_timer_user_pause(file);
    }
    return -ENOTTY;
}
```

`snd_timer_user_ioctl`函数中未进行加锁，所以可以多个线程同时进入此函数。`SNDRV_TIMER_IOCTL_SELECT`和`SNDRV_TIMER_IOCTL_START`等多个选项之间存在竞争。

`snd_timer_user_tselect`函数首先对`tu->tread_sem`进行加锁操作，然后调用`snd_timer_close`关闭现有的timeri。

```c
static int snd_timer_user_tselect(struct file *file,
                  struct snd_timer_select __user *_tselect)
{
    struct snd_timer_user *tu;
    struct snd_timer_select tselect;
    char str[32];
    int err = 0;

    tu = file->private_data;
    mutex_lock(&tu->tread_sem);
    if (tu->timeri) {
        snd_timer_close(tu->timeri);
        tu->timeri = NULL;
    }
    ......
   __err:
        mutex_unlock(&tu->tread_sem);
    return err;
}
```

在`snd_timer_close`的最后会通过`kfree`释放`timeri`。

```c
int snd_timer_close(struct snd_timer_instance *timeri)
{
 ......
 out:
    if (timeri->private_free)
        timeri->private_free(timeri);
    kfree(timeri->owner);
    kfree(timeri);         // FREE
    if (timer)
        module_put(timer->module);
    return 0;
}
```

若此时另一线程通过`cmd`为`SNDRV_TIMER_IOCTL_START`参数调用`snd_timer_user_ioctl`，则会在`snd_timer_user_start`中导致对`tu->timeri`的`UAF`。

```c
static int snd_timer_user_start(struct file *file)
{
    int err;
    struct snd_timer_user *tu;

    tu = file->private_data;
    if (!tu->timeri)
        return -EBADFD;
    snd_timer_stop(tu->timeri);   // UAF
    tu->timeri->lost = 0;
    tu->last_resolution = 0;
    return (err = snd_timer_start(tu->timeri, tu->ticks)) < 0 ? err : 0;
}
```

本质上是释放路径和访问路径中存在一条未加锁的路径，导致的竞争问题。

| **CPU-1** | **CPU-2** |
|----|----|
| `snd_timer_user_ioctl` | `snd_timer_user_ioctl` |
|     `snd_timer_user_tselect` |    |
|         `mutex_lock` |      `snd_timer_user_start` |
|            `snd_timer_close` |    |
|                 `kfree` |    |
|    |            `snd_timer_stop` |

补丁也比较简单，直接对`snd_timer_user_ioctl`整个范围加锁。

```c
diff --git a/sound/core/timer.c b/sound/core/timer.c
index 31f40f03e5b7..b03a9e489286 100644
--- a/sound/core/timer.c
+++ b/sound/core/timer.c
@@ -73,7 +73,7 @@ struct snd_timer_user {
    struct timespec tstamp;     /* trigger tstamp */
    wait_queue_head_t qchange_sleep;
    struct fasync_struct *fasync;
-   struct mutex tread_sem;
+   struct mutex ioctl_lock;
 };
 
 /* list of timers */
@@ -1253,7 +1253,7 @@ static int snd_timer_user_open(struct inode *inode, struct file *file)
        return -ENOMEM;
    spin_lock_init(&tu->qlock);
    init_waitqueue_head(&tu->qchange_sleep);
-   mutex_init(&tu->tread_sem);
+   mutex_init(&tu->ioctl_lock);
    tu->ticks = 1;
    tu->queue_size = 128;
    tu->queue = kmalloc(tu->queue_size * sizeof(struct snd_timer_read),
@@ -1273,8 +1273,10 @@ static int snd_timer_user_release(struct inode *inode, struct file *file)
    if (file->private_data) {
        tu = file->private_data;
        file->private_data = NULL;
+       mutex_lock(&tu->ioctl_lock);
        if (tu->timeri)
            snd_timer_close(tu->timeri);
+       mutex_unlock(&tu->ioctl_lock);
        kfree(tu->queue);
        kfree(tu->tqueue);
        kfree(tu);
@@ -1512,7 +1514,6 @@ static int snd_timer_user_tselect(struct file *file,
    int err = 0;

    tu = file->private_data;
-   mutex_lock(&tu->tread_sem);
    if (tu->timeri) {
        snd_timer_close(tu->timeri);
        tu->timeri = NULL;
@@ -1556,7 +1557,6 @@ static int snd_timer_user_tselect(struct file *file,
    }

       __err:
-       mutex_unlock(&tu->tread_sem);
    return err;
 }
 
@@ -1769,7 +1769,7 @@ enum {
    SNDRV_TIMER_IOCTL_PAUSE_OLD = _IO('T', 0x23),
 };
 
-static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
+static long __snd_timer_user_ioctl(struct file *file, unsigned int cmd,
                 unsigned long arg)
 {
    struct snd_timer_user *tu;
@@ -1786,17 +1786,11 @@ static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
    {
        int xarg;

-       mutex_lock(&tu->tread_sem);
-       if (tu->timeri) {   /* too late */
-           mutex_unlock(&tu->tread_sem);
+       if (tu->timeri) /* too late */
            return -EBUSY;
-       }
-       if (get_user(xarg, p)) {
-           mutex_unlock(&tu->tread_sem);
+       if (get_user(xarg, p))
            return -EFAULT;
-       }
        tu->tread = xarg ? 1 : 0;
-       mutex_unlock(&tu->tread_sem);
        return 0;

    case SNDRV_TIMER_IOCTL_GINFO:
@@ -1829,6 +1823,18 @@ static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
    return -ENOTTY;
 }
 
+static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
+                unsigned long arg)
+{
+   struct snd_timer_user *tu = file->private_data;
+   long ret;
+
+   mutex_lock(&tu->ioctl_lock);
+   ret = __snd_timer_user_ioctl(file, cmd, arg);
+   mutex_unlock(&tu->ioctl_lock);
+   return ret;
+}
+
 static int snd_timer_user_fasync(int fd, struct file * file, int on)
 {
    struct snd_timer_user *tu;
```

## 三、过早释放锁

虽然加锁了，但如果过早的释放锁，也会导致问题。`CVE-2022-1048`就是一个很好的例子。

如下是`snd_timer`相关的文件操作，重点关注`snd_pcm_common_ioctl`函数。

```c
const struct file_operations snd_pcm_f_ops[2] = {
    {
        .owner =        THIS_MODULE,
        .write =        snd_pcm_write,
        .write_iter =       snd_pcm_writev,
        .open =         snd_pcm_playback_open,
        .release =      snd_pcm_release,
        .llseek =       no_llseek,
        .poll =         snd_pcm_poll,
        .unlocked_ioctl =   snd_pcm_ioctl,
        .compat_ioctl =     snd_pcm_ioctl_compat,
        .mmap =         snd_pcm_mmap,
        .fasync =       snd_pcm_fasync,
        .get_unmapped_area =    snd_pcm_get_unmapped_area,
    },
    {
        .owner =        THIS_MODULE,
        .read =         snd_pcm_read,
        .read_iter =        snd_pcm_readv,
        .open =         snd_pcm_capture_open,
        .release =      snd_pcm_release,
        .llseek =       no_llseek,
        .poll =         snd_pcm_poll,
        .unlocked_ioctl =   snd_pcm_ioctl,
        .compat_ioctl =     snd_pcm_ioctl_compat,
        .mmap =         snd_pcm_mmap,
        .fasync =       snd_pcm_fasync,
        .get_unmapped_area =    snd_pcm_get_unmapped_area,
    }
};

static long snd_pcm_ioctl(struct file *file, unsigned int cmd,
              unsigned long arg)
{
    struct snd_pcm_file *pcm_file;

    pcm_file = file->private_data;

    if (((cmd >> 8) & 0xff) != 'A')
        return -ENOTTY;

    return snd_pcm_common_ioctl(file, pcm_file->substream, cmd,
                     (void __user *)arg);
}

static int snd_pcm_common_ioctl(struct file *file,
                 struct snd_pcm_substream *substream,
                 unsigned int cmd, void __user *arg)
{
    struct snd_pcm_file *pcm_file = file->private_data;
    int res;

    if (PCM_RUNTIME_CHECK(substream))
        return -ENXIO;

    if (substream->runtime->status->state == SNDRV_PCM_STATE_DISCONNECTED)
        return -EBADFD;

    res = snd_power_wait(substream->pcm->card);
    if (res < 0)
        return res;

    switch (cmd) {
    ......
    case SNDRV_PCM_IOCTL_HW_FREE:
        return snd_pcm_hw_free(substream);
    ......
  }
    pcm_dbg(substream->pcm, "unknown ioctl = 0x%x\n", cmd);
    return -ENOTTY;
}
```

`snd_pcm_common_ioctl`函数中未进行加锁，所以可以多个线程同时进入此函数。

`snd_pcm_hw_free`函数首先通过`snd_pcm_stream_lock_irq`进行加锁操作，但在调用`do_hw_free`进行释放前，就已调用`snd_pcm_stream_unlock_irq`解锁，所以如果多线程同时调用`snd_pcm_hw_free`就可能会导致竞争问题。

```c
static int snd_pcm_hw_free(struct snd_pcm_substream *substream)
{
    struct snd_pcm_runtime *runtime;
    int result;

    if (PCM_RUNTIME_CHECK(substream))
        return -ENXIO;
    runtime = substream->runtime;
    snd_pcm_stream_lock_irq(substream);
    switch (runtime->status->state) {
    case SNDRV_PCM_STATE_SETUP:
    case SNDRV_PCM_STATE_PREPARED:
        break;
    default:
        snd_pcm_stream_unlock_irq(substream);
        return -EBADFD;
    }
    snd_pcm_stream_unlock_irq(substream);
    if (atomic_read(&substream->mmap_count))
        return -EBADFD;
    result = do_hw_free(substream);     // 第二个进程 double free
    snd_pcm_set_state(substream, SNDRV_PCM_STATE_OPEN);
    cpu_latency_qos_remove_request(&substream->latency_pm_qos_req);
    return result;
}
```

| **CPU-1** | **CPU-2** |
|----|----|
| `snd_pcm_common_ioctl` | `snd_pcm_common_ioctl` |
|    `snd_pcm_hw_free` |    `snd_pcm_hw_free` |
|       `snd_pcm_stream_lock_irq` |    |
|          `snd_pcm_stream_unlock_irq` |          `snd_pcm_stream_lock_irq` |
|    |             `snd_pcm_stream_unlock_irq` |
|                `do_hw_free` |                `do_hw_free` |

由于`snd_pcm_common_ioctl`还存在多处其它的竞争问题，所以补丁实际上是增加了一个新的锁来解决，新的锁范围涵盖了`do_hw_free`。

```c
@@ -848,26 +860,31 @@ static int do_hw_free(struct snd_pcm_substream *substream)
 static int snd_pcm_hw_free(struct snd_pcm_substream *substream)
 {
    struct snd_pcm_runtime *runtime;
-   int result;
+   int result = 0;

    if (PCM_RUNTIME_CHECK(substream))
    return -ENXIO;
    runtime = substream->runtime;
+   mutex_lock(&runtime->buffer_mutex);
    snd_pcm_stream_lock_irq(substream);
    switch (runtime->status->state) {
    case SNDRV_PCM_STATE_SETUP:
    case SNDRV_PCM_STATE_PREPARED:
+       if (atomic_read(&substream->mmap_count))
+           result = -EBADFD;
        break;
    default:
-       snd_pcm_stream_unlock_irq(substream);
-       return -EBADFD;
+       result = -EBADFD;
+       break;
    }
    snd_pcm_stream_unlock_irq(substream);
-   if (atomic_read(&substream->mmap_count))
-       return -EBADFD;
+   if (result)
+       goto unlock;
    result = do_hw_free(substream);
    snd_pcm_set_state(substream, SNDRV_PCM_STATE_OPEN);
    cpu_latency_qos_remove_request(&substream->latency_pm_qos_req);
+ unlock:
+   mutex_unlock(&runtime->buffer_mutex);
    return result;
 }
```

## 四、过早暴露给用户态

当一个对象被过早的暴露给用户态时，也会存在竞争问题。例如一个函数中调用`fd_install`使得用户态可以通过`fd`访问对应的`file`对象之后（此时用户态可以通过`close`释放对应的`file`对象），又接着在后面代码中访问`file`对象，此时就会导致`UAF`。

下文将通过`CVE-2022-1998`进行说明。

在`copy_event_to_user`中调用`create_fd`创建对应的`file`对象和`fd`，紧接着调用`fd_install`使得用户态可以通过fd访问对应的`file`对象，然后调用`copy_info_records_to_user`，此时若`copy_info_records_to_user`返回失败，则会进入失败处理流程，调用`fput`释放`file`对象，但如果用户态在`fput`之前就调用`close`释放了`file`对象，那么在`fput`中会出现`UAF/Double Free`。

```c
static ssize_t copy_event_to_user(struct fsnotify_group *group,
                  struct fanotify_event *event,
                  char __user *buf, size_t count)
{
    ......
    if (!FAN_GROUP_FLAG(group, FANOTIFY_UNPRIV) &&
        path && path->mnt && path->dentry) {
        fd = create_fd(group, path, &f);
        if (fd < 0)
            return fd;
    }
    metadata.fd = fd;
    ......
    if (f)
        fd_install(fd, f);

    if (info_mode) {
        ret = copy_info_records_to_user(event, info, info_mode, pidfd,
                        buf, count);
        if (ret < 0)
            goto out_close_fd;
    }

    return metadata.event_len;

out_close_fd:
    if (fd != FAN_NOFD) {
        put_unused_fd(fd);
        fput(f);       // UAF/ Double Free
    }

    if (pidfd >= 0)
        close_fd(pidfd);

    return ret;
}
```

| **CPU-1** | **CPU-2** |
|----|----|
| `copy_event_to_user` |    |
|    `fd_install` |    |
|       `copy_info_records_to_user` | `close` |
|          `fput` |    |

补丁也很简单，将`fd_install`往后移，确保不会在`fd_install`之后依然使用`file`对象即可。`windows`内核中也存在类似的问题，可以参考这篇文章[CVE-2021-41335](https://pastebin.com/H7tQSX7C)。

```c
diff --git a/fs/notify/fanotify/fanotify_user.c b/fs/notify/fanotify/fanotify_user.c
index 1026f67b1d1e4..2ff6bd85ba8f6 100644
--- a/fs/notify/fanotify/fanotify_user.c
+++ b/fs/notify/fanotify/fanotify_user.c
@@ -701,9 +701,6 @@ static ssize_t copy_event_to_user(struct fsnotify_group *group,
    if (fanotify_is_perm_event(event->mask))
        FANOTIFY_PERM(event)->fd = fd;
 
-   if (f)
-       fd_install(fd, f);
-
    if (info_mode) {
        ret = copy_info_records_to_user(event, info, info_mode, pidfd,
                        buf, count);
@@ -711,6 +708,9 @@ static ssize_t copy_event_to_user(struct fsnotify_group *group,
            goto out_close_fd;
    }

+   if (f)
+       fd_install(fd, f);
+
    return metadata.event_len;

 out_close_fd:
```

## 五、未取消工作队列

此类问题常见于设备移除过程，`linux`设备有时会通过创建工作队列，来处理一些问题。若是在设备移除时，忘记取消之前创建的工作队列，那么就可能导致`UAF`。

`CVE-2023-33288`就是这一类问题，在`bq24190_probe`函数中初始化`input_current_limit_work`工作队列指针为`bq24190_input_current_limit_work`。

```c
static int bq24190_probe(struct i2c_client *client)
{
    .......
    INIT_DELAYED_WORK(&bdi->input_current_limit_work,
              bq24190_input_current_limit_work);
  .......
}
```

之后当外部电源改变时，会调用`bq24190_charger_external_power_changed`将`input_current_limit_work`加入到延迟工作队列中（300ms后才会真正调用`bq24190_input_current_limit_work`）。

```c
static void bq24190_charger_external_power_changed(struct power_supply *psy)
{
    struct bq24190_dev_info *bdi = power_supply_get_drvdata(psy);

    /*
     * The Power-Good detection may take up to 220ms, sometimes
     * the external charger detection is quicker, and the bq24190 will
     * reset to iinlim based on its own charger detection (which is not
     * hooked up when using external charger detection) resulting in a
     * too low default 500mA iinlim. Delay setting the input-current-limit
     * for 300ms to avoid this.
     */
    queue_delayed_work(system_wq, &bdi->input_current_limit_work,
               msecs_to_jiffies(300));
}
```

若此时移除此模块，则会调用`bq24190_remove`进行清理，但该函数没有移除之前的工作队列，导致后续`bq24190_input_current_limit_work`被调用时`UAF`。

```c
static void bq24190_remove(struct i2c_client *client)
{
    struct bq24190_dev_info *bdi = i2c_get_clientdata(client);
    int error;

    error = pm_runtime_resume_and_get(bdi->dev);
    if (error < 0)
        dev_warn(bdi->dev, "pm_runtime_get failed: %i\n", error);

    bq24190_register_reset(bdi);
    if (bdi->battery)
        power_supply_unregister(bdi->battery);
    power_supply_unregister(bdi->charger);
    if (error >= 0)
        pm_runtime_put_sync(bdi->dev);
    pm_runtime_dont_use_autosuspend(bdi->dev);
    pm_runtime_disable(bdi->dev);
}
```

补丁也很简单，在`bq24190_remove`中加上`cancel_delayed_work_sync`移除工作队列即可。

```c
diff --git a/drivers/power/supply/bq24190_charger.c b/drivers/power/supply/bq24190_charger.c
index be34b98484508..de67b985f0a91 100644
--- a/drivers/power/supply/bq24190_charger.c
+++ b/drivers/power/supply/bq24190_charger.c
@@ -1906,6 +1906,7 @@ static void bq24190_remove(struct i2c_client *client)
    struct bq24190_dev_info *bdi = i2c_get_clientdata(client);
    int error;
 
+   cancel_delayed_work_sync(&bdi->input_current_limit_work);
    error = pm_runtime_resume_and_get(bdi->dev);
    if (error < 0)
        dev_warn(bdi->dev, "pm_runtime_get failed: %i\n", error);
```

## 六、总结

本文总结了Linux内核中常见的几种条件竞争问题，还有许多更复杂的条件竞争类型，限于笔者水平，尚不能很好的分析总结。

总而言之，Linux内核中依然存在很多的条件竞争问题，和其它漏洞类型相比，条件竞争相对不易于理解，难以触发，希望本文能起到抛砖引玉的效果。

## 七、参考链接

CVE-2016-2546 [https://www.openwall.com/lists/oss-security/2016/01/19/1](https://www.openwall.com/lists/oss-security/2016/01/19/1)

CVE-2016-2546 补丁[https://github.com/torvalds/linux/commit/af368027a49a751d6ff4ee9e3f9961f35bb4fede](https://github.com/torvalds/linux/commit/af368027a49a751d6ff4ee9e3f9961f35bb4fede?diff=unified&w=0)

CVE-2022-1048 [https://seclists.org/oss-sec/2022/q1/204](https://seclists.org/oss-sec/2022/q1/204)

CVE-2022-1048 补丁[https://github.com/torvalds/linux/commit/92ee3c60ec9fe64404dc035e7c41277d74aa26cb](https://github.com/torvalds/linux/commit/92ee3c60ec9fe64404dc035e7c41277d74aa26cb)

CVE-2022-1998 [https://seclists.org/oss-sec/2022/q1/99](https://seclists.org/oss-sec/2022/q1/99)

CVE-2022-1998 补丁 [https://github.com/torvalds/linux/commit/ee12595147ac1fbfb5bcb23837e26dd58d94b15d](https://github.com/torvalds/linux/commit/ee12595147ac1fbfb5bcb23837e26dd58d94b15d)

CVE-2021-41335 [https://pastebin.com/H7tQSX7C](https://pastebin.com/H7tQSX7C)

CVE-2023-33288 补丁[https://github.com/torvalds/linux/commit/47c29d69212911f50bdcdd0564b5999a559010d4](https://github.com/torvalds/linux/commit/47c29d69212911f50bdcdd0564b5999a559010d4)
