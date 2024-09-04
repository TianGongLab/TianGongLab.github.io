---
slug: tiangongarticle028
date: 2024-04-24
title: "SystemUI As EvilPiP: 针对现代移动设备的劫持攻击"
author: mg1937
tags: [SystemUI, Activity Hijack Attack, AHA, BlackHat]
---

# SystemUI As EvilPiP: 针对现代移动设备的劫持攻击

2024年4月19日，奇安信天工实验室安全研究员程为民，出席国际顶级信息安全会议BlackHat ASIA 2024，发表 **《SystemUI As EvilPiP: The Hijacking Attacks on Modern Mobile Devices》** 议题演讲。**议题披露了在SystemUI下隐藏了六年之久的新型攻击面，以及SystemServer中难以修复的设计缺陷**。

 ![](/attachments/2024-04-24-systemui-as-evilpip/ba981914-26a9-4048-83eb-365110e422a1.png)

<!-- truncate -->

## 一、Preface

Activity Hijack Attack(AHA)是一项古老的UI攻击技术。大约在十年前，利用这种技术的银行木马与间谍软件开始在Android4.0平台上泛滥，这些劫持软件可以精确监控用户的行为，并以几乎无感知的方式劫持用户正在浏览的内容。由于在早期Android平台上利用这种技术无需任何权限和额外的用户交互，其成为了地下产业最喜爱的攻击手段之一。

但近年来，AHA逐渐失去了它的光彩。由于Google持续发布针对这类技术的缓解方案与限制策略，劫持软件的攻击成本被不断提高。2016年，Google更新了SELinux策略，完全禁止了应用对procfs的访问，并限制了大部分可以泄露应用运行状态的API，自此，无感知与零权限的劫持攻击(基于AHA)成为了历史。2017年，更加严格的LMKD机制与后台执行限制开始杀死处于后台的闲置进程。2019年，Google发布了BAL限制，从后台启动活动的行为被禁止，AHA技术彻底死亡。

在这些安全策略的保护下，AHA不再是低成本的移动端攻击方案。攻击者或许会通过诱导用户开启需要复杂交互才能使用的特权以在高版本设备上实现AHA攻击，但这距离精准劫持还很遥远，更何况手机厂商会在这些特权被授予前警告用户不要轻易相信第三方软件，所以AHA毫无疑问被地下产业抛弃了，甚至在2019年之后，再也没有论文或会议提到这类技术。劫持软件的时代结束了吗？

这份研究将证明Google的安全策略并非不可突破，零权限且无感知的劫持攻击仍有可能出现在高版本Android设备上。

六年前，Android引入了一个新的系统特性。同时也引入了一个潜在的攻击面。本研究将披露攻击面下多个未公开漏洞的细节，任何应用都可以利用漏洞间接攻击SystemUI，并以零权限突破BAL限制。接着，研究将深入SystemServer，同时分析其中潜藏多年的安全问题与设计缺陷，最终利用这些缺陷以侧信道方式来泄露任意一个应用的运行状态，绕过LMKD与后台执行限制，获得长期监控与稳定运行的能力。

在最后，研究将组合这些绕过方案，以武器化一个可以绕过自2014年以来Google发布的所有安全策略的劫持软件。这或许是**七年来唯一一个从正面突破安全策略与防御机制，在 Android Q+ 设备上达成零权限且无需额外用户交互的劫持软件(基于AHA)**。

## 二、Introduction

在高版本设备上实现UI劫持攻击之前，有必要知道它在早期Android设备上是怎么运作的。虽然"Preface"章节简要谈到了限制劫持攻击的几种安全策略，同时也提到了绕过策略的可行方案，但如果要理解本研究针对关键组件的分析以及完整利用链的原理，那么通过传统劫持链条来理解安全策略是有必要的。

### 2.1 Chain Of AHA-based Hijackware

 ![](/attachments/2024-04-24-systemui-as-evilpip/61ac6331-37b5-4e96-9b03-67a1bec61d55.png)

如图为传统劫持软件的大致攻击链条。首先链条将启动`Service`组件以便进程长时间驻留在后台，接着组件内的代码将不间断获取目标的运行状态，以此来判断其是否来到前台。一旦目标到达前台，也就意味着用户目前正在浏览目标应用，当时机合适时，程序会通过一个带有`NEW_TASK`标记的`Intent`对象从后台启动Activity以覆盖用户正在浏览的页面(这一步骤正是AHA)，最终达到UI劫持的目的。

可见传统劫持链条相当简单，没有任何一步是多余的，且链条中的所有关键操作在早期Android平台上无需申请任何权限。毫无疑问，简短且有效的攻击链条允许攻击者很好地混淆或隐藏恶意代码，且这种UI覆盖攻击不易被用户察觉。如果Google没有对这类攻击方法采取措施，恐怕直到现在地下产业的开发者仍会采用这种方案攻击用户设备。

在了解攻击链条后，下面将正式进入到关键步骤的技术细节以及安全策略的分析部分。

### 2.2 Leaking Running State

在API22之前，攻击者可以通过滥用`ActivityManager`下的接口来泄露第三方应用的运行状态。如下图，`getRunningTasks`与`getRunningAppProcesses`函数可以获取到详细的第三方应用信息，其中`getRunningTasks`接口甚至能够获取到目标任务栈顶的Activity信息，早期的劫持软件正是以此实现高精度的劫持攻击。

 ![](/attachments/2024-04-24-systemui-as-evilpip/8202847a-761b-4c82-9ba1-11e2e17d51f9.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/df87bb43-4d50-4c68-8c96-794e3f80ef7d.png)

在API22之后，这些API全部被Google标记为Deprecated且做了相关限制，目前在API33上调用这些接口将只能返回调用者本身的相关信息。但是在API26之前，攻击者仍可以通过procfs以侧信道方式泄露敏感信息。

 ![](/attachments/2024-04-24-systemui-as-evilpip/0a8c23b9-dcb3-4b31-92ea-724fdb42f16b.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/e0c64ad7-e217-4831-9b06-b04b57884d12.png)

如上图，以API19的Android设备为例，以用户u0_a57身份列出/proc目录下的内容，随机选中一个进程并访问其`oom_score_adj`，显然非特权用户依然有权限浏览第三方进程信息，即使Google对敏感API进行了限制，攻击者仍可以通过procfs获取第三方进程的优先级，以此判断其是否存在于前台。

 ![](/attachments/2024-04-24-systemui-as-evilpip/63013f3c-90dc-4c38-a5e7-db0527d75585.png)

随后在2017年，Google更新了SELinux策略，彻底禁止了任意应用通过procfs访问第三方应用数据(类似hidepid=2保护)。自此之后劫持软件不得不通过 `PACKAGE_USAGE_STATS` 权限与 `UsageStatsManager` 来实现精确劫持，但该权限的开启需要复杂的用户交互，诱导用户开启这种权限并非一件易事，况且许多手机厂商(比如MIUI)会在开启这类权限前强制警告用户可能的安全风险，且警告页面会强制持续10秒。所以在"Preface"章节才会称零权限与无感知的劫持攻击成为了历史。

### 2.3 Activity Hijack Attack

要实现精准UI劫持，泄露第三方应用的运行状态固然重要，但AHA技术是整个攻击链条的核心，一旦AHA技术不再起作用，整个链条也就无法运行。

 ![](/attachments/2024-04-24-systemui-as-evilpip/b60d4349-a6f5-40c6-8d82-5e4d62489ab6.png)

在API29之前，AHA仍可以被利用。攻击者会通过调用startActivity启动一个指向Activity且携带`NEW_TASK`标记的Intent对象以实现AHA攻击。如AOSP框架代码中对于该标记的描述，携带此标记时启动Activity会让系统创建一个新的任务栈(如果这个Activity不包含在任何现有任务栈中)，接着这个Activity将立即出现在用户视野内，覆盖屏幕上原本的内容。那么为什么会发生这种情况？ 为什么启动新任务栈可以让Activity覆盖屏幕上的内容？

 ![](/attachments/2024-04-24-systemui-as-evilpip/da2af201-3263-41e6-bcff-923a37b2360c.png)

任务栈可以看作装载Activity的容器，任何应用在启动时都将至少创建一个任务栈(假设应用拥有UI)。根据官方文档"[Task and back-stack](https://developer.android.com/guide/components/activities/tasks-and-back-stack)"的描述，应用内启动的Activity都将进入对应的任务栈内，且任务栈可以容纳任意数量的Activity。

在用户视野内，用户将首先看到任务栈中的栈顶活动，而任务栈可以被分为前台任务栈与后台任务栈，后台任务栈不被用户可见，且后台中可以同时存在多个任务栈。前台任务栈为用户可见，但大多数情况下有且仅有一个任务栈存在于前台，用户一次只能与一个前台任务栈进行交互(不考虑分屏或其它情况)。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c8577c1a-94d7-4cba-8fc8-062ec5a01522.png)

在了解过任务栈相关的概念后，AHA技术就很好理解了。以API15的AOSP框架代码为例，`startActivity`函数被调用后，系统将进入`ActivityStack#startActivityUncheckedLocked`函数，接着代码将判断传入的Intent是否携带NEW_TASK标记，携带标记时系统会将Intent指向的Activity的所在任务栈移动到前台，而由于前台仅允许存在一个任务栈，所以之前存在于前台的第三方应用任务栈将被压入后台，并被新的任务栈顶替。

不难得出结论，AHA的本质事实上就是对前台任务栈的抢占，在合适的时机抢占前台，就能悄无声息地劫持用户的屏幕。事实上早在2013年，由北京航空航天大学与其他相关机构发表的论文《Hijacking Activity Technology Analysis and Research in Android System》([10.1007/978-3-662-43908-1_6](https://www.researchgate.net/publication/289280922_Hijacking_Activity_Technology_Analysis_and_Research_in_Android_System))就曾提到过利用这种方法实现AHA攻击。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c0804b1b-25e9-4920-9741-30388eedcd01.png)

但自从API29，谷歌开始发布相关策略来阻止这类攻击。下文称该策略为BAL限制(Background Activity Launch restriction)。根据官方文档"[Restriction on starting activities](https://developer.android.com/guide/components/activities/background-starts)"对该限制的描述，任何处于后台的应用都无法启动Activity，除非该应用能够满足一项或多项豁免条件。然而这些条件都十分苛刻，几乎没有任何后台应用可以在不持有危险权限时满足任何一条。如果Activity启动的流程被中断，就不可能创建新任务栈来劫持屏幕内容，所以在API29之后，AHA技术被宣告死亡，目前基于AHA技术的所有相关PoC在API29及以上Android版本都无法正常运行。

### 2.4 Persistently Background Process

本章节的"Leaking Running State"与"Activity Hijack Attack"部分主要介绍了早期劫持攻击中的两大核心步骤，同时也说明了Google是如何利用安全策略使劫持攻击失效的。那么现在来假设一个理想情况: Google完全没有发布任何限制劫持攻击的相关策略，那么此时劫持软件可以在高版本设备上实现精确劫持吗？

答案自然是否定的，精准劫持不仅依赖于完整可用的利用链条，更依赖于程序本身的持续性。劫持软件在早期Android平台上的确有许多技巧来实现持久运行，即使仅启动一个Service，进程也能在后台长时间运行以执行劫持任务，但API26之后，情况发生了改变。

在阅读下文前，有必要了解什么是[Low Memory Killer Deamon](https://source.android.com/docs/core/perf/lmkd)(LMKD)。简要来说，LMKD是用于监视高内存占用且非必要进程的系统进程，LMKD将杀死这类臃肿进程以保证整个系统的稳定性。需要注意的是，LMKD是通过进程优先级来判断臃肿进程的，进程越臃肿其优先级就越低。

 ![](/attachments/2024-04-24-systemui-as-evilpip/20af843f-e9ca-4332-b16c-d41498166a96.png)

简单编写一个用于测试进程持久性的App: 该App会在运行时启动一个Service。将其安装在API19与API33的设备上，启动App后模拟用户点击"Home"按键回到主页面，接着通过procfs中的oom_score_adj与oom_adj查询其进程优先级。

可见在API19设备上，进程将获得处于PREVIOUS_APP_ADJ与SERVICE_B_ADJ之间的优先级，持有该优先级的后台进程在相当长的一段时间内不会被系统杀死，持续性地在后台执行劫持任务是有可能的。而在API33设备上，应用几乎一进入后台就被赋予了接近CACHED_APP_LMK_FIRST_ADJ的优先级，持有该优先级的后台进程几乎会被系统立即杀死。

进程能否在后台持续性运行很大程度上取决于其优先级，那么如何提升进程优先级成为了下一个问题。在2020年，论文《Demystifying Diehard Android apps》([10.1145/3324884.3416637](https://dl.acm.org/doi/10.1145/3324884.3416637))研究了12种利用Android平台特性或缺陷的`Diehard`方案(实际上就是持续性方案)。论文在分析了这些方案的实现方式后给出了一套规则以检测此类`Diehard app`。

 ![](/attachments/2024-04-24-systemui-as-evilpip/d9e4bde2-50a5-469a-8acb-7e0e369d1659.png)

上图表格就是论文中给出的检测规则，通过这些规则可以很容易推导出原`Diehard`方案的大致实现过程。虽然这些方案理论上可以提升进程优先级，且论文作者声称它们可以被应用在Android5。1到10的设备上，但由于谷歌在2017年发布的[后台与广播限制](https://developer.android.com/about/versions/oreo/background)，大部分方案的效果并不理想，且不适用于API26以上的设备。例如论文中提到的BRS与ACP方案就高度依赖于第三方进程(虽然论文中并没有明示这一点)，虽然论文在讨论BRS时提到过需要运行一个独立的Service进程以提升优先级，但这种方案仅适用于API19左右的版本。COW方案则需要复杂的用户交互以开启一个危险权限(API23+)，其中利用TYPE_PHONE的部分已被修复。MSB与MAB方案中利用系统与第三方应用广播的方案已被Google与主流手机厂商限制。HFS是利用前台服务的方案，它确实可以在大多数Android设备上提升进程优先级，但启动前台服务必须持续性地向用户显示Notification，显然不适合需要在后台静默运行的恶意软件。而剩下的方案无一例外都被主流手机厂商限制或修复。

前有安全策略，后有LMKD，开发者面临的可行方案仅剩下"[前台服务](https://developer.android.com/guide/components/foreground-services)"。对于常规应用开发者而言，适配这种折中方案并不会消耗太多时间，然而，恶意开发者将受到限制，"前台服务"会不可避免地影响试图在后台隐蔽运行的恶意软件。当然，本研究始终不会选择前台服务作为持续化方案。

## 三、Defeat UI Security

上个章节中，研究具体分析了基于AHA技术的UI攻击链条的技术细节，并且简要分析了几类Google沿用了近七年的前沿防御手段，这些防御手段至今仍有效保护着用户设备免受UI攻击的威胁。在本章节中，研究将模拟恶意软件开发者，滥用数个新型攻击面以从正面突破这些防御手段，并最终实现零权限，无感知的UI劫持攻击。

### 3.1 Analyse BAL Restriction

后台活动启动限制(BAL限制)是Google限制AHA的核心手段，这种防御手段成功消灭了API29+设备上的所有劫持软件，同时它也是活动劫持无法回避的问题。由于上一章节并没有具体分析这个限制，所以在本部分，研究将对其进行具体分析。

 ![](/attachments/2024-04-24-systemui-as-evilpip/b78f1bdb-4048-4a93-90ab-734aafa4355d.png)

上图为官方文档对于BAL限制的简要描述，描述提到，当App处于后台时，其启动Activity的时机将受到系统限制，而对于Google所定义的"可以启动Activity的时机"，文档在"[When apps can start activities](https://developer.android.com/guide/components/activities/background-starts#exceptions)"条目中列出了多项豁免条件，在满足其中的一项或多项条件前，任何Activity都无法从后台启动，即使带有NEW_TASK标记。而这些条件都无一例外地十分苛刻，几乎每一项条件都要求用户与应用有强交互，并且其中一些条件还要求应用必须持有某些危险权限，总而言之，在API29+的设备上实现AHA并非易事。

 ![](/attachments/2024-04-24-systemui-as-evilpip/2eddea81-5845-4de3-b873-7284f7b12165.png)

以API33为例，假定有应用在后台调用了startActivity方法，按照Activity的常规启动链，系统将进入上图中ActivityStarter#executeRequest方法内的代码片段。其中，restrictedBgActivity成员由shouldAbortBackgroundActivityStart方法赋值，而该方法正是系统侧判定App是否符合豁免条件的关键函数。此处暂且假设App未通过系统侧检查，从而导致restrictedBgActivity成员被赋值为true。

 ![](/attachments/2024-04-24-systemui-as-evilpip/15cd9248-af3a-45c6-8e81-1208166d6471.png)

顺着启动链继续执行，系统进入ActivityStarter#setInitialState方法，由于restrictedBgActivity成员在之前被置为true，所以在该方法内其将影响mRestrictedBgActivity变量，接着系统将进入分支，使得mAvoidMoveToFront与mDoResume同样受到影响。

 ![](/attachments/2024-04-24-systemui-as-evilpip/7803c139-bbf3-4ae4-b117-fb31f4453f3e.png)

最终在ActivityStarter#startActivityInner方法内，mAvoidMoveToFront与mDoResume将影响系统决策，该决策将决定系统是否要将Activity的所在任务栈移动到前台，由于前文已经假设App未通过系统侧的条件检查(当然大多数情况下App也无法通过检查)，故此处系统跳过`moveToFront`函数，前台任务栈将不会被新任务栈顶替。

以上便是针对BAL限制实现的具体分析。事实上BAL限制的本质是为了提升用户体验，防止用户被不必要的内容打断，这项限制不仅防止了许多弹窗广告软件，同时也让多数攻击手段失效。

### 3.2 Analyse Exemption Condition

在分析过BAL限制的具体实现后，下一步目标便非常明确了。该部分，研究将审计其中一项豁免条件，深入分析shouldAbortBackgroundActivityStart方法(下文简称为shouldABAS方法)，最终在接下来的部分定制一套可行的攻击方案以突破系统侧的豁免判断。

 ![](/attachments/2024-04-24-systemui-as-evilpip/fd577947-c0f5-488b-bb74-a7a6e44fe04f.png)

首先大致浏览这些豁免条件，可以发现除了前三项，其它条件几乎无法被满足，但这也不意味着前三项条件可以轻易达到。以第一项条件为例，该项条件要求应用拥有可见窗体时才能获得豁免。但文档无法体现系统侧的真实判断流程，所以下面将跟入审计与该条件对应的代码片段。

 ![](/attachments/2024-04-24-systemui-as-evilpip/6c259391-198e-4061-a016-4d4982021f35.png)

在shouldABAS方法内，系统通过mService句柄的hasActiveVisibleWindow方法判断调用者是否拥有可见窗体，当该方法返回true时，shouldABAS方法将直接返回false，即允许App从后台启动Activity。由此可见hasActiveVisibleWindow方法正是系统判断第一项豁免条件的核心函数。

 ![](/attachments/2024-04-24-systemui-as-evilpip/0a36974f-24bf-4d9b-b27a-6486ae27e67d.png)

不难得知mService句柄即ActivityTaskManagerService(ATMS)实例，所以跟入该组件下的hasActiveVisibleWindow方法。在方法内，系统将首先调用VisibleActivityProcessTracker#hasVisibleActivity方法判断调用者是否满足豁免条件，若不满足，系统还会通过MirrorActiveUids#hasNonAppVisibleWindow方法进行最后一次判断，若两次判断结果均为false，则认为调用者没有可见窗体。对于hasVisibleActivity方法，该方法会判断调用者是否存在于前台任务栈或者拥有可见Activity，若结果为false则系统将进入hasNonAppVisibleWindow方法，此方法用于检测调用者是否拥有Type值大于FIRST_SYSTEM_WINDOW且不为TYPE_TOAST的窗体，很显然可由非系统级应用控制的系统级窗体仅TYPE_APPLICATION_OVERLAY一类，且此类窗体需要应用持有SYSTEM_ALERT_WINDOW(SAW)特权，但开启该特权需要复杂的用户交互。

如果不考虑其它豁免条件，仅针对第一项豁免条件进行绕过，那么在分析其判断细节后会发现能做的选择并不多，首先系统会判断应用是否拥有可见的Activity，但AHA技术本身就假设应用已经存在于后台，处于后台的同时存在于前台任务栈似乎无法实现，其次系统会判断应用是否拥有系统级窗体，非特权应用除了诱导用户申请高危权限以外别无选择。这一项条件的判断流程严防死守，几乎无法被绕过，而其它豁免条件则更是苛刻，这些条件几乎把启动Activity的时机锁死在应用处于前台的时段，这也解释了AHA技术彻底消失的核心原因。

### 3.3 New Attack Surface

虽然应用无法同时存在于前台与后台任务栈，但Google于API26引入的一项系统特性为绕过带来了可能。

 ![](/attachments/2024-04-24-systemui-as-evilpip/96892028-9fb2-4c15-bf55-c2a11257850b.png)

这项特性便是画中画(PiP)模式，据官方文档所述，PiP模式允许任意活动以小窗形式持续驻留在前台，这项特性很好地提升了用户体验，用户可以同时专注于不同的活动，避免了频繁的页面切换。如上图为正在使用PiP模式的视频播放软件MXPlayer。当然，在为用户带来便利的同时，PiP模式也存在潜在威胁， PiP窗口几乎可以看作无需SAW特权的系统级悬浮窗，任意非特权应用都可自由使用PiP模式而无需经过用户授权，这样的特性随时有可能被地下产业滥用。

 ![](/attachments/2024-04-24-systemui-as-evilpip/e67bd796-3449-4391-804c-9acfcb876ed9.png)

仍然以视频播放软件MXPlayer为例，当其以PiP模式运行时dump任务栈，可见MXPlayer此时处于pinned状态，并且其visible属性为true，这代表系统认为该Activity对用户可见，**也意味着MXPlayer此时处于前台任务栈，且满足了豁免条件**。那么假设这样的场景: 用户点击Home按键尝试回到主页，此时MXPlayer应当进入后台，但由于其在生命周期末期及时调用相关API进入PiP模式，其PiP窗口依然驻留前台，那么MXPlayer就可以在满足豁免条件的同时允许用户与其它应用进行交互(通常，如果用户正在与其它应用交互，则意味着自身进程已经处于后台)。

PiP模式确实是提升体验的不错功能，但如前文所述，由于PiP模式允许系统无条件授予任意应用长时间且稳定的前台特权，且允许特权进程SystemUI渲染其活动窗体，一系列高危操作让PiP模式本身成为了一个巨大的攻击面，而框架中负责PiP模式的相关代码出现的任何问题都有可能触发攻击面，最终导致UI或限制策略相关的安全问题。

 ![](/attachments/2024-04-24-systemui-as-evilpip/11e406d2-5bdc-4f8d-b332-67585a8072b4.png)

然而颇为讽刺的是，这样一个本应受到研究员重视的特性居然连续四年没有相关漏洞被公开，直到2021年，由Dimitrios Valsamaras发现的漏洞才被Google公开: [CVE-2021-0485](https://valsamaras.medium.com/size-matters-cve-2021-0485-cfa0a291f903)。Google对该问题评级为High，漏洞允许Activity以畸形的尺寸启动PiP模式，最终PiP窗口将以一个像素点的大小显示在屏幕顶层，由于用户几乎不可见且无法触摸的尺寸，应用可以在无用户感知的情况下在"后台"持续占有前台特权。该问题产生的原因是负责计算PiP窗口边界的组件PipBoundsAlgorithm没有严格校验输入数据。

 ![](/attachments/2024-04-24-systemui-as-evilpip/2c9b3584-a0d2-4889-84a8-bf99b53babc2.png)

针对该缺陷的Patch也很简单，Google直接规定了PiP窗体的最小边界，任何小于最小边界的畸形尺寸都将被修正为48dp。虽然漏洞已经被修复，但Dimitrios Valsamaras的发现在针对PiP特性进行代码审计的初期提供了良好的思路。

### 3.4 PiP Launch Chain

在深入分析PiP之前，理清PiP的启动链条并了解链条中的代码细节是必要的，这项工作将极大方便后续的代码审计。

 ![](/attachments/2024-04-24-systemui-as-evilpip/a3395d99-6991-433b-bcc3-97afb6944f95.png)

根据官方文档提供的PiP开发手册，Activity#enterPictureInPictureMode接口用于使应用进入PiP模式，在应用层中调用该接口后，框架层将与系统侧跨进程通讯，以进入到ATMS下的`enterPictureInPictureMode`函数，接着ATMS调用到`RootWindowContainer#moveActivityToPinnedRootTask`函数，顾名思义，该函数将对调用者ActivityRecord所在Task的窗口模式及其状态细节进行处理(如上图)，确保Task处于Pinned状态。随后，函数调用到`Task#sendTaskAppeared`方法，并与SystemUI(com.android.systemui)进行一次跨进程通讯，自此调用链条正式进入到系统交互接口侧(下文称UI侧)。

`sendTaskAppeared`方法与UI侧跨进程通讯后，`ShellTaskOrganizer#onTaskAppeared`接口将被调用，也可理解为应用进入PiP模式时，该接口就是UI侧首个被调用的接口。

 ![](/attachments/2024-04-24-systemui-as-evilpip/8d5ddbd6-9419-46a1-972c-5064e9e69d1f.png)

接着UI侧调用到`PipTaskOrganizer#onTaskAppeared`接口，该接口主要对调用方传入的附加PiP参数进行初始化和处理。最终，接口调用`scheduleAnimateResizePip`函数，并将处理后的PiP参数应用到系统动画上。由于后续的系统动画对于启动链并不重要，故此处不进行具体分析。总之，忽略启动链中的非关键代码片段，以上便是PiP启动过程中将触发的关键函数，且整个启动总共进行了两次跨进程通讯，下图为启动链条的时序图。

 ![](/attachments/2024-04-24-systemui-as-evilpip/b603b219-c5ee-496c-a748-98cafe3966ea.png)

### 3.5 Analyse Attack Vector

上述便是针对启动链的分析，刚才的工作主要抽离了PiP启动链中的关键函数，同时给出了对应的时序图。作为PiP完整运行链条的前半部分，对启动链的深入理解将有助于后续调试工作的进行。

在前文，研究提到了CVE-2021-0485，该EoP漏洞允许PiP模式以畸形的尺寸被启动，使得应用在无用户感知的情况下持续持有前台特权。而通过其Patch不难得知PoC是通过\<layout\>标签中的minWeight与minHeight参数直接控制活动的最小宽高的，在未Patch的API30分支下，畸形的最小宽高将被直接运用在PiP窗口上。

CVE-2021-0485的本质是利用了UI侧的视图处理缺陷，PoC实际上已经以PiP模式启动，只是通过某种方式以用户极难感知到的形式"合法"地持有前台特权，与以往获取前台特权的EoP漏洞有所不同，以往的漏洞着重于设法绕过系统侧的限制检查，破坏系统侧对后台进程的降权处理，而CVE-2021-0485则是触发了PiP模式下埋藏了六年的攻击面，由于PiP模式能够使应用通过UI侧的系统级窗体长时间持有前台特权，攻击者完全可以将复杂调用链中繁琐的限制绕过问题转化为UI侧的视图处理问题，以一种全新的方式执行EoP操作。

显然，基于前文的讨论，可以确定这是一个新型攻击向量，在此基础上进一步进行讨论，如何滥用PiP模式以启动用户无法察觉的畸形活动，本研究给出以下两种方案:

1. 攻击PiP模式的启动链，寻找方法使系统侧正常处理任务栈的Pinned状态与可见属性，但使启动链在与UI侧跨进程通讯前中断，最终获得一个不被UI侧渲染和显示，但可见状态为true的畸形活动，从而实现EoP；
2. 攻击PiP模式的UI侧，寻找并利用类似CVE-2021-0485的视图处理问题，以用户无法感知的状态持有前台特权。

方案一看起来是效果最好的EoP方案，但事实上该方案几乎不可能实现。通过前文对PiP模式启动链的分析，不难发现在`moveActivityToPinnedRootTask`方法下，系统侧一旦处理完活动的可见状态，就立刻向UI侧发起跨进程通讯，想要在跨进程通讯发起前找到相应的Trick中断链条调用几乎是不可能的事。

方案二自不必多说，但目前为止，利用PiP模式实现EoP操作的漏洞仅CVE-2021-0485一个，自此之后，PiP模式下就再也没有漏洞被公开，唯一可以直接控制UI侧视图显示的\<layout\>标签也已经不起作用，PiP模式真的安全了吗？

### 3.6 SourceRectHint To EoP

此处，研究正式进入针对UI侧的分析部分，根据谷歌提供的相关文档，PiP模式向应用层暴露了多个API以供开发者调整PiP窗口的细节。接下来将跟踪其中一个API中参数的具体流向，以分析该API将对UI侧产生何种影响。

 ![](/attachments/2024-04-24-systemui-as-evilpip/fdd3aadd-2a25-4c9e-9174-5d010595cf24.png)

[setSourceRectHint](https://developer.android.com/reference/android/app/PictureInPictureParams.Builder#setSourceRectHint(android.graphics.Rect))接口是本部分的重点，根据官方文档给出的描述，UI侧可以根据从接口传入的Rect实例指定的矩形区域自动缩放并裁剪当前Activity的内容，接着将其渲染到PiP窗口中。看起来很有意思，既然能够随意控制传入的Rect实例以影响Activity的裁剪范围，那么是否能通过传递畸形的Rect以实现类似CVE-2021-0485的攻击效果？

 ![](/attachments/2024-04-24-systemui-as-evilpip/1cd63fe7-42b2-45a6-956b-9c60adcdc34e.png)

如图所示，编写代码向接口传入一个宽高均为1的畸形Rect对象，编译PoC并运行于Android13.0.0_r7分支的AVD，不出所料，其运行后达成的效果与CVE-2021-0485类似，应用的活动窗口被裁剪并缩小至肉眼不可见的1dp大小，但该情况并没有持续多久，大概仅半秒钟后1dp的畸形窗口就恢复为大小正常的PiP窗口。

 ![](/attachments/2024-04-24-systemui-as-evilpip/38f5749d-5c0b-472c-a46c-aa715c2023eb.png)

需要注意的是，这里使用的是Android13.0.0_r7分支的AVD，而自Android13.0.0_r16以来，UI侧开始对传入的Rect进行检查，若Rect的矩阵大小小于正常窗口大小，则将Rect置空，即传入的Rect不起任何作用。如上图所示，该Patch为[ab39215](https://cs.android.com/android/_/android/platform/frameworks/base/+/ab392150d4b1460c0686186a4ddb4a472b2894c4)新增的代码，但根据其Commit Detail可知其为**功能性**补丁而非安全性补丁(非安全补丁可能不会被强制Merge到多个分支或旧版本分支)，这意味着API33的部分分支以及低于API33的全部分支仍有分析价值。

目前，已经可以利用`setSourceRectHint`接口在非最新Android分支下使Activity以1dp窗口的形式显示在屏幕顶端半秒左右。如果有任何Trick或代码逻辑上的问题可以延长1dp窗口的显示时间，甚至让1dp窗口持续驻留在屏幕顶层，那么就可以实现EoP。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c946bcc1-ab3f-4c47-90fc-c7f0c2a42c26.png)

跟踪Rect对象在`setSourceRectHint`接口内的传递路径，忽略非UI侧的启动链条，传入的Rect将在`PipTaskOrganizer#onTaskAppeared`方法中被首次取出，并被传入`scheduleAnimateResizePip`方法。根据该方法名可以推测整个PiP窗口的渲染流程以及setSourceRectHint接口导致的活动裁剪与缩放很大程度与"Animate"机制有关。

 ![](/attachments/2024-04-24-systemui-as-evilpip/0ae1aff5-0f42-46dd-a2fb-cd4bc009af17.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/bea5ecda-5e47-444a-9eae-be8f73452349.png)

随后，Rect对象通过`scheduleAnimateResizePip`传入`animateResizePip`方法，在此方法下代码实例化了一个`PipTransitionAnimator`对象以处理PiP窗体的缩放和裁剪动画，其还通过`setDuration`方法指定了整个动画的执行时长，此处指定的时长为425毫秒，这似乎可以解释为什么1dp的PiP窗口仅半秒后就恢复为大小正常的窗口的原因。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c7a91579-4326-4cea-b066-fb08d4ab897a.png)

继续审计代码，可知`PipTransitionAnimator`对象通过`setPipAnimationCallback`方法指定了一个句柄以处理动画的执行回调，该句柄便是`mPipAnimationCallback`成员。跟入审计其执行回调的具体实现。其中，其重写的`onPipAnimationEnd`接口将在UI侧渲染PiP窗口的动画执行结束后被系统调用。值得注意的是，在该接口的实现代码中，`finishResize`函数被调用，而根据其函数名与代码注释可知该函数用于调整PiP窗口的尺寸。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c8d55d2f-bcf5-41fa-8702-84ad8cd13545.png)

随之跟入`finishResize`函数。此函数代码大致处理了PiP窗口动画的相关细节，虽然部分逻辑无关紧要，但仍需要注意其中两处函数的调用:

* 其代码实例化了一个`WCT`(`WindowContainerTransaction`)对象，并将其传入`prepareFinishResizeTransaction`函数，该函数为此WCT对象设置了边界尺寸并定义了`SurfaceControl.Transaction`(`SCT`)。
* 随后，经过处理的`WCT`对象被传入`applyFinishBoundsResize`函数，而此函数中的代码将通过`mTaskOrganizer`句柄与系统侧跨进程通讯，接着将`WCT`传入系统侧`WindowOrganizerController#applyTransaction`函数。

 ![](/attachments/2024-04-24-systemui-as-evilpip/d9f0fa6f-911e-4172-96b8-824d20113d58.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/4ee029aa-ce1b-4034-b38f-d065f10a3257.png)

在`applyTransaction`函数下，WCT对象的操作变动(Change)对象被取出，并传入`applyWindowContainerChange`函数，需要注意该Change对象包含前文代码定义的SCT对象。忽略无关代码，系统侧最终触发调用者所在Task对象的`setMainWindowSizeChangeTransaction`函数(下文均称此为MWSCT)，同时在此函数下，SCT对象也被提取并执行merge操作以在屏幕上渲染相应事务。

经过Debug，该SCT对象将会让PiP窗口渲染到正常尺寸。那么此时就可以解释畸形1dp窗口最终会恢复为尺寸正常的PiP窗口的核心原因。而当前的目标是延长1dp窗口在屏幕上显示的时间，或者让1dp窗口持续驻留在屏幕上。总之先给出从动画结束回调到最终SCT渲染的大致流程图。

 ![](/attachments/2024-04-24-systemui-as-evilpip/b59523eb-18bf-487f-80fc-a0bb17e0ab72.png)

在`setMWSCT`函数中，SCT对象被直接执行了merge操作。由于没有找到阻止SCT在屏幕上进行渲染的方法，因此为了实现目前的需求，唯一可行的方法是在系统进入关键函数之前中断执行。然而，经过对整个链条的重新审计后，仍未能发现任何有效且可用的策略。因此，该链条下是否还存在其他可以利用的方式仍需进一步探讨。

 ![](/attachments/2024-04-24-systemui-as-evilpip/2830bb95-494f-4004-9f46-787d5a6eb19d.png)

直至目前，本研究审计的是API33平台，而API32平台下的setMWSCT函数代码与API33平台有较大差异，这是由于Google在Android13.0.0_r1分支下[20620bc](https://cs.android.com/android/_/android/platform/frameworks/base/+/20620bc01b14b070700eec6b530c34496e0ae3a8)提交导致的代码变动。上图为20620bc的Commit Detial，不难看出该次提交是为了适应异步系统，换言之其依然为功能性修复补丁，这代表13.0.0_r1之前的所有分支代码仍有审计价值。

 ![](/attachments/2024-04-24-systemui-as-evilpip/ce55bced-385a-4008-a69c-be50940d1900.png)

对比13.0.0_r1与12.1.0_r27(目前可访问到的Android12最新分支)分支下的`setMWSCT`函数代码，可见在13.0.0_r1分支之前，函数并没有直接对SCT对象执行merge操作，而是将其赋值给了两个全局变量，接下来进入12.1.0_r27分支，以`mMainWindowSizeChangeTransaction`成员为重点进行分析。

 ![](/attachments/2024-04-24-systemui-as-evilpip/67541ba2-b75c-4f13-8b34-b3be28a89357.png)

该成员在Task类下没有被引用或被调用，仅通过`getMWSCT`函数向外暴露。经过Debug，发现`WindowStateAnimator#setSurfaceBoundariesLocked`函数通过`getMWSCT`获取到了SCT对象，并对SCT对象执行了merge操作。虽然SCT最终还是要在屏幕上被渲染，但其触发渲染的细节与13.0.0_r1分支不同，r27分支不主动触发SCT渲染，而是通过其它调用链被动触发。Hook住`setSurfaceBoundariesLocked`函数，打印函数调用栈以进行分析。

 ![](/attachments/2024-04-24-systemui-as-evilpip/92ff6596-1c4c-489d-aec0-5d5ca8aa65de.png)

虽然输出的调用栈很复杂，但其显然与Activity的启动及绘图渲染流程相关，所以直接定位到链条最底部的`Session#relayout`函数，该函数与窗口布局更新有关。继续向上搜索链条，最终可以追溯到`ViewRootImpl#setView`函数，而此函数将在Activity创建时被系统调用，那么完整的渲染触发链条就呼之欲出了。

 ![](/attachments/2024-04-24-systemui-as-evilpip/42d3ecb7-78a4-4dee-b2f8-132c5dcf774b.png)

如上图所示，当应用进入PiP模式时，会同时触发过渡动画链与Activity重绘链，当过渡动画结束时，链条会触发回调，并最终进入`setMWSCT`函数。此时重绘链条触发`setSurfaceBoundariesLocked`函数获取SCT对象，并最终执行`merge`函数。除去PiP动画链条，Activity重绘链条为用户高度可控，所以攻击对象是显而易见的。

 ![](/attachments/2024-04-24-systemui-as-evilpip/ee5e79bc-c6fc-4746-9a2f-3034c5f2926f.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/fc2b5523-f991-41ee-9109-2d63864cf51b.png)

编写如图所示代码，输入长宽为5的Rect作为`SourceRectHint`，并在进入PiP模式后阻塞UI线程以阻止Activity重绘，运行PoC，可见由于重绘链条被阻塞，PiP窗口呈现出畸形尺寸并持续保持用户不可见状态，此时Dump任务栈，可见PoC所在任务栈被系统认为处于前台，且visible属性为true。这意味着应用已经可以在无用户感知的情况下持续获得限制豁免。

### 3.7 ActivityOptions To EoP

前面的研究旨在利用API32及以下版本的SCT渲染细节与活动重绘时的视图渲染流程，构造一个可以持续显示的畸形PiP窗体，并通过该方法成功突破了BAL限制。然而，由于Google调整了API33及以上版本的SCT渲染细节，PoC并不适用于API33+的设备。这自然是不可容忍的，所以在本节，本研究仍将继续审计PiP特性的相关代码，并最终突破API33+的BAL限制。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c403a816-1a50-4364-be23-d467704b36d4.png)

相比于API32，框架代码并非是API33中唯一产生变动的对象。根据官方文档提供的[api_diff](https://developer.android.com/sdk/api_diff/33/changes)索引显示，在API33中有大量的函数接口被添加，删除或修改，这些变动同样是研究最为关注的部分，因为接口的变动往往意味着缺陷和攻击点的引入。如上图，文档中的`ActivityOptions#makeLaunchIntoPip`函数是Google于API33新增的开发接口，根据描述可知，该函数将实例化一个特殊的`ActivityOptions`对象，开发者可以利用该对象使启动的目标Activity直接进入到PiP模式。

 ![](/attachments/2024-04-24-systemui-as-evilpip/02c856a0-0a85-4d22-bb74-21a825719caa.png)

关于ActivityOptions，此处有必要引入一些前置知识，根据框架代码对于`startActivity`接口中参数options的描述可知，该Bundle对象可以决定活动如何被启动，而`ActivityOptions`事实上就提供了`toBundle`方法将对象参数封装为Bundle实例，换句话来说，开发者可以通过调整ActivityOptions的参数来间接控制活动的启动细节(比如为启动的活动增添过渡动画)。

 ![](/attachments/2024-04-24-systemui-as-evilpip/447c7893-3c52-4e0a-9bd2-6e25e05c7fd9.png)

那么回到`ActivityOptions#makeLaunchIntoPip`，接口接收了一个由外部传入的`PIPParams`对象，并初始化了`mLaunchIntoPipParams`与`mLaunchBounds`成员，这两个成员显然是由开发者控制的参数，因此toBundle方法也将这两个成员进行了封装。在明确了`makeLaunchIntoPip`接口允许开发者控制的参数后，接下来就有必要对最终封装的Bundle及其参数进行追踪，分析其在Activity启动链中的传播路径，以及其是如何影响启动细节的。

 ![](/attachments/2024-04-24-systemui-as-evilpip/e0078eca-e078-456c-abc7-47505144d6fc.png)

将`ActivityOptions`封装为`Bundle`对象，并通过`startActivity`接口将Bundle转交给框架与系统进行处理，上图为Bundle及其参数通过传播到达的一些重要函数，很显然其传播路径与Activity启动链高度重叠。在传播链中需要关注的是封装在Bundle中的`mLaunchIntoPipParams`参数，其与欲利用的PiP特性高度关联，而链条中的`startActivityInner`函数首次将该参数取出并做了处理。

 ![](/attachments/2024-04-24-systemui-as-evilpip/58bef66e-a6af-47b9-959a-66edd929d55c.png)

在`startActivityInner`函数的结尾部分，代码调用了`ActivityOptions#isLaunchIntoPip`函数判断传入的Bundle是否封装了`mLaunchIntoPipParams`参数，显然结果将满足判断条件并使得执行进入分支内部，而值得注意的是分支内代码调用了`moveActivityToPinnedRootTask`函数。在前文的"[PiP Launch Chain](#_IV._PiP_Launch)"章节，本研究详细分析了活动进入PiP模式的启动链条，其中`moveActivityToPinnedRootTask`函数用于处理活动所在Task的各类属性，换句话说，`makeLaunchIntoPip`函数确实影响到了活动的启动细节，它可以直接将活动启动链转入PiP启动链的起始部分，使得PiP启动链直接接管活动。

而"[Analyse BAL Restriction](#_I._Analyse_BAL)"章节则分析了框架代码中BAL限制的实现部分，如前文所述，限制的核心部分在于`ActivityStarter#executeRequest`函数中的`restrictedBgActivity`成员，该成员直接影响了Activity启动链中`startActivityInner`函数的代码执行，系统将在此函数决定是否要将处于后台的任务栈移动至前台，但怪异的是，通读整个`startActivityInner`函数，`restrictedBgActivity`成员的赋值或整个应用任务栈的状态丝毫没有影响到最终`moveActivityToPinnedRootTask`函数的调用，且后续PiP启动链的运行也与这些影响因子没有丝毫关系，似乎PiP特性并不在BAL限制的管控范围之内？ 显然这将导致API33+设备的EoP漏洞。

 ![](/attachments/2024-04-24-systemui-as-evilpip/e57a97ac-9037-4dc5-ba63-13c21cd1a7f1.png)

编写如上所示代码，编译并运行于API33和API34(目前的最新版本)的AVD上，最终，在这两个版本下，PoC可以直接无视BAL限制从后台以PiP模式启动Activity。这代表着我们目前已经可以在所有Android版本上实现BAL。而在本节的最后，需要声明的是我们已于2023年1月将上述问题提交至Google VRP平台。

### 3.8 Side-Channel For Running-State

BAL是AHA技术与劫持软件最重要的部分，只要能够使任务栈移动到前台，顶替旧的任务栈，劫持攻击就能够基本实现。尽管如此，但这与精准劫持还有很大的距离。回顾前文的"[Leaking Running State](#_Leaking_Running_State)"章节，研究提到早期劫持软件会尝试使用一些侧信道方案，之后，这些方案被Google彻底禁止，劫持软件开发者开始将目光转向某些正常的系统特性，并寻找滥用正常服务或API的方案。

其中`UsageStateManager`是最常被滥用的组件，劫持软件通过该组件获取受害者应用的使用时长与电池消耗情况，并以此判断目标是否来到前台，选择时机顶替前台任务栈，这个方案目前仍能够使用，但由于使用此组件需要诱导用户手动开启一些敏感权限，这将不可避免地导致用户感知和复杂交互，所以本研究不会使用该组件实现精确劫持攻击。

**Ⅰ. Bug Or Trick**

下面的描述源自一段真实场景，这是笔者进行软件开发时遇到的Bug。开发需求很简单，其中的一个需求是: 程序需要定时绑定到某个第三方通讯软件的导出服务，从而进行数据交换。该程序稳定运行了数个版本，直到某次代码合并后，程序开始频繁崩溃。

 ![](/attachments/2024-04-24-systemui-as-evilpip/0d06af42-3d68-4ce4-8077-3449b7e47fe7.png)

根据Crash日志显示，程序出现崩溃的原因是框架抛出了`BackgroundServiceStartNotAllowedException`异常。通过分析打印的栈信息并参考官方文档，可以得知异常抛出的原因是系统限制了程序启动后台服务。然而，问题在于旧版本的代码同样启动了后台服务，但框架却未抛出该异常。因此，初步推断该问题与合并的新代码有关。

 ![](/attachments/2024-04-24-systemui-as-evilpip/789875c7-f48e-4b20-9f4c-6735db17013d.png)

根据日志定位到`ContextImpl#startServiceCommon`函数，该函数的某个分支手动抛出了上文提到的异常类型，故在此处下断点以便深入调试。最终，Bug被成功定位与复现，该问题产生的核心因素与程序对后台服务执行"绑定"或"启动"操作的时机有关。

在未合并新代码前，程序仅会在"绑定"后台服务之后的某个时刻对其执行"启动"操作，由于调用`bindService`接口绑定后台服务的操作[不受后台执行限制的影响](https://developer.android.com/about/versions/oreo/background#services)，因此在执行绑定操作后，后台服务将被成功启动，而此时利用`startService`接口对其执行启动操作则不会抛出任何异常。但在合并的新代码中，某个模块在`bindService`接口执行前就尝试启动后台服务，进而导致异常抛出与程序崩溃。

**Ⅱ. Abuse startService**

 ![](/attachments/2024-04-24-systemui-as-evilpip/f3f707a9-6591-414e-93ac-d95b2127e08e.png)

经过Debug，程序的问题已经得到解决，然而框架的安全隐患才刚刚暴露出来。前文提到，系统会限制后台服务的启动，而根据Android O的"[Background execution limits](https://developer.android.com/about/versions/oreo/android-8.0-changes#back-all)"行为变化细节，更确切的说法是，在程序未被许可启动后台服务的前提下，系统才会抛出异常。因此，问题在于"许可"的具体细节是什么？ 攻击者是否可以反向利用这些用于维持系统安全的策略？

 ![](/attachments/2024-04-24-systemui-as-evilpip/c2e5a3f9-bdcd-4908-811f-6c5e9a8afd98.png)

由于该策略与Service的启动流程高度相关，故本研究对整个`startService`流程进行了重新审计，并最终定位到`ActiveServices#startServiceLocked`函数下。该函数的某一分支实现了"许可"的具体细节。在此分支中，系统首先通过目标服务句柄的`startRequested`属性判断该服务是否为初次启动，若为初次启动，则调用`getAppStartModeLOSP`函数判断目标服务的所在进程是否存在于后台，当目标进程满足分支的全部判断条件时，代码将构造一个包名为" ？"的畸形`ComponentName`实例，并将其返回到`ContextImpl`组件内。而根据前文的分析已经可以知道，该组件在处理畸形`ComponentName`时将抛出异常提示开发者`startService`请求不被允许。

问题在于，请求丢弃后的异常并不在`SystemServer`内部进行处理，而是在应用层抛出，任何应用都可以捕获这个异常，那么这就导致了一个很明显的信息泄露问题: 恶意软件可以通过`startService`接口诱导系统调用特权函数`getAppStartModeLOSP`以探测目标进程的前后台状态。

 ![](/attachments/2024-04-24-systemui-as-evilpip/ca909185-34fd-4ebd-90f8-03afb81efe16.png)

那么对于任意一个具有导出服务的应用程序来说，仅需要简单修改前文用于复现程序Bug的PoC代码，就足以利用之以泄露目标的运行状态。

**Ⅲ. Abuse ApplicationInfo**

经过前文对startService API以及行为变动细节的分析，我们成功发现了一个可利用的侧信道漏洞，尽管该漏洞目前仍可以在最新版本的Android设备(API34)上被攻击者所利用，但我们已于2022年10月将其提交至Google VRP平台，相信漏洞很快就能得到修复。

在本节，研究将深入`ApplicationInfo`组件，并通过组件的flags属性进行侧信道攻击，从而泄露第三方应用的运行状态。与前文研究不同的是，该方案旨在滥用正常的系统接口，所以谷歌不会对"预期行为"进行修复。需要注意，目前此方案已经证实正在被地下产业滥用。

根据官方文档的描述，系统允许开发者通过PackageManager获取第三方应用的`ApplicationInfo`对象，通过此对象，开发者得以访问目标应用的部分数据，这些数据与应用清单文件内的\<application\>标签高度相关，这意味着其提供的大部分数据是无法反映运行时状态的静态数据。尽管如此，仍有少部分数据是动态变化的。以flags成员为例，该成员为整数类型，在内存空间中占4个字节，即32个比特位，每个比特位都反映了应用的某种状态，虽然大部分状态由\<application\>标签控制(静态状态)，但其中一个状态却可以在某种程度上反映应用的运行情况。该状态由flags值的第22个比特位控制，在框架代码中，该控制位以`FLAG_STOPPED`常量体现。那么此时的问题是，  `FLAG_STOPPED`是如何反映运行情况的？ 根据文档描述，该常量用以标记应用是否已经停止，而对于停止状态的定义，文档未给出具体细节。

 ![](/attachments/2024-04-24-systemui-as-evilpip/197e3f9b-42c3-48f8-a24f-5a25ce560d8c.png)

PackageParser为框架中用以解析包文件的组件，其`generateApplicationInfo`函数将在解析过程中被调用，此处暂且假设目标应用已经处于停止状态，跟入函数并观察组件做了哪些关键操作。如代码所示，组件在确认应用处于停止状态后，会将其`ApplicationInfo`实例的flags成员与`FLAG_STOPPED`常量进行一次或运算，该运算会将flags值的第22个比特位置为1，若应用仍在活动，则组件会进入另一个分支进行与运算，把该比特位置为0，接着，系统会将处理后的`ApplicationInfo`实例返回，此时开发者则可以通过返回实例的flags成员查询应用的各种状态。

 ![](/attachments/2024-04-24-systemui-as-evilpip/609f622a-398e-4316-846b-31f05e20e703.png)

应用的停止状态是个重要因素，它将直接影响PoC在观测目标运行情况时的适用范围。在包管理组件中，`setPackageStoppedState`接口用以标记目标应用是否停止，而在原生AOSP框架下，该接口仅在AMS#forceStopPackage函数中被系统调用且传入True值，这意味着只有通过设置面板来强行停止目标应用，才能手动将其标记为停止状态。然而，大部分用户在关闭应用程序时，不会执行如此繁琐的操作，相反，用户通常会在"最近任务"视图中删除应用任务栈以"关闭"目标，该操作会触发系统调用`AMS#killProcessesForRemovedTask`函数，尽管此操作可以使系统终止应用的大部分进程组，但由于该函数的整个调用过程没有使用到`setPackageStoppedState`接口，即便目标进程全部死亡，也不代表目标会被标记为"停止"。

所以，在载有原生AOSP系统的移动设备上(例如Pixel手机)，滥用ApplicationInfo的侧信道技术几乎无法提升劫持攻击的精度，由于无法捕获到常规意义上应用被"关闭"的时刻，PoC在大部分时间都无法确定劫持目标的时机。但是在客制化Android系统上，停止状态的适用范围似乎发生了变化。

 ![](/attachments/2024-04-24-systemui-as-evilpip/7eaaf334-39a5-4243-b9e7-cb350b25d1e0.png)

由上海科技大学及相关机构发表的论文《VenomAttack: automated and adaptive activity hijacking in Android》([10.1007/s11704-021-1126-x](https://link.springer.com/article/10.1007/s11704-021-1126-x))则验证了这一点。该论文利用了2015年Usenix安全顶会上提出的任务栈劫持技术([10.5555/2831143.2831203](https://dl.acm.org/doi/10.5555/2831143.2831203))以攻击第三方应用，虽然文中的大部分攻击方案现已不适用于Android Q+的设备，但论文的4.6章节"Attack at the right timing"验证了在高版本客制化系统上滥用ApplicationInfo仍具有可行性。该章节指出，多个主流厂商的客制化系统(例如Xiaomi，Huawei)会由于用户的多项行为而导致应用的"停止状态"发生改变，这些行为包括从"最近任务"视图中删除应用任务栈以及从Home界面点击应用图标。而在前文的研究中可以得知，这类操作在原生系统上是无法影响应用的"停止状态"的。论文指出，这可能是由于设备厂商在定制系统时误解了FLAG_STOPPED常量的含义而导致的。

 ![](/attachments/2024-04-24-systemui-as-evilpip/62bc44d6-01f8-4384-96e4-1dc22ca6af1c.png)

针对在客制化系统上出现的此类情况，本研究与论文持有不同的解释。以Xiaomi的MIUI14系统为例，从"最近任务"中删除目标，日志将打印出如上图所示的内容。"SwipeUpClean"是MIUI框架对此行为命名的TAG，在对系统简单调试后，发现该行为会触发此Jar包下代码: /system/system_ext/framework/miui-services.jar。包内`handleSwipeKill`函数将被调用以处理"SwipeUpClean"行为。

 ![](/attachments/2024-04-24-systemui-as-evilpip/ab09944c-13c2-4ce6-a1de-5cbfea891781.png)

随后，代码触发`killOnce`函数，如图中实现的Smali代码，该函数最终将调用系统下的`AMS#forceStopPackage`接口以强行停止目标应用程序。此时关联前文研究就不难解释为什么这种行为会改变应用的"停止状态"。Xiaomi的客制化系统对于后台进程的管控十分严格，个人开发者不止一次反馈应用进程几乎无法在MIUI系统的后台进行存留(即使进程启动了前台服务)，这种情况很大概率与系统大量使用"强行停止"来管理进程有关，换言之，并非是系统开发者误解了`FLAG_STOPPED`常量的含义，而是"强行停止"的使用范围被扩大了，即这种情况本身为预期行为。那么其它厂商的客制化系统是否存在"强行停止"被扩大使用的情况？ 除去论文已经测试过的Huawei厂商，本研究额外测试了Oppo，Vivo，Realme等第三方客制化系统，最后发现这些系统均会因为删除任务栈而强行停止应用，这或许说明滥用ApplicationInfo的侧信道技术可以在大部分严格管控后台进程的客制化系统上使用。

## 四、Breaking LMKD & BEL

在本白皮书的前半部分，研究对Android系统的多个基础组件与安全策略进行了深入分析。通过利用数个组件中存在的安全缺陷与特性，研究成功实现了针对现代Android设备的精确劫持攻击。然而，这距离最终的武器化阶段，仍存在着名为"持续化"的最后一公里。

### 4.1 Privilege Process & High Priority

所有Android恶意软件的终极梦想是，一旦感染目标设备，就能够永久地在后台稳定运行，保持进程高优先级并突破系统上所有的内存优化手段，即使进程被用户强制停止，也能如细菌一样在短时间内fork出大量子进程以持续运行在Android设备上。

在早期Android系统，大多数恶意软件的确可以利用AOSP中的代码缺陷和部分设计问题做到如此骇人的效果，但随着谷歌不断发布安全补丁，调整框架代码，并且在API26正式实施了'[后台限制策略](https://developer.android.com/about/versions/oreo/background#services)'，不仅是恶意软件，即使是正常的软件开发者，都不可能奢求软件在无用户交互甚至无用户感知的条件下持续运行在后台。

**Ⅰ. Privileged Process & OOM_ADJ_SCORE**

在白皮书的"[Persistently Background Process](#_Persistently_Background_Process)"章节中，研究曾提到，精确劫持的关键是完整可用的利用链条，而其前提是进程本身的持续性，恶意进程需要不间断地收集受害者进程的运行状态，以确定最佳的劫持时机，为了使这类收集行为不被用户察觉，进程必须在后台静默运行。然而，由于谷歌对后台运行策略进行了严格限制，进程一旦进入后台，将会被系统认为处于"idle"状态，并且在接下来一段很短的时间窗口内被LMKD优化，最终导致进程被迫停止。而在这种极端情况下，想要恶意软件在后台保持稳定运行甚至绕过系统的内存优化手段，其首要条件是使进程持有高优先级，因此，可以在无用户感知的情况下提升进程优先级的框架漏洞对于最终的武器化阶段就显得极为重要。

 ![](/attachments/2024-04-24-systemui-as-evilpip/8ef80074-33f4-4ef1-89bf-5680bdfc335c.png)

根据Android Developer文档中[Low-memory killer](https://developer.android.com/topic/performance/memory-management#low-memory_killer)条目的相关说明可知，当kswapd无法为系统分配足够的内存时，内核将调用LMKD杀死部分进程以释放足够的内存空间，而LMKD将通过进程优先级来区分哪些进程应该被杀死。

 ![](/attachments/2024-04-24-systemui-as-evilpip/e189146d-028f-49c2-add0-c49787916cb4.png)

如文档所述，进程的优先级又通过进程的"oom_adj_score"来决定，而此值最高的后台类进程其优先级最低，该类进程将最先被LMKD杀死以释放内存，换句话来说，如果恶意软件既想要在后台运行，又要保持其进程的高优先级，在不考虑框架漏洞的情况下，几乎只能采用谷歌为开发者提供的解决方案:'[前台服务](https://developer.android.com/guide/components/foreground-services)'。

虽然该官方方案可以解决后台低优先级的问题，但使用该方案的前提是应用必须使用[startForeground](https://developer.android.com/reference/android/app/Service#startForeground(int,%20android.app.Notification))方法创建一个Notification实例以告知用户自身进程正在运行，而用户也可以通过该Notification实例进入应用的设置页面以强行停止应用。而被用户感知进程正在后台运行显然不是恶意软件，尤其是间谍软件想要的，更何况用户可以通过Notification实例随时停止自己。那么提升进程优先级的渠道真的只有"前台服务"这一条路可走吗？

 ![](/attachments/2024-04-24-systemui-as-evilpip/d2a05769-0e70-46aa-8ed5-df5833bc55e7.png)

以API33为例，分析框架中的`OomAdjuster#computeOomAdjLSP`函数，顾名思义，该函数用于计算特定进程的`oom_adj_score`，而在该函数中存在如上图所示的代码片段。通过观察代码不难得知，该函数还将绑定到进程的其他进程一并作为计算score的影响因素。

若不考虑特殊情况，代码在确定进程当前的score大于前台进程指定的score后(oom_adj_score越大，则进程优先级越低)，代码将进入一个分支，在该分支中代码将绑定到进程的绑定方其score(即clientAdj成员)与可见进程指定的score进行对比，并从这二者中取出score最大值作为进程接下来的`oom_adj_score`。

 ![](/attachments/2024-04-24-systemui-as-evilpip/06bbe37b-e5c1-4e16-9423-06a813f15d7d.png)

那么，如果有方法使优先级足够高的进程甚至是系统持久性进程绑定到自身，在最好的情况下，应用将可以获得与可见进程同等级别的`oom_adj_score`。此时不妨进行一个假设，AOSP中存在着某种攻击面，可以让某个系统持久性进程绑定到自身。

 ![](/attachments/2024-04-24-systemui-as-evilpip/114a0419-60c2-4632-8f46-91818e8fd1b1.png)

框架层中，有这样一类特别的组件: `Manager`。该组件是多个组件的统称，例如`ActivityManager`，`WindowManager`等等都属于`Manager`组件，而应用进行的大部分操作(启动Activity，发送广播…)最终都需要由`Manager`进行处理。但值得注意的是，框架层并非直接与`Manager`进行交互，其首先通过组件对应的`IBinder`对象与内核态`binder`进行交互，最终由特权进程`system_server`接管Manager以处理相关操作。

也就是说，框架层中的`Manager`最终将以特权进程`system_server`的身份运行，而Android平台上的很多基础组件(例如Activity，Service等等)都要求App通过框架间接与Manager进行交互，这将导致一个安全隐患: Manager中出现的任何纰漏都可能影响system_server，甚至可能允许攻击者通过该特权进程造成EOP。那么，以特权身份运行的Manager会通过哪些方式与应用层进行交互？ 这些交互方式是否有可能被滥用？

以`AccessibilityService`组件为例，此组件是AOSP框架向应用层暴露的服务接口，应用可通过接口与系统内的特权服务组件`AccessibilityManagerService`进行一定程度上的交互。根据`AndroidDeveloper`文档所述，若应用想要向系统申请无障碍服务，就必须在`AndroidManifest`中申明一个特殊的Service组件，该组件必须可以处理指定的系统Intent。其Intent对象的Action值为`AccessibilityService`组件中`SERVICE_INTERFACE`常量的具体值。

 ![](/attachments/2024-04-24-systemui-as-evilpip/c869f966-a0c6-4c9d-ba94-6a40ba9e714e.png)

接下来，Manager中负责无障碍服务部分的函数[AccessibilityManagerService# updateServicesLocked](https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java?q=func:updateServicesLocked%20filepath:AccessibilityManagerService)将会实例化一个`AccessibilityServiceConnection`对象，接着代码将调用该对象下的`bindLocked`函数以绑定目标应用中特定的Service组件。由于`Manager`是以`system_server`的身份运行的，那么在绑定目标Service时，就相当于特权进程`system_server`对目标进程进行了绑定。

 ![](/attachments/2024-04-24-systemui-as-evilpip/498f43be-e0b8-4a71-97e5-c7fd702f54e7.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/89d0609d-1b8f-419e-9774-5e4f6d7659d8.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/66dd913a-64e5-4850-8e76-e2bc70956176.png)

简单编写一个无障碍服务应用，并在设置面板中允许该应用的无障碍权限，可以发现应用已经被`system_server`绑定了。由于该进程为系统持久性进程，故其`oom_adj_score`为-900，即系统级优先级，那么根据`OomAdjuster#compute-OomAdjLSP`函数的运行逻辑，被绑定进程将获得可见进程级别的优先级，即score=100，由于该值属于高优先级，故该进程被LMKD优化的可能性极小。

**Ⅱ.  Abuse AccountManager**

显然，被设计用以向应用层提供服务的Manager会通过某些方式绑定非特权进程，那么`system_server`内的攻击面便呼之欲出了。只不过，上一节提到的无障碍服务并不适合作为提升进程优先级的最佳方案，由于无障碍特权服务允许进程随意控制与模拟用户操作，授予该服务将导致应用取得极高的特权，所以其授权行为受到系统的严格管控，应用主动申请该特权需要多次交互并引导用户在设置面板中进行复杂操作，第三方设备厂商甚至会在该特权授予前强制用户确认长达10秒的风险警告按钮，而本研究最终需要达成的效果是无用户感知的优先级提升，无障碍服务显然不能被滥用。那么是否存在无需授权即可使用的特权服务？

 ![](/attachments/2024-04-24-systemui-as-evilpip/c199e379-b907-4aeb-b1de-aecd3c440fc1.png)

`AccountManager`为框架向应用层暴露的一个特殊的`Manager`组件。根据[官方文档](https://developer.android.com/reference/android/accounts/AccountManager)相关条目的描述，为了方便集中管理用户在设备内存储的在线账户与凭据信息，Google于API5(2009年)提供了`AccountManager`接口以供应用使用，接口可以通过简单的交互为用户提供存储的关键数据。而系统内与此接口进行对接的特权服务`AccountManagerService`，在下文称之为账户服务。

为了方便应用与系统进行对接与交互，框架额外为开发者提供了抽象组件[AbstractAccountAuthenticator](https://developer.android.com/reference/android/accounts/AbstractAccountAuthenticator)。组件文档提到，当应用需要与账户服务进行交互时，需要在重写的`onBind`方法内返回由该组件封装的`IBinder`对象，接着，应用就可以通过组件内置的数个接口与系统进行数据交换。有意思的是，文档同样要求应用为导出的`Service`组件配置意图过滤器，这与无障碍服务的前置配置需求是一致的。那么，应用申请系统的账户服务是否也要求用户进行复杂的授权操作？

 ![](/attachments/2024-04-24-systemui-as-evilpip/23460f64-d051-4b0d-91c3-6a28dcb33422.png)

观察`AccountManager`组件，其提供了数个用以操作账户信息与类型的接口。以开发文档给出的第一个接口`addAccount`为例，首先审计此接口代码，观察应用如何通过该接口与系统交互。

 ![](/attachments/2024-04-24-systemui-as-evilpip/cf24f739-ca8e-4e3b-bc85-d4392f1e627d.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/02171d09-f06d-484d-9717-41b2d8c74210.png)

 ![](/attachments/2024-04-24-systemui-as-evilpip/5fc00c96-5abd-46c6-aa5e-07ac21f1cb42.png)

`addAccount`接口内，代码首先实例化抽象任务对象`AmsTask`以执行异步操作， 其`doWork`接口会在任务启动后被执行，随后，接口内代码将立即调用`AccountManagerService#addAccount`函数并传入相关参数。忽略无关代码，系统将执行进入`addAccountAndLogMetrics`函数，在该函数内，`Session`对象将被实例化，系统会在对象实例化完成后调用其内部的`bind`函数。 接着，`bind`函数会调用`Session`对象内的私有方法`bindToAuthenticator`执行最后一步操作。私有方法内，代码将实例化带有指定Action与`ComponentName`的`Intent`对象，随后调用`system_server`的上下文对该Intent执行`bindServiceAsUser`操作。而经过后续调试，Intent对象内的`ComponentName`实际上指向的正是最初`AccountManager#addAccount`函数的调用方主动导出的用以与账户服务对接的`Service`组件。前文曾提到，官方文档要求开发人员为导出组件配置特定的意图过滤器，而其Action正是配对此处代码内的`Intent`对象。显然，该私有方法是应用与系统进行交互前要执行的最核心的步骤，只有系统绑定应用主动导出的服务，才能通过特定的`IBinder`对象进行数据交换，更重要的是，从最初的`addAccount`函数直到执行进入此私有方法，框架与系统均没有要求额外的授权操作! 这意味着应用已经可以通过`AccountManager`在无用户感知的情况下提升自身的进程优先级。

## 五、IN THE END

至此，针对现代Android设备的AHA与界面劫持攻击已经完成。本报告为了实现这一目标，在极其有限的条件内将攻击面与利用面拓展到了`SystemUI`，`SystemServer`，`ActivityManagerService`，`PIP`等各种持有特权的组件，并最终完成对这些组件的利用，突破了Google这些年来为阻止界面劫持而实施的所有安全策略。最终，一个完全无需任何特权，无用户感知的利用程序将向您展现。
