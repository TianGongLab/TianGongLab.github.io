---
slug: tiangongarticle034
date: 2024-06-12
title: macOS 中四类 TCC BYPASS 绕过案例分析
author: fmyy
tags: [macOS, TCC]
---


## 一、前言

TCC 由 Apple 于 2012 年在 macOS Mountain Lion 上推出，其主要目的是帮助用户配置其应用的隐私设置，当用户引应用请求类型在 TCC 数据库中有记录，则会通过TCC数据库的校验来进行判断是否通过，如果没有则会向用户进行提示申请对应的访问权限。

同时macOS在对用户隐私保护的同时，TCC的保护是其中一个比较重要的点，更新了众多的缓解措施及预防手段。

<!-- truncate -->

## 二、结构

用户通常在 macOS 中的"系统偏好设置"下对其进行管理（系统偏好设置 > 隐私与安全性）

 ![](/attachments/2024-06-12-macos-tcc-bypass/dc6bfc6f-8132-483d-b85c-6904ff3e9bf0.png)

当应用试图执行对隐私访问的行为时，则会触发用户授权，当用户授权之后则会在打开对应的控制开关。

而当系统启动之后，在系统进程中则会出现两个进程，分别以root权限运行的和当前用户权限运行的同一可执行文件，即是用于管控隐私权限的TCC守护进程。

 ![](/attachments/2024-06-12-macos-tcc-bypass/8fa7a339-de80-4187-9336-34ab41b7940c.png)

守护进程主要负责处理应用程序对系统资源的访问权限控制，而它会通过访问或者修改如下对象数据库文件来记录用户应用程序的相关隐私特权。

 ![](/attachments/2024-06-12-macos-tcc-bypass/ae799508-1ca5-4759-b760-319376f8ed57.png)

* **用户特定数据库：**包含仅适用于特定用户配置文件的存储权限类型；它保存在\~/Library/Application Support/com.apple.TCC/TCC.db下，拥有该配置文件的用户可以访问;
* **系统范围的数据库**：包含适用于系统级别的存储权限类型；它保存在

  /Library/Application Support/com.apple.TCC/TCC.db下。

macOS系统中通过codesign命令查看目标应用或者可执行文件的签名或者权限。

```bash
fmyy@Macbook_M1 UserFrameworks % codesign -dv --entitlements - /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
Executable=/System/Library/PrivateFrameworks/TCC.framework/Support/tccd
Identifier=com.apple.tccd
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=6055 flags=0x0(none) hashes=179+7 location=embedded
Platform identifier=15
Signature size=4442
Signed Time=Feb 10, 2024 at 20:26:27
Info.plist entries=13
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=1 size=64
......
    [Key] com.apple.private.tcc.allow
    [Value]
        [Array]
            [String] kTCCServiceSystemPolicyAllFiles
    [Key] com.apple.private.tcc.manager
    [Value]
        [Bool] true
    [Key] com.apple.rootless.storage.TCC
    [Value]
        [Bool] true
```

`com.apple.private.tcc.allow`键值下则会存在系统允许的行为，具有访问对应TCC保护对象的属性权限。上图所示"kTCCServiceSystemPolicyAllFiles"属性则是属于TCC最高权限之一，即全磁盘完全访问控制权限，作为管理TCC相关请求的守护进程，必须存在此属性。

当然具有`kTCCServiceSystemPolicyAllFiles`属性的应用并不止有守护进程所持有，macOS系统十分庞大，具有此权限的自带应用并不少见，而这些应用亦是攻击者所特别关注的对象，如果有能力劫持应用的执行流，则可以拥有对应的TCC特权，抑或是控制应用相关未授权的接口或行为达到篡改用户配置文件的行为。

## 三、相关漏洞分析

### 3.1 注入攻击类

`Hardened Runtime`是一种`MacOS`应用程序安全保护和资源访问，用于保护和防止某些漏洞利用。

`com.apple.security.cs.allow-dyld-environment-variables` 是 macOS 中的一项权限，用于控制应用程序是否允许在其运行时设置动态链接器（dyld）环境变量。

`com.apple.security.cs.disable-library-validation` 是 macOS 中的一项权限，用于控制应用程序是否允许禁用对动态链接库（库文件）的验证。

#### CVE-2023-26818 - Telegram Dylib注入攻击

在App Store中上传的Telegram应用程序并没有施加严格的安全措施，可以导致DYLIB注入攻击。

 ![](/attachments/2024-06-12-macos-tcc-bypass/87814a6b-fe3a-4567-8756-d696ba213bb0.png)

根据对应的权限配置的diff，其中删除了`com.apple.security.cs.disable-library-validation`的权限，并启用了Sandbox的安全机制,macOS应用则会根据Application Sandbox的规则进行限制。

 ![](/attachments/2024-06-12-macos-tcc-bypass/fd0c22ed-6be4-4852-85cd-cdd7949cdb28.png)

同时开启了Hardened Rumtime的标志位，因此阻断了通过加载指定DYLIB进行注入。

注入攻击所采用的环境变量为DYLD_INSERT_LIBRARIES。

```c
#import <Foundation/Foundation.h>
__attribute__((constructor))
static void telegram(int argc, const char **argv) {
    NSLog(@"[+] Dynamic library loaded into %@", argv[0]);
}
```

创建如上内容的文件，并使用GCC编译为DYLIB库文件。

```bash
gcc -dynamiclib -framework Foundation telegram.m -o telegram.dylib
```

通过在启动应用之前，控制环境变量DYLD_INSERT_LIBRARIES的值。

```bash
DYLD_INSERT_LIBRARIES=telegram.dylib /Applications/Telegram.app/Contents/MacOS/Telegram
```

#### CVE-2021-30654 - GarageBand 加载库代理攻击

`com.apple.private.security.clear-library-validation` 属性于 macOS 10.15.2 上引入，用于取代以前`com.apple.security.cs.disable-library-validation`在系统二进制文件上使用的权利,影响大致相同,原属性依旧保留，但它们的工作方式不同，后者会强制开启库验证，只有通过csops系统调用主动禁用库验证。

若还想要进行注入恶意执行流，通过控制DYLD_INSERT_LIBRARIES变量已不再可行，而通过当前App执行时的加载库或插件，进而向目标应用程序执行代理攻击则是新的一种方式。

```shell
$ codesign -d --entitlements - /Applications/GarageBand.app
Executable=/Applications/GarageBand.app/Contents/MacOS/GarageBand
[Dict]
    [Key] com.apple.application-identifier
    [Value]
        [String] F3LWYJ7GM7.com.apple.garageband10
    [Key] com.apple.private.security.clear-library-validation
    [Value]
        [Bool] true
    [Key] com.apple.private.icloud-account-access
    [Value]
        [Bool] true
```

可以发现此处存在 `com.apple.private.security.clear-library-validation` 权限。

```shell
$ otool -L /Applications/GarageBand.app/Contents/MacOS/GarageBand
/Applications/GarageBand.app/Contents/MacOS/GarageBand:
    @rpath/MAGUI.framework/Versions/A/MAGUI (compatibility version 1.0.0, current version 5753.0.0)
    @rpath/MAMachineLearning.framework/Versions/A/MAMachineLearning (compatibility version 1.0.0, current version 5753.0.0)
    @rpath/MAMusicAnalysis.framework/Versions/A/MAMusicAnalysis (compatibility version 1.0.0, current version 5753.0.0)
    [...]
```

通过otool -L 工具可以查看对应程序会加载的所有framework框架依赖。

`install_name_tool` 是 macOS 上的一个命令行工具，用于修改可执行文件或动态链接库中的库文件路径。

`install_name_tool -change old_path new_path executable`

* `old_path` 是当前库文件的路径，它将被修改为新的路径。
* `new_path` 是要替换为的新库文件路径。
* `executable` 是要进行修改的可执行文件或动态链接库的路径。

 ![](/attachments/2024-06-12-macos-tcc-bypass/9fdf8c19-f06b-4392-adee-8d347ae543d7.png)

当动态链接器加载该共享库(自定义OAuthClient)时，会通过`LC_REEXPORT`指向路径加载原OAuthClient的相关导出函数，用于GarageBand的正常运行。

当启动迁移到 `/tmp`目录下的GarageBand应用程序时，则会触发代理攻击，加载的当前App包中的Framework会执行恶意代码，恶意代码即可使用GarageBand应用程序本体所具有的`com.apple.private.icloud-account-access`权限。

当然在前面所述的两个属性之外，另有`com.apple.security.get-task-allow`属性允许调试器attach进程等特殊权限，都可能导致应用控制流的修改并行使应用所具有的TCC权限。

#### 启动约束

在严格限制应用所具有的属性的另一侧，Apple依旧会应对利用手段的场景进行缓解，因此若应对第二种需要迁移应用到/tmp目录的利用行为，在macOS Ventura发布时，Apple引入了启动约束(Launch Constraints)的缓解措施。

例如当我尝试将Music.app拷贝到`$TMPDIR`目录打开时，会提示无法打开。

 ![](/attachments/2024-06-12-macos-tcc-bypass/fa69b59d-7974-4771-ba44-d01f73239808.png)

查看日志流可以发现如下的日志信息：

 ![](/attachments/2024-06-12-macos-tcc-bypass/c40700a5-4e1f-4746-919c-31c4d4bfbbbc.png)

在经过AMFI检测的时候，出现了`Constraint not matched`的问题，可知相关检测流程是在AMFI中实现并导致启动过程的阻断。

在macOS系统中，每一个二进制可执行文件都分配对应的约束类别，在信任缓存中定义了多种约束类型。信任缓存是所有系统二进制文件、它们的哈希值以及它们的启动约束类别的列表。各种启动约束类别在 AMFI（AppleMobileFileIntegrity）中引入，因此启动约束缓解的施行，在利用过程中，极大减少了上述攻击场景的利用。

### 3.2 通过控制用户主目录加载自定义TCC数据库

在之前所描述TCC权限记录中，有提到一点，用户和系统是分为两个TCC.db的数据库文件进行管理记录相应服务或者服务的TCC规则。

当然，这些目录都不是可以轻易访问修改的，但是如若攻击者可以自定义加载构造的恶意TCC数据库，则可以让权限发生变化，即可以控制自定义应用具有FDA（FullDiskAccess）权限，从而实现全磁盘访问。

#### CVE-2020–9934

TCC 守护程序通过 `launchd` 启动，在当前用户域内运行，但是当launchd启动守护进程时，忽略了对$HOME变量的校验。

```bash
launchctl setenv HOME /PATH/TO/CUSTOM_HOME
```

因此可以通过直接设置用户域中的环境变量，替换当前用户域的主目录路径，而守护进程在重启之后，则会通过加载当前用户域的$HOME环境变量来加载对应目录中的TCC数据库。

**$: /CUSTOM_HOME/Library/Application Support/com.apple.TCC/TCC.db**

目前则是通过**getpwuid()** 函数动态的读取当前用户的相关主目录信息，而不是如之前一般从launchd的启动环境中读取。

#### CVE-2020-27937

当前，前一种情况也是比较特殊的，直接修改了守护进程启动之前的主目录。而除此之外，有如下这类特殊的应用，通过codesign命令查看其具有的TCC权限，可以发现存在`kTCCServiceSystemPolicySysAdminFiles`属性，而此属性的作用则是允许用户更改NFSHomeDirectory路径，即用户主目录路径。

```none
Executable=/System/Library/CoreServices/Applications/Directory Utility.app/Contents/MacOS/Directory Utility
Identifier=com.apple.DirectoryUtility
Format=app bundle with Mach-O universal (x86_64 arm64e)
CodeDirectory v=20500 size=1755 flags=0x0(none) hashes=44+7 location=embedded
...
[Dict]
    [Key] com.apple.private.tcc.allow
    [Value]
        [Array]
            [String] kTCCServiceSystemPolicySysAdminFiles
```

通过修改`NFSHomeDirectory`属性并重启TC守护进程，即可通过对应的`NFSHomeDirectory` ，目录索引对应的自定义TCC数据库。

 ![](/attachments/2024-06-12-macos-tcc-bypass/76e1054e-d465-46cc-be5b-d3c2eee975cd.png)

当时，在macOS上各种缓解还没施行之前，可以通过代理攻击或替换插件等行为进行劫持程序执行流,同时此应用未开启Hardened Runtime强化运行。

当进行代理攻击之后，则会通过使用`kTCCServiceSystemPolicySysAdminFiles`权限作出修改主目录的行为。

通过上述恶意行为，可以修改`NFSHomeDirectory`变量对应路径指向，在重启用户TCC守护进程之后，则会加载`NFSHomeDirectory`路径所对应的TCC.db数据库文件，从而导致用户TCC守护进程读取伪造的应用特权。

#### CVE-2023-40424

而在各种缓解措施之后，系统App层的代理攻击已经濒临灭绝，但是有一点可知，若是依旧能修改主目录指向自定义路径，依然可以加载自定义TCC数据库。

而在macOS Sonoma系列发行之后，存在如下变动：

```plain text
In Ventura user's TCC.db was "global" 
(e.g.: access to Documents = all users' Documents) but Sonoma this is per user
```

在Sonoma版本中，用户的TCC特权进一步隔离保护，用户间相互独立，每个用户具有自身的访问控制，当前用户是无法轻易的访问到其他用户目录中的相关隐私数据。

而漏洞则是由于在新用户进入系统之时，则会通过预先指定的`NFSHomeDirectory`所对应路径进行加载自定义的配置文件，其中守护进程自然会加载目录中可以由攻击者自定义控制的TCC.db数据库文件，从而达到隐私绕过。

通过`sysadminctl`  创建用户并指定 **\<HOME Directory\>**

`sudo sysadminctl -addUser username -password password -home /path/to/custom_home`

```bash
sudo dscl . -create /Users/username
sudo dscl . -create /Users/username UserShell /bin/zsh
sudo dscl . -create /Users/username RealName "Full Name"
sudo dscl . -create /Users/username UniqueID 555
sudo dscl . -create /Users/username PrimaryGroupID 20
sudo dscl . -create /Users/username NFSHomeDirectory /path/to/custom_home
sudo dscl . -passwd /Users/username password
```

抑或通过 dscl命令进行创建用户并设置对应 **\<NFSHomeDirectory\>** 来进行加载自定义TCC.db

同时，也可以通过模板库中预先存放指定TCC数据库文件，新用户创建时则会加载对应路径中的自定义文件。

```plain text
echo "++ Copy TCC database to Templates"
mkdir -p /Library/User\ Template/Non_localized/Library/Application\ Support/com.apple.TCC
cp /private/tmp/TCC.db /Library/User\ Template/Non_localized/Library/Application\ Support/com.apple.TCC/
```

苹果在 macOS Sonoma 中采取了双重修复措施：

首先，用户级 TCC 数据库不会授予您访问其他用户私人文件的权限，因此控制了其他用户的TCC数据库，亦是没有办法去访问其他用户的敏感信息；

其次，首次登录时将创建一个新的 TCC 数据库；因此，任何先前创建的文件都将被系统删除，从利用场景的情况下隔绝了例如通过提前往模板库中存放伪造的TCC数据库文件达到TCC隐私权限的绕过的利用行为。

### 3.3 通过挂载文件系统绕过隐私保护

#### CVE-2020-9771

因为所有 用户都可以创建本地的APFS文件系统快照，而同时TCC隐私保护对安装的系统快照没有强制执行保护，通过挂载系统快照并让文件或者目录忽略所有者，则能够直接访问系统所有隐私信息。

1. 手动建立新的系统快照

    ```bash
    n00b@mac Messages % tmutil localsnapshot
    Created local snapshot with date: 2019-11-17-141812
    ```

2. 配合noowners标志位，指定上述所创建的快照，以只读形式挂载。此处noowners标志位的作用则是忽略所有者信息，挂载之后的所有文件和目录将被系统认为是当前有效用户所拥有。

    ```bash
    n00b@mac Messages % mount_apfs -o noowners -s com.apple.TimeMachine.2019-11-17-141812.local /System/Volumes/Data /tmp/snap
    mount_apfs: snapshot implicitly mounted readonly
    ```

3. 挂载之后则可以以低权限从挂载目录进入实现全盘敏感数据访问。

#### CVE-2021-1784

因为Sandbox/TCC对于某些敏感目录没有安装保护，所以比如`~/Library/Application Support/com.apple.TCC`此目录，存放了当前用户的TCC规则的数据库文件，直接访问是不可行的，但是正如之前所述，没有安装保护。

因此此处允许攻击者通过挂载自定义镜像到该目录 `~/Library/Application Support/com.apple.TCC`，并在自定义镜像中提前布局好对应路径相关的文件，则通过重启TCC守护进程则可以加载镜像中的自定义TCC数据库。

```bash
hdiutil attach -owners off -mountpoint ~/Library/Application Support/com.apple.TCC/ MyImage.dmg
```

之后则出现了 另一个漏洞，即**[CVE-2021-30808](https://theevilbit.github.io/posts/cve-2021-30808/)**，该漏洞是是通过挂载 `~/Library/`来进行控制的，异曲同工之妙。

而如今再次尝试挂载此目录，则会返回权限错误的信息，并通过查看日志，可以发现如下信息：

```javascript
kernel: (Sandbox) System Policy: diskimages-helper(10387) deny(1) file-mount /Users/admin/Library/Application Support/com.apple.TCC
```

可知，目前加上保护之后，则直接限制了挂载镜像的恶意行为，目前为止，大多数的目录都已经被官方进行了保护。

#### CVE-2022-22655

TCC 的位置服务允许的客户端列表位于`/var/db/locationd/clients.plist` 文件中，此文件此前则已经被`Sandbox/TCC`保护，root用户也无法直接修改其中的内容。

正如之前所述，同样此目录`/var/db/locationd`是没有安装保护，因此可以通过挂载自定义镜像到该目录，从而可以直接控制locationd目录中的文件，例如前面所说的 clients.plist文件，从而允许自定义的客户端访问位置服务。

随着macOS的日渐更新，文件系统绝大多数已经被保护了，当尝试挂载的时候则会直接被Sandbox拒绝。

### 3.4 应用｜服务的文件的操作行为 → FDA

当前，在前面所述的情况之外，还有其他行为可以实现FDA(FullDiskAccess)全磁盘访问的权限，此处则是分四种情况解释一下如何通过不严格的文件操作的行为，构造恶意行为，导致借用特权应用的权限进而修改TCC数据库文件。

#### CVE-2023-38571 - 通过应用程序本身的文件行为

该漏洞发生于 **/System/Applications/Music.app/Contents/MacOS/Music** 系统应用的音乐应用中。

```bash
fmyy@Macbook_M1 Applications % codesign -dv --entitlements - Music.app 
Executable=/System/Applications/Music.app/Contents/MacOS/Music
Identifier=com.apple.Music
Format=app bundle with Mach-O universal (x86_64 arm64e)
[Dict]
...
    [Key] com.apple.private.tcc.allow
    [Value]
        [Array]
            [String] kTCCServiceAddressBook
            [String] kTCCServicePhotos
            [String] kTCCServiceAppleEvents
            [String] kTCCServiceCamera
            [String] kTCCServiceMediaLibrary
            [String] kTCCServiceSystemPolicyAllFiles
...
```

Music.app中会有一个文件操作的行为，将`~/Music/Music/Media.localized/Automatically Add to Music.localized`目录下的音频文件导入到用户媒体库中，而Music.app在处理无法识别的音频文件时，则会将该目录下的音频文件移动到当前目录下的**\~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized** ，用于存放未导入的音频文件。

而其中会在`**Not Added.localized**`目录下创建一个以当前时间节点作为名称的目录，例如`*/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`。

而在上述行为中，用于实现文件移动的函数则是通过rename函数来进行的。

```c
#include <stdio.h>
int rename(const char *old, const char *new);
```

而同时，在rename拷贝的期间，攻击者有如下四种可控制的内容：

1. 源文件名
2. 目标文件名
3. 移动文件中内容
4. 对`2023-09-25 11.06.28`目录的控制权

```bash
a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"
b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3
```

例如，Music应用在操作过程中，存在rename(a,b)的行为，变量a与b分别可对应如上参数。

此处则是存在一个竞争窗口，当进程创建`2023-09-25 11.06.28`目录时，利用程序可以观测此目录的创建，一旦创建则删除，并将此处`2023-09-25 11.06.28`目录通过链接的方式指向存放TCC.db的目录，由于目标文件名和源文件内容都可控制，所以借用Music的TCC特权即可实现覆盖TCC.db数据库的行为。

诚然，在后续的更新中，MusicApp中的`kTCCServiceSystemPolicyAllFiles`已经被官方删除。

#### CVE-2023-32407 - 通过应用程序加载的系统库的行为或函数

第二种则是关注应用加载库中的相关行为，或者分析对应库中的函数。同样在Music.app该应用中,在启动之时，则会加载`/System/Library/Frameworks/Metal.framework/Versions/A/Metal`进入进程中。

Metal 框架可让您的应用直接访问设备的图形处理单元 (GPU)。借助 Metal，应用可以利用 GPU 快速渲染复杂场景并并行运行计算任务。

```bash
fmyy@Macbook_M1 Applications % otool -L ./Music.app/Contents/MacOS/Music 
./Music.app/Contents/MacOS/Music:  
    /System/Library/Frameworks/Metal.framework/Versions/A/Metal (compatibility version 1.0.0, current version 343.14.0)
```

而此`Metal.framework`中，存在对环境变量`MTL_DUMP_PIPELINES_TO_JSON_FILE`的使用。

它可以指向一个文件路径，在`Metal.framework`中通过`getenv`函数获取对应变量，并调用`NSFileManager` 类中的`createFileAtPath`方法。

```objectivec
NSString *filePath = getenv("XXX");
NSFileManager *fileManager = [NSFileManager defaultManager];
BOOL success = [fileManager createFileAtPath:filePath contents:nil attributes:nil];
```

所传入的filePath则是由`MTL_DUMP_PIPELINES_TO_JSON_FILE`变量进行控制，如果对应文件存在，则会导致覆盖原文件并创建对应文件名。

例如，若 `MTL_DUMP_PIPELINES_TO_JSON_FILE` 指向`/DIR/FILENAME`,目录有效则会在/DIR/目录下创建随机文件名的一个文件\<.dat.nosyncXXXX.XXXXXX\>并在之后通过open函数打开，再往后则会往上述文件中写入内容，内容不可控，最后通过rename函数将随机文件名文件重命名为最初`MTL_DUMP_PIPELINES_TO_JSON_FILE`变量所给的路径的名称。

在进行重命名之前，通过监控文件的创建并尝试切换/DIR目录为用户TCC数据库目录的链接，则会将.dat.nosyncXXXX.XXXXXX文件移动到TCC数据库位置位置。

rename函数在使用的过程中，会有两次访问路径的操作，具体实现在XNU内核中可以查看，因为它对应的两个参数都是作为路径传入到rename函数中。

```javascript
rename("/DIR/.dat.nosyncXXXX.XXXXXX", "/DIR/FILENAME");
```

如若在取出"/DIR/dat.nosyncXXXX.XXXXXX"文件之后，拿到对应的文件节点，但是在取出"/DIR/FILENAME"之前，通过替换/DIR/目录指向com.apple.TCC目录，那么则可以实现将\<.dat.nosyncXXXX.XXXXXX\>文件拷贝到恶意指向的目录中。

同时由于内容不可控，同时还需要对所创建的随机文件进行open并控制内容写入，才能在极低概率的状态下控制住TCC.db的内容。

#### CVE-2023-27952 - 通过系统注册的独立XPC服务的行为

在macOS系统Safari.app 应用程序存在多个XPCServices服务管理Safari应用的功能，而经过`codesign`命令对其查看，可以发现它拥有FDA最高属性之一，能对全磁盘文件进行读写。

 ![](/attachments/2024-06-12-macos-tcc-bypass/6b4f0052-0d17-4f9f-b9d4-490f15786896.png)

其中一个功能则是，当用户通过Safari下载一个zip格式的文件时，则会通过如下服务自动对其进行解压缩。

具体操作过程如下所示：

1. 首先在`~/Download/`目录下创建一个 `< [filename].zip.download >`的目录，并在此目录下进行目标zip文件的下载；

    ![](/attachments/2024-06-12-macos-tcc-bypass/7ed666ba-06e2-4ad0-ad1f-5e68c6ae3a27.png)

2. 当下载完成的时候，此时则会先创建一个由6个随机字符命名的目录，之后进行解压，服务会将解压缩后文件或目录往此目录写入；
3. 当解压缩完成之后，再将所解压后的文件或目录统一拷贝到`~/Download`目录下。

而如上解压缩过程中存在一个竞争空间，当服务创建了由6个随机字符命名的目录之后，而在往此目录写入解压后文件之前，攻击者可以通过将此目录删除并重新建立一个指向任意目录的同名目录链接，之后服务解压缩的时候，则会将zip中的文件往指定目录写入。

#### AUHelperService(macOS Sonoma BETA) - 主动与具有特权的未校验的XPC服务交互

在macOS Sonoma BETA发布后，位于 `System/Library/CoreServices/Applications/Archive Utility.app/Contents/XPCServices/AUHelperService.xpc`中的XPC服务,将`kTCCServiceSystemPolicyAllFiles`，全磁盘访问的属性添加进入其中。

 ![](/attachments/2024-06-12-macos-tcc-bypass/f4558e94-4ae9-4e23-9c56-f0024dcbe0b8.png)

在后续Sonoma的版本中，IDA可以发现：

 ![](/attachments/2024-06-12-macos-tcc-bypass/6e15538c-64df-4570-8342-3dcbc2d5c593.png)

在服务请求到达的时候，会经过一个`valueForEntitlement`的获取请求，用于检测请求的客户端是否存在`com.apple.private.AUHelperService.xpc`属性，而在之前则是没有此权限检测，因为问题是在添加FDA权限后，并没有同步添加相关的权限进行限制，因此该XPC服务提供了许多的原语。

 ![](/attachments/2024-06-12-macos-tcc-bypass/bcbe0620-f885-496a-981a-8cfbb9b24aae.png)

上述则是该XPC服务注册的函数之一，其中提供了一个原语用于文件的移动，而经过恶意的二次开发可用于移动自定义文件并覆盖指定目录的文件。因此通过开发的原语从而可以任意操控自定义TCC.db覆盖用户配置中的TCC.db数据库文件，再重启守护进程即可实现隐私绕过。

## 四、总结

本文归纳了四种TCC BYPASS的案例，介绍了四种类型在不同场景下的一些利用流程，同时可以学习如何在前一个漏洞的基础上，更进一步的利用相似的场景，即便攻击面的收窄，但是依旧能在上述分析中可知，漏洞研究员可以在已知的攻击面基础上扩展出各种的场景，所以对已知漏洞的分析是必不可少的，然后集多种想法也许能挖掘出更深层次的攻击面，包括但不限于从用户态的常见函数与XNU内核中对应函数实现的联动，抑或从官方的更新措施中寻求其他方向的切入点。

随着macOS系统的更新，漏洞的产量会逐渐变少，现有攻击面也开始收窄，大多数以前具有FDA的应用或是可执行文件都已经被保护，要么是加入了特权属性才能请求，或者直接删除了其具有的FDA属性，但是正如之前所述，macOS的系统是十分庞大的，里面存在着更多的可能性。

## 五、参考链接

\[1\] [bypass-tcc-via-icloud](https://wojciechregula.blog/post/bypass-tcc-via-icloud/)

\[2\] [macOS AUHelperService Full TCC Bypass](https://jhftss.github.io/macOS-AUHelperService-Full-TCC-Bypass/)

\[3\] [librarian (CVE-2023-38571)](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)

\[4\] [lateralus (CVE-2023-32407)](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

\[5\] [TCC bypass via mouting](https://theevilbit.github.io/posts/cve-2021-30808/)

\[6\] [Location Services Bypass](https://theevilbit.github.io/posts/cve-2022-22655/)

\[7\] [TCC bypass with telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)

\[8\] [BlackHat2024 Asia The Final Chapter: Unlimited ways to bypass your macOS privacy mechanisms](https://www.blackhat.com/asia-24/briefings/schedule/#the-final-chapter-unlimited-ways-to-bypass-your-macos-privacy-mechanisms-37662)
