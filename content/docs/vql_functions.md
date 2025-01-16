---
slug: vql_function
title: "VQL 函数功能描述"
date: 2023-10-17
weight: 3
---

### taintPropagation

> **taintPropagation(List\<Long> Source, List\<Long> sink, Integer flag, List\<Long> should, List\<Long> shouldNot)**

+ 参数
  + **List\<Long> source:** source 点 ID 集合
  + **List\<Long> sink:** sink 点 ID 集合
  + **Integer flag:** 默认为空为从source和sink中较少的一方传递
    + flag=1 时为有方向从 source 到 sink
    + flag=2 时为有方向从 sink 到 source
    + flag=3 时污点分析为无向
  + **List\<Long> should:** 期望经过的点ID集合
  + **List\<Long> shouldNot:** 排除点ID的集合
+ 功能
  + 找出 source 到 sink 之间的传输路径
+ 返回
  + 通路上点的集合
+ 样例
  + 查找集合[845623]到集合[845593, 845664]之间的单向污点路径,并且途中需要经过集合[845658]

    ```cypher
    CALL VQL.taintPropagation([845623], [845593, 845664], 1, [845658])
    ```

### doubleTaintPropagation

> **doubleTaintPropagation(Long sourceId, Long sinkId, Integer flag, List\<Long> should, List\<Long> shouldNot)**

+ 参数
  + **Long sourceId:** source 点 ID
  + **Long sinkId:** sink 点 ID
  + **Integer flag:** 默认为空为从 source 和 sink 中较少的一方传递
    + flag=1 时为有方向
    + flag=2 时为无方向
  + **List\<Long> should:** 期望经过的点 ID 集合
  + **List\<Long> shouldNot:** 排除点 ID 的集合
+ 功能
  + 双向找出 source 到 sink 之间的传输路径
+ 返回
  + 通路上点的集合
+ 样例
  + 同时从点845623和845664向中间查找有向污点路径。

    ```cypher
    CALL VQL.doubleTaintPropagation(845623,845664,1)
    ```

### simpleTaintPropagation

> **simpleTaintPropagation(List\<Long> source, List\<Long> sink, Integer flag)**

+ 参数
  + **List\<Long> source:** source 点 ID 集合
  + **List\<Long> sink:** sink 点 ID 集合
  + **Integer flag:** 默认为空为从source和sink中较少的一方传递
    + flag=1时为有方向
    + flag=2时为无方向
    + flag=3时找出全部路径
+ 功能
  + 使用最短路径找出 source 到 sink 之间通路
+ 返回
  + 通路上点的集合
+ 样例
  + 使用最短路径找出集合[845623]到集合[845664]的有向污点传输路径

    ```cypher
    CALL VQL.simpleTaintPropagation([845623],[845664],1)
    ```

### getAllBasicblocks

> **getAllBasicblocks()**

+ 参数
  + 无
+ 功能
  + 获取当前项目所有基本块
+ 返回
  + 基本块节点
+ 样例
  + 找出当前分析项目中所有的基本块节点

    ```cypher
    CALL VQL.getAllBasicblocks
    ```

### getAllFunctions

> **getAllFunctions()**

+ 参数
  + 无
+ 功能
  + 获取当前项目所有函数
+ 返回
  + 函数节点
+ 样例
  + 找出当前分析项目中所有函数节点

    ```cypher
    CALL VQL.getAllFunctions
    ```

### getAllFiles

> **getAllFiles()**

+ 参数
  + 无
+ 功能
  + 获取当前项目所有文件
+ 返回
  + 文件节点
+ 样例
  + 找出当前分析项目中所有文件节点

    ```cypher
    CALL VQL.getAllFiles
    ```

### getASTOfCodeline

> **getASTOfCodeline(String function, Long nodeId, Long line)**

+ 参数
  + **String function:** 函数名
  + **Long nodeId:** 节点 ID，按照 code_line 的 id 进行查询
  + **Long line:** 行号
+ 功能
  + 获取指定code_line的AST路径
  + 当 nodeId 为空时按照 function、line 进行查询
+ 返回
+ 样例
  + 找出函数中第 11 行 code_line 对应的 ast 路径

    ```cypher
    CALL VQL.getASTOfCodeline("_mgfini_BFDD", 11)
    ```

  + 找出code_line的id为31687对应的ast路径

    ```cypher
    CALL VQL.getASTOfCodeline(31687)
    ```

### getBasicblockOfFunction

> **getBasicblockOfFunction(Long functionId, String start_address)**

+ 参数
  + **Long FunctionId:**
  + **String start_address:** 函数入口点地址
+ 功能
  + 获取指定函数的基本块
+ 返回
  + 基本块节点
+ 样例
  + 找出入口地址为0805be6b函数的所有基本块

    ```cypher
    CALL VQL.getBasicblockOfFunction("0805be6b")
    ```

  + 找出id号为22947函数的所有基本块

    ```cypher
    CALL VQL.getBasicblockOfFunction(22947)
    ```

### getArgument

> **getArgument(String callee, Long index)**

+ 参数
  + **callee:** 调用函数
  + **index:** 参数位置
    + -1 代表输出
    + 0 代表第一个参数、1 代表第二个参数、以此类推
+ 功能
  + 通过变量被调用的函数和参数顺序定位变量
+ 返回
  + 变量节点
+ 样例
  + 找出位于函数malloc第一个参数位置上的所有变量

    ```cypher
    CALL VQL.getArgument("malloc",0)
    ```

### getChildren

> **getChildren(Long nodeId, Long stepStart, Long stepStop)**

+ 参数
  + **Long nodeId:** 指定节点的id
  + **Long stepStart:** 最小跳数
  + **Long stepStop:** 最大跳数
+ 功能
  + 获取指定节点指定层数的子节点路径
+ 返回
  + 到达子节点路径
+ 样例
  + 找出距离节点958080一跳距离的子节点

    ```cypher
    CALL VQL.getChildren(958080, 1, 1)
    ```

### getFunctionByAddress

> **getFunctionByAddress(String entry_point)**

+ 参数
  + **String entry_point:** 指定函数的入口地址
+ 功能
  + 通过入口地址查找函数节点
+ 返回
  + 函数节点
+ 样例
  + 找出入口地址为 0x080f316c 的函数

    ```cypher
    CALL VQL.getFunctionByAddress("080f316c")
    ```

### getFunctionsByName

> **getFunctionsByName(String function)**

+ 参数
  + **String function:** 指定函数的名称
+ 功能
  + 通过函数名称查找函数节点，支持模糊匹配
+ 返回
  + 函数节点
+ 样例
  + 找出函数名为 zclient 的函数

    ```cypher
    CALL VQL.getFunctionsByName("zclient")
    ```

### getFunctionsOfFile

> **getFunctionsOfFile(String name)**

+ 参数
  + **String name:** 指定文件的名称
+ 功能
  + 获取指定文件的所有函数，支持模糊匹配
+ 返回
  + 函数节点
+ 样例
  + 找出文件名为 bgpd 下面的所有函数

    ```cypher
    CALL VQL.getFunctionsOfFile("bgpd")
    ```

### getInfluencedCodeline

> **getInfluencedCodeline(Long nodeId, Long stepStart, Long stepStop)**

+ 参数
  + **Long nodeId:** 指定节点的 id
  + **Long stepStart:** 最小跳数
  + **Long stepStop:** 最大跳数
+ 功能
  + 通过变量获取其所在的语句节点
+ 返回
  + code_line 节点
+ 样例
  + 找出距离变量节点 50523 步长为 1 的 code_line

    ```cypher
    CALL VQL.getInfluencedCodeline(150523, 1, 1)
    ```

### getInputsOfCodeline

> **getInputsOfCodeline(Long nodeId)**

+ 参数
  + **Long nodeId:** 指定代码行 code_line 的 id
+ 功能
  + 获取节点所归属AST的输⼊变量
+ 返回
  + 变量节点
+ 样例
  + 找出 code_line 987013 通过 asts 输入的相应变量

    ```cypher
    CALL VQL.getInputsOfCodeline(987013)
    ```

### getCodelineByName

> **getCodelineByName(String name)**

+ 参数
  + **String name:** 指定代码行 code_line 的内容
+ 功能
  + 通过语句内容来获取 code_line 节点
+ 返回
  + code_line 节点
+ 样例
  + 找出内容为 11: \*DAT_080f1264 = iVar1 所对应的 code_line
    ```cypher
    CALL VQL.getCodelineByName("11: \*DAT_080f1264 = iVar1;")
    ```

### getCodelineOfBasicblock

> **getCodelineOfBasicblock(String start_address, String stop_address)**

+ 参数
  + **String start_address:** 起始地址
  + **String stop_address:** 终止地址
+ 功能
  + 通过基本块地址来获取 code_line 节点
+ 返回
  + code_line 节点
+ 样例
  + 找出起始地址为: 0x0804e0f3，终止地址为: 0x0804e10d 的基本块对应的 code_line

    ```cypher
    CALL VQL.getCodelineOfBasicblock("0804e0f3", "0804e10d")
    ```

### getCodelineOfFunction

> **getCodelineOfFunction(String function, String entry_point)**

+ 参数
  + **String function:** 函数名
  + **String entry_point:** 函数入口点
+ 功能
  + 通过函数名或者入口地址获取 code_line 节点
+ 返回
  + code_line 节点
+ 样例
  + 找出函数名为 _sub_I_01001_0.0 对应的所有 code_line

    ```cypher
    CALL VQL.getCodelineOfFunction("_sub_I_01001_0.0", null)
    ```

  + 找出入口地址为 0x0804e645 的函数对应的所有 code_line

    ```cypher
    CALL VQL.getCodelineOfFunction(null, "0804e645")
    ```

### getOutputsOfCodeline

> **getOutputsOfCodeline(Long nodeId)**

+ 参数
  + **Long nodeId:** 指定语句节点的id值
+ 功能
  + 获取指定语句节点所归属 AST 的输出变量
+ 返回
  + 变量节点
+ 样例
  + 找出 code_line 31683 通过 asts 输出的相应变量

    ```cypher
    CALL VQL.getOutputsOfCodeline(31683)
    ```

### getParents

> **getParents(Long nodeId, Long stepStart, Long stepStop)**

+ 参数
  + **Long nodeId:** 指定节点的id
  + **Long stepStart:** 最小跳数
  + **Long stepStop:** 最大跳数
+ 功能
  + 获取指定节点指定层数的父节点路径
+ 返回
  + 到达父节点路径
+ 样例
  + 找出距离节点31683步长为1的所有父节点

    ```cypher
    CALL VQL.getParents(31683, 1, 1)
    ```

### getFileByName

> **getFileByName(String name)**

+ 参数
  + **String name:** 指定文件文件名
+ 功能
  + 通过文件名获取文件节点
+ 返回
  + 文件节点
+ 样例
  + 找出文件名为bgpd的所有文件节点

    ```cypher
    CALL VQL.getFileByName("bgpd")
    ```

### getClassByNameSpace

> **getClassByNameSpace(String namespace)**

+ 参数
  + **String namespace:** 指定的命名空间名称
+ 功能
  + 通过命名空间获取类节点
+ 返回
  + 类节点
+ 样例
  + 找出命名空间名称为std::verify的所有类节点

    ```cypher
    CALL VQL.getClassByNameSpace("std::verify")
    ```

### getClassByType

> **getClassByType(String type)**

+ 参数
  + **String type:** 制定的类类型
+ 功能
  + 获取指定类型的类节点
+ 返回
  + 类节点
+ 样例
  + 找出类类型为 User-defined 的所有类节点

    ```cypher
    CALL VQL.getClassByType("User-defined")
    ```

### getClassByName

> **getClassByName(String name)**

+ 参数
  + **String name:** 指定的类名称
+ 功能
  + 获取指定名称的类节点
+ 返回
  + 类节点
+ 样例
  + 找出类名称为encryption的类节点

    ```cypher
    CALL VQL.getClassByName("encryption")
    ```

### getClassOfFile

> **getClassOfFile(String name)**

+ 参数
  + **String name:** 指定的类名称
+ 功能
  + 获取指定文件中的类节点
+ 返回
  + 类节点
+ 样例
  + 找出文件名为bgpd中的所有类节点

    ```cypher
    CALL VQL.getClassOfFile("bgpd")
    ```

### getFunctionOfClass

> **getFunctionOfClass(String name )**

+ 参数
  + **String name:** 指定的类名称
+ 功能
  + 获取指定类中的成员函数
+ 返回
  + 函数节点
+ 样例
  + 找出类encryption中的所有函数节点

    ```cypher
    CALL VQL.getFunctionOfClass("encr")
    ```

### getFileldOfClass

> **getFileldOfClass(String name)**

+ 参数
  + **String name:** 指定的类名称
+ 功能
  + 获取指定类中的成员变量
+ 返回
  + 变量节点
+ 样例
  + 找出类encryption中所有的类成员变量

    ```cypher
    CALL VQL.getFileldOfClass("encryption")
    ```

### getOperatorByName

> **getOperatorByName(String name)**

+ 参数
  + **String name:** 操作符的名称
+ 功能
  + 通过名称获取操作符
+ 返回
  + 操作符节点
+ 样例
  + 找出所有的+操作符变量

    ```cypher
    CALL VQL.getOperatorByName("+")
    ```
