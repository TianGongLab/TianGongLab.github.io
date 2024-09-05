---
slug: qucickstart
date: 2023-10-18
title: "VQL使用手册"
weight: 5
---

## 简介

VQL（**Vulnerability Query Language**）是基于 Cypher（**一种声明式的图数据库查询语言**）开发的漏洞查询语言插件，它既包含了 Cypher 精简和灵活，同时也兼顾了简单和实用的特性，能够帮助用户更好地进行漏洞挖掘。本平台的图中包含函数调用图、控制流图、数据流图等多种能辅助漏洞挖掘的的图，用户可以使用VQL和Cypher结合在图中进行批量漏洞挖掘工作。

## Cypher 语句使用

> Cypher 是 一种图数据库的查询语言，就如同 SQL 之于其他关系型数据库一样。在图数据库中，数据均以节点、关系来存储。所以 Cypher 应该能够有某种语法来描述节点和关系，并能表征他们之间的关系。

### 节点查询

```cypher
MATCH (n:identifier) RETURN id(n) LIMIT 25
```

说明：查询变量节点，并返回其节点 id 限制数量为 25

### 路径查询

```cypher
MATCH p=()-[r:dfg]->() RETURN p LIMIT 25
```

说明：查找节点关系为数据流图关系(dfg,data flow graph)的路径限制数量为 25

### 子句

> 如同 SQL 中的 `SELECT`、`WHERE` 等子句，在 cypher 中也有这类子句，用来进行查找、过滤、排序等操作。

```cypher
MATCH (n:identifier) WHERE n.callee = "lxmldbc_system" AND (n.index=2 or n.index=3 or n.index=4) WITH collect(id(n)) AS sinkSet RETURN sinkSet
```

说明：查找调用函数 lxmldbc_system 第 3，4，5 参数位置上的所有变量(注：函数调用输出值为-1，index从0开始计数)，并将其节点 id 作为集合输出

`WITH` 能将多个语句连接起来，就像管道一样，前一个语句的输出作为下一个语句的输入

`collect` 可以将多个匹配收集到一个数组中

`WHERE` 中还可以指定一个模式，可以过滤掉符合或者不符合这个模式的结果

## 常见的节点类型使用

| 类型 | 解释 |
| --- | --- |
| node | 返回值为节点 |
| path | 返回值为路径 |
| taintPropagationPath | 返回值为污点路径（注：若需要在平台显示代码路径，返回值需要命名为taintPropagationPath） |

## 使用实列

### 节点 id 获取

```cypher
CALL VQL.getAllFunctions() YIELD node WITH COLLECT(id(node)) AS functionId RETURN functionId
```

说明：找出所有函数节点，并返回所有节点的 id

### 路径中关系获取

```cypher
CALL VQL.getChildren(958080, 1, 1) YIELD path WITH relationships(path) AS r RETURN r
```

说明：找出id为958080节点的跳数为1跳的ast关系节点

### 污点路径获取

```cypher
CALL VQL.taintPropagation([845623], [845593, 845664], 1, [845658]) YIELD taintPropagationPath RETURN taintPropagationPath ORDER BY SIZE(taintPropagationPath)
```

说明：查找id集合 [845623] 到id集合 [845593, 845664] 之间的单向污点路径，并且途中需要经过集合 [845658]，并将路径按长度由小到大排列

### 漏洞实例检测

```cypher
CALL VQL.getArgument("system", 0) YIELD node WITH collect(id(node)) AS SinkSet 
CALL VQL.getArgument("getenv", -1) YIELD node WITH SinkSet,collect(id(node)) AS SourceSet 
CALL VQL.taintPropagation(SourceSet, SinkSet, 1) YIELD taintPropagationPath RETURN taintPropagationPath order by size(taintPropagationPath)
```

说明：

1. 找出函数 system 的第一个参数位置的所有变量作为 sink 点
2. 找出位于函数 getenv 的返回值位置的所有变量作为 source 点
3. 利用单向污点传播函数找到所有的污点路径，并按照污点路径的长度从小到大排列

## Cypher 与 VQL 结合使用

```cypher
MATCH (n:identifier) WHERE n.callee = "getenv" AND n.index=-1 WITH COLLECT(id(n)) AS sourceSet
MATCH (n:identifier) WHERE n.callee = "lxmldbc_system" AND (n.index=2 or n.index=3 or n.index=4) WITH sourceSet,COLLECT(id(n)) AS sinkSet 
CALL VQL.taintPropagation(sourceSet, sinkSet) YIELD taintPropagationPath RETURN taintPropagationPath ORDER BY size(taintPropagationPath)
```

说明：

1. 找出位于函数 getenv 的返回值位置的所有变量作为 source 点
2. 找出位于函数 lxmldbc_system 第 3，4，5 参数位置上的所有变量作为 sink 点
3. 利用单向污点传播函数找到所有的污点路径，并按照污点路径的长度从小到大排列
