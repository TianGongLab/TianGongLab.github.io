---
slug: tiangongarticle029
date: 2024-05-08
title: 关于 C++ 迭代器失效特性的研究
author: lime
tags: [C++, Iterator]
---

## 一、前言

在C++中，迭代器（Iterator）是一种用于遍历容器中元素的对象（如数组、向量、列表等）。它提供了一种统一的访问容器元素的方式，无论容器的类型和实现细节如何，比如list，vector，map等虽然实现不同，但最终都可以通过迭代器来访问和操作容器中的元素。

迭代器的工作方式类似于指针，它可以指向容器中的特定位置，并允许你在容器中前进或后退。通过使用迭代器，你可以遍历容器中的所有元素，执行读取、修改或删除操作。

<!-- truncate -->

## 二、迭代器的几种常见使用方式

1. Range-Base-For形式

    ```jsx
    for(auto& it : its_){ 
      [...]
    }
    ```

2. 直接迭代器形式

    ```jsx
    auto it = its_.begin()
    it.next()
    ```

3. 循环形式

    ```jsx
    for(it = its_.begin();it！= its_.end();it++){
      [...]
    }
    ```

## 三、序列式容器

### 3.1 Vector失效

首先先来介绍一下Vector的结构，Vector 是C++标准程序库中的一个类，可视为会自动扩展容量的数组，以循序（Sequential）的方式维护变量集合。

 ![图片来源：参考链接\[4\]](/attachments/2024-05-08-cpp-iterator-invalidation/f2378bfe-03f3-4ce4-9885-54fc7759ca0d.png)

1. 失效原因：容器发生内存重分配后，或者有删除或者插入操作
2. 失效前提：有删除或者插入操作。
3. 失效情况：

    1. 容器内存经过push_back 后重新分配，迭代器的指针还是指向原来的内存，导致迭代器、引用、指针都失效。如果是插入且没有重新分配，只会使后面的元素失效。

        如下例，定义了一个Vector，并对其进行循环迭代。

        ```cpp
        std::vector<int> vec_;
        vec_.push_back(1);
        vec_.push_back(2);
        for(auto & it : vec_){
            vec_.push_back(3);
            std::cout<<it<<std::endl;
        }
        ```

        在运行完两个push_back进行元素的添加后，此时Vector的内存：

        ```jsx
        std::vector<int> vec_;
        vec_.push_back(1);
        vec_.push_back(2);
        ---------------------
        vec_:
        0x7fffffffdcc0: 0x0000602000000030[start]      0x0000602000000038[finish]
        0x7fffffffdcd0: 0x0000602000000038[end]      0x00007ffff7f953f8
        ----------------------
        ```

        然后在进行迭代时，对其进行元素添加，超过其容量导致空间重分配。\[\*\]的位置就是Vector的首地址，可以清楚看见此时的地址已经为重新分配后的地址了，原地址已经被释放。然后在运行输出语句后导致UAF。

        ```jsx
        for(auto & it : vec_){
            vec_.push_back(3);
            ----------------------------
            0x7fffffffdcc0: 0x0000602000000050[*]      0x000060200000005c
            0x7fffffffdcd0: 0x0000602000000060      0x00007ffff7f953f8
            //原先的内存被释放，重新申请新空间。此时迭代器it 引用的地址
            //pwndbg> p &it
            //$9 = (int *) 0x602000000030
            ----------------------------
            std::cout<<it<<std::endl;
            ----------------------------
            ==2386378==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000030 at pc 0x5555556329fe bp 0x7fffffffdc90 sp 0x7fffffffdc88
            READ of size 4 at 0x602000000030 thread T0
            -----------------------------
        }
        ```

    2. 容器内元素erase后，在其后面的元素都会往前移，导致其后面的元素都失效。（不可利用）

        ```cpp
        std::vector<std::string> vec_;
        vec_.push_back("1");
        vec_.push_back("2");
        vec_.push_back("3");
        vec_.push_back("4");
        int times = 1;
        for(auto &it : vec_){
            if(times==1){
                vec_.erase(++vec_.begin());
                times--;
            }
            std::cout<<it<<std::endl;
        }
        -----------------------------
        Output:
        1
        3
        4
        ```

案例分析：[Security: UAF in MultiplexEncoderFactory](https://issues.chromium.org/issues/40061482#c_ts1666951529)

这是一个Vector失效的案例，例子中有一个Range For base的迭代，但是在这个循环中，对迭代器的范围进行了push_back操作，如果此时因为这个push_back操作导致容器的地址重分配，就会导致UAF。

```cpp
std::vector<SdpVideoFormat> MultiplexDecoderFactory::GetSupportedFormats()
    const {
  std::vector<SdpVideoFormat> formats = factory_->GetSupportedFormats();
  for (const auto& format : formats) {
    if (absl::EqualsIgnoreCase(format.name, kMultiplexAssociatedCodecName)) {
      SdpVideoFormat multiplex_format = format;
      multiplex_format.parameters[cricket::kCodecParamAssociatedCodecName] =
          format.name;
      multiplex_format.name = cricket::kMultiplexCodecName;
      formats.push_back(multiplex_format); //<---- realloc: crash
    }
  }
  return formats;
}
```

Fix：

修复是对这个容器进行深拷贝，这样在push_back的时候不会对正在访问的容器进行操作，而是把数据拷贝到新的容器里，然后在返回这个新容器。

```diff
std::vector<SdpVideoFormat> MultiplexDecoderFactory::GetSupportedFormats()
     const {
   std::vector<SdpVideoFormat> formats = factory_->GetSupportedFormats();
+  std::vector<SdpVideoFormat> augmented_formats = formats;
   for (const auto& format : formats) {
     if (absl::EqualsIgnoreCase(format.name, kMultiplexAssociatedCodecName)) {
       SdpVideoFormat multiplex_format = format;
       multiplex_format.parameters[cricket::kCodecParamAssociatedCodecName] =
           format.name;
       multiplex_format.name = cricket::kMultiplexCodecName;
-      formats.push_back(multiplex_format);
+      augmented_formats.push_back(multiplex_format);
     }
   }
-  return formats;
+  return augmented_formats;
 }
 
```

### 3.2 Deque失效

Deque虽然也是序列式容器，但是他跟Vector 差距还是挺大的。Deque是一种支持向两端高效地插入数据、支持随机访问的容器。其内部实现原理如下：双端队列的数据被表示为一个分段数组，容器中的元素分段存放在一个个大小固定的数组中，此外容器还需要维护一个存放这些数组首地址的索引数组。参见下图：

 ![图片来源：参考链接\[2\]](/attachments/2024-05-08-cpp-iterator-invalidation/0c6a13ec-7f01-41f0-a56f-09f07b3510b7.png)

由于分段数组的大小是固定的，并且它们的首地址被连续存放在索引数组中，因此可以对其进行随机访问。

* 向两端加入新元素时，如果这一端的分段数组未满，则可以直接加入； 如果这一端的分段数组已满，只需创建新的分段数组，并把该分段数组的地址加入到索引数组中即可。无论哪种情况，都不需要对已有元素进行移动，因此在双端队列的两端加入新的元素都具有较高的效率。
* 当删除双端队列容器两端的元素时，由于不需要发生元素的移动，效率也是非常高的。
* 双端队列中间插入元素时，需要将插入点到某一端之间的所有元素向容器的这一端移动，因此向中间插入元素效率较低，而且往往插入位置越靠近中间，效率越低。删除队列中元素时，情况也类似，由于被删元素到某一端之间的所有元素都要向中间移动，删除的位置越靠近中间，效率越低。

**注意: 在除了首尾两端的其他地方插入和删除元素，都有可能导致元素的任何pointers、references、iterators失效。**

1. 失效原因：容器发生内存重分配后，或者有删除或者插入操作。
2. 失效前提：有删除或者插入操作。
3. 失效情况：

    1. 容器内存经过push_back 后Map索引重新分配，迭代器的指针还是指向原来的内存，导致迭代器、引用、指针都失效。如果是插入且没有重新分配，只会使后面的元素失效。

        以下代码分配了一个deque实例，首先往里面添加足够多的元素，然后在迭代的时候，直接往容器里面添加元素当到Map达一定的阈值后，造成UAF。

        ```cpp
        std::deque<int> myDeque = {1};
            for(int i=0;i<0x1000;i++){
                myDeque.emplace_back(2);
            }
            for(auto it : myDeque){
                myDeque.emplace_back(2);
            }
        -----------------------
        ==3331485==ERROR: AddressSanitizer: heap-use-after-free on address 0x6160000001f0 at pc 0x0000004c9a6b bp 0x7ffec6f450f0 sp 0x7ffec6f450e8
        READ of size 8 at 0x6160000001f0 thread T0
        ```

        Fix: 同Vector，只需要在迭代之前，把容器进行深拷贝。

    2. 容器内元素erase后，在其后面的元素都会往前移，导致其后面的元素都失效。（不可利用）

## 四、链表式容器

### 4.1 List失效

List 由双向链表（doubly linked list）实现而成，元素也存放在堆中，每个元素都是放在一块内存中，他的内存空间可以是不连续的，通过指针来进行数据的访问，这个特点使得它的随机存取变得非常没有效率，因此它没有提供 \[\] 操作符的重载。但是由于链表的特点，它可以很有效率的支持任意地方的插入和删除操作。

 ![](/attachments/2024-05-08-cpp-iterator-invalidation/6daa4ac4-cba5-4d18-ad35-15cb10f30cf5.jpeg)

 ![图片来源：参考链接\[5\]](/attachments/2024-05-08-cpp-iterator-invalidation/3945549c-fcee-43f5-9c32-74132438d81c.png)

如果想要两个Node之间再增加一个Node元素，使用push_back 或者emplace API将插入两端的指针指向新插入的元素就可以，如下图所示：

 ![图片来源：参考链接\[5\]](/attachments/2024-05-08-cpp-iterator-invalidation/ad416dbb-eabd-4441-9801-962eb7496bab.jpeg)

1. 失效原因：元素删除导致的当前被erase元素失效。
2. 失效条件：删除元素。
3. 失效情况：容器内元素erase后，当前元素会在链表中取下来，然后被释放。就不能在用它了。

**案例分析**

下列代码定义了一个list容器，然后往里面添加2个int 元素，然后在对其进行迭代的时候，erase其中一个元素后，由于当前元素被erase后，从链中被取下来，随后被释放掉，最终导致UAF。

```cpp
std::list<int> vec_;
vec_.push_back(1);
vec_.push_back(2);
for (auto it = vec_.begin(); it != vec_.end(); ) {
    vec_.erase(it);
    std::cout<<*it<<std::endl;
}
-----------------------
==2387140==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000050 at pc 0x558fe2416a0e bp 0x7ffd5b1fa870 sp 0x7ffd5b1fa868
READ of size 4 at 0x603000000050 thread T0
```

Fix: 建议的修复是在erase 后，迭代一次，使迭代器指向下一个合法元素。

```cpp
std::list<int> vec_;
vec_.push_back(1);
vec_.push_back(2);
for (auto it = vec_.begin(); it != vec_.end(); it++) {
    vec_.erase(it++);
    std::cout<<*it<<std::endl;
}
```

## 五、关联式容器

### 5.1 Map/Set失效

Set容器内的元素会被自动排序，Set 与 Map 不同，Set 中的元素即是键值又是实值，Set 不允许两个元素有相同的键值。不能通过 Set 的迭代器去修改 Set 元素，原因是修改元素会破坏 Set 组织。当对容器中的元素进行插入或者删除时，操作之前的所有迭代器在操作之后依然有效。

 ![图片来源：参考链接\[6\]](/attachments/2024-05-08-cpp-iterator-invalidation/42f94070-f78d-47fe-bfd6-371153bd826b.png)

Map 由红黑树实现，其元素都是 "键值/实值" 所形成的一个对组（key/value pairs）。每个元素有一个键，是排序准则的基础。每一个键只能出现一次，不允许重复。

map主要用于资料一对一映射的情况，Map 内部自建一颗红黑树，这颗树具有对数据自动排序的功能，所以在 Map 内部所有的数据都是有序的。比如一个班级中，每个学生的学号跟他的姓名就存在着一对一映射的关系。

 ![图片来源：参考链接\[6\]](/attachments/2024-05-08-cpp-iterator-invalidation/e5ddfb06-c211-47b1-ac27-317f0d03bff5.png)

 ![图片来源：参考链接\[7\]](/attachments/2024-05-08-cpp-iterator-invalidation/c4fb47f8-33e0-468c-b0bb-8fe2e72bacfb.png)

1. 失效原因：元素删除导致的当前被erase 元素失效。
2. 失效条件：删除元素。
3. 失效情况：

    1. 容器内元素erase后，当前元素会在红黑树中取下来，然后被释放，就不能在用它了。

        ```cpp
        std::map<int,int> vec_;
        vec_.emplace(1,0);
        vec_.emplace(2,0);
        for (auto it = vec_.begin(); it != vec_.end(); it++) {
            vec_.erase(it);
            std::cout<<it->first<<std::endl;
        }
        -------------------------------
        ==2387781==ERROR: AddressSanitizer: heap-use-after-free on address 0x6040000000b0 at pc 0x557252362d0e bp 0x7ffe42db7d10 sp 0x7ffe42db7d08
        READ of size 4 at 0x6040000000b0 thread T0

        -------------------------------
        std::map<int,int> vec_;
        vec_.emplace(1,0);
        vec_.emplace(2,0);
        auto it = vec_.begin();
        vec_.erase(it);
        std::cout<<it->first<<std::endl;
        ------------------------------
        ==2398643==ERROR: AddressSanitizer: heap-use-after-free on address 0x6040000000b0 at pc 0x5564da9f3bee bp 0x7ffca5911fb0 sp 0x7ffca5911fa8
        READ of size 4 at 0x6040000000b0 thread T0
        ```

Fix: 同list一样，在Node 被取消释放后，迭代到下一个有效的Node 就可以。

案例分析：[Potential use after free in CPDFSDK_FormFillEnvironment::ClearAllFocusedAnnots (XFA)](https://issues.chromium.org/issues/40095009)

如下例是chromium里面的Map迭代失效。在ClearAllFocusedAnnots 函数里，有一个KillFocusAnnot调用，但是这个KillFocusAnnot最终有条路径可以走到CXFA_Node::ProcessEvent，然后ProcessEvent可以自定义JS代码，这样就起到了回调作用，然后可以通过别处的m_PageMap.Clear() 把Map的节点全部清空释放，这样在后面迭代的时候就会造成UAF。

```cpp
void CPDFSDK_FormFillEnvironment::ClearAllFocusedAnnots() {
    for (auto& it : m_PageMap) {
        if (it.second->IsValidSDKAnnot(GetFocusAnnot()))
        KillFocusAnnot(0);
    }
}
```

```cpp
CPDFSDK_FormFillEnvironment::KillFocusAnnot ->
CPDFSDK_AnnotHandlerMgr::Annot_OnKillFocus ->
CPDFSDK_XFAWidgetHandler::OnKillFocus ->
CXFA_FFDocView::SetFocus ->
CXFA_FFWidget::OnSetFocus ->
CXFA_Node::ProcessEvent
```

## 六、总结

本文总结了C++迭代器失效的几种情况，总之，迭代器失效就是在迭代器迭代的过程中，容器或者容器内元素发生变化，导致的内存损坏等影响。

## 七、参考

\[1\] [【C++ STL】迭代器失效的几种情况总结](https://www.cnblogs.com/linuxAndMcu/p/14621819.html)

\[2\] [STL容器迭代器失效情况分析、总结](https://ivanzz1001.github.io/records/post/cplusplus/2018/03/14/cpluscplus_stl_iterator)

\[3\] [知乎问答](https://www.zhihu.com/question/486490278)

\[4\] [C++ 数据结构-Vector的内部机制](https://www.jianshu.com/p/9d400528a421)

\[5\] [C++ list容器](https://blog.csdn.net/cpp_learner/article/details/104672874)

\[6\] [Standard Associative Containers](https://hackingcpp.com/cpp/std/associative_containers.html)

\[7\] [C++ map用法总结（整理）](https://blog.csdn.net/sevenjoin/article/details/81943864)
