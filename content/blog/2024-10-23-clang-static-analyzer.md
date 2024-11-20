---
slug: tiangongarticle050
date: 2024-10-23
title: 探索Clang Static Analyzer：使用方法与源码解读
author: R0g3rTh4t
tags: ["静态分析", "CSA"]
---

## 一、前言

静态分析技术因其在学术研究和工业应用中的广泛用途而备受关注。尽管静态分析技术已经取得了长足的进步，但现有的静态分析框架仍然存在易用性方面的挑战。本文主要介绍了 Clang Static Analyzer（CSA）的使用方法，对部分检查器的源代码进行了浅析，并探讨了其设计思想。希望通过本文，能够帮助那些希望深入了解静态分析技术的同学更好地掌握相关知识。

## 二、CSA 工作原理
CSA 分析器的设计灵感来自几篇基础性的研究论文 ([Precise interprocedural dataflow analysis via graph reachability, T Reps, S Horwitz, and M Sagiv, POPL '95](http://portal.acm.org/citation.cfm?id=199462), [A memory model for static analysis of C programs, Z Xu, T Kremenek, and J Zhang](http://lcs.ios.ac.cn/\~xzx/memmodel.pdf))。

分析器基本上是一个源代码模拟器，它能跟踪可能的执行路径。程序的状态由状态（ProgramStateRef）进行封装。在 CSA 术语中对应 `ExplodedNode`。

分析器通过对分支进行推理，找出多条路径，然后对状态进行分叉。在真分支上，假设该分支的条件为真，而在假分支上，假设该分支的条件为假。这种"假设"会对程序的值产生约束，这些约束被记录在程序状态（ProgramState）中并由约束管理器管理。如果假设分支的条件会导致约束条件无法满足，那么该分支将被视为不可行，该路径将被删除，这就是路径敏感性。CSA 通过缓存节点来减少指数级爆炸，如果新节点的状态和程序点与现有节点相同，路径就会被"缓存"，我们只需重新使用现有节点即可。

更详细的工作原理可以参考 CSA [README.md](https://github.com/llvm/llvm-project/blob/main/clang/lib/StaticAnalyzer/README.txt)。

总而言之，Clang Static Analyzer（CSA） 是基于 Clang AST（编译器前端） 实现的源代码静态符号执行工具。支持分析 C，C++，和 Objective-C 。基于静态符号执行技术实现了路径敏感技术，也支持过程间分析。工具被集成进 llvm-project，有长期的维护和发展。如果你对符号执行比较熟悉，会注意到其与 KLEE，Angr 的诸多相似之处。

## 三、CSA 安装指南

**clang is all you need**。

* 通过包管理工具安装因平台而异，这里以 ubuntu 为例。

  ```bash
  apt install clang
  ```
* 根据源码编译 LLVM 项目，编译细节可以参考 Getting Started with the LLVM System ([Getting Started with the LLVM System](https://llvm.org/docs/GettingStarted.html), [Clang 的編譯——面向 Clang Static Analyzer 開發的編譯配置指北, Xutong Ma](https://blog.oikawa.moe/2021/06/06/clang-%e7%9a%84%e7%b7%a8%e8%ad%af-%e9%9d%a2%e5%90%91-clang-static-analyzer-%e9%96%8b%e7%99%bc%e7%9a%84%e7%b7%a8%e8%ad%af%e9%85%8d%e7%bd%ae%e6%8c%87%e5%8c%97/))。

  ```bash
  git clone https://github.com/llvm/llvm-project.git
  mkdir -p llvm-project/build && cd llvm-project/build
  # 可以只编译部分项目，通过 LLVM_ENABLE_PROJECTS 我们可以只编译 clang 和 clang-tools-extra（并非必须）。还可以在此处指定编译的类型，Debug 或者 Release 等。为了减少编译量，可以只编译 x86 的 clang。
  cmake ../llvm \
   -DLLVM_ENABLE_PROJECTS=clang \
   -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
   -DLLVM_TARGETS_TO_BUILD=X86 \
   -DLLVM_USE_SPLIT_DWARF=ON \
   -DBUILD_SHARED_LIBS=ON \
   -DLLVM_OPTIMIZED_TABLEGEN=ON \
   -DLLVM_ENABLE_Z3_SOLVER=ON \
   -DCMAKE_C_COMPILER=clang \
   -DCMAKE_C_FLAGS=-fno-limit-debug-info \
   -DCMAKE_CXX_COMPILER=clang++ \
   -DCMAKE_CXX_FLAGS=-fno-limit-debug-info \
   -DLLVM_USE_LINKER=lld \
   -DLLVM_ENABLE_BINDINGS=OFF \
   -DCLANG_ENABLE_ARCMT=OFF \ 
   -G Ninja
  ```

## 四、CSA Driver 使用

由于 CSA 工具被集成进 `clang` 中, 并不是一个非常"独立"的工具，使用起来会有一些麻烦。当然 CSA 相关项目也提供了一些相对独立的工具如 `clang-check`， `CodeCheck`，但是从结果来看与直接使用 `clang` 是差不多的。一般来说，使用 CSA 需要 driver 来加载参数来决定是否开启某些 checker，是否开启 z3 进行约束求解，是否导出报告等。由于参数实在之多，不可能一一列出，这里只介绍部分。

 ![](/attachments/2024-10-23-clang-static-analyzer/63afed9b-c96f-4b92-ac9b-8fc6ad428fb9.jpeg)

* 查看与前端 analyze 相关的参数：

  ```bash
  clang -cc1 -help | grep analyze
  ```

  期望输出：

  ```none
  -analyze-function <value>
  -analyzer-checker-help-alpha
                          Display the list of in  development analyzer checkers.  These are NOT considered safe,  they are unstable and will emit incorrect reports. Enable ONLY FOR DEVELOPMENT purposes
  -analyzer-checker-help-developer
  -analyzer-checker-help  Display the list of analyzer  checkers that are available
  -analyzer-checker-option-help-alpha
  -analyzer-checker-option-help-developer
  -analyzer-checker-option-help
  -analyzer-checker <value>
                          Choose analyzer checkers to enable
  -analyzer-config-compatibility-mode <value>
                          Don't emit errors on invalid  analyzer-config inputs
  -analyzer-config-help   Display the list of  -analyzer-config options. These are meant for development  purposes only!
  -analyzer-config <value>
  ...
  ```
* 查看当前 clang 有哪些 checker：

  ```bash
  clang -cc1 -analyzer-checker-help-developer
  ```

  或者

  ```bash
  clang -cc1 -analyzer-checker-help
  ```

  期望输出：

  ```none
  OVERVIEW: Clang Static Analyzer Checkers List
  
  USAGE: -analyzer-checker <CHECKER or PACKAGE,...>
  
  CHECKERS:
    alpha.core.PthreadLockBase    Helper registering multiple    checks.
    alpha.cplusplus.ContainerModeling
                                  Models C++ containers
    alpha.cplusplus.IteratorModeling
                                  Models iterators of C++  containers
    alpha.osx.cocoa.IvarInvalidationModeling
                                  Gathers information for  annotation driven  invalidation checking for   classes that contains a   method annotated with  'objc_instance_variable_inva   lidator'
    apiModeling.Errno             Make the special value   'errno' available to other checkers.
    apiModeling.StdCLibraryFunctions
                                  Improve modeling of the C   standard library functions
    apiModeling.TrustNonnull      Trust that returns from  framework methods annotated with _Nonnull are not null
  ...
  ```

为例便于使用 CSA ，我们需要用 driver 来配置 CSA 的参数，对单个或多个源代码进行分析，自己写或者利用现成的工具。

以分析如下代码为例，说明 CSA 是如何进行过程间分析，并熟悉相关参数：

* 源代码：

  ```cpp
  // main.cpp
  int foo();
  
  int main() {
    return 3 / foo();
  }
  ```

  ```cpp
  // foo.cpp
  int foo() {
    return 0;
  }
  ```
* 导出 ast：

  ```bash
  clang++ -emit-ast -o foo.cpp.ast foo.cpp
  ```
* 导出 `externalDefMap.txt`：

  ```bash
  clang-extdef-mapping -p . foo.cpp
  ```
* 替换 `externalDefMap.txt` 一些路径问题：

  ```bash
  sed -i -e "s/.cpp/.cpp.ast/g" externalDefMap.txt
  sed -i -e "s|$(pwd)/||g" externalDefMap.txt
  ```
* 使用 CSA 进行过程间分析：

  ```bash
  clang++ --analyze \
     -Xclang -analyzer-config -Xclang experimental-enable-naive-ctu-analysis=true \
     -Xclang -analyzer-config -Xclang ctu-dir=. \
     -Xclang -analyzer-output=plist-multi-file \
     main.cpp
  ```

报告可以通过参数来指定，下图是一个报告的例子。

 ![](/attachments/2024-10-23-clang-static-analyzer/f35e03bb-a65f-41f2-bb6d-8d8b6bc9d305.png " =675x467")

## 五、CSA 源码浅析

下面以 `TaintTesterChecker.cpp` 为例说明 CSA checker 的一般结构与实现。

* `TaintTesterChecker.cpp` 可以从 `path-to-llvm-project/clang/lib/StaticAnalyzer/Checkers` 目录下找到，这里直接引用它的内容。

  ```cpp
  //== TaintTesterChecker.cpp ----------------------------------- -*- C++ -*--=//
  //
  // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
  // See https://llvm.org/LICENSE.txt for license information.
  // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
  //
  //===----------------------------------------------------------------------===//
  //
  // This checker can be used for testing how taint data is propagated.
  //
  //===----------------------------------------------------------------------===//
  
  #include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
  #include "clang/StaticAnalyzer/Checkers/Taint.h"
  #include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
  #include "clang/StaticAnalyzer/Core/Checker.h"
  #include "clang/StaticAnalyzer/Core/CheckerManager.h"
  #include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
  
  using namespace clang;
  using namespace ento;
  using namespace taint;
  
  namespace {
  class TaintTesterChecker : public Checker<check::PostStmt<Expr>> {
    const BugType BT{this, "Tainted data", "General"};
  
  public:
    void checkPostStmt(const Expr *E, CheckerContext &C) const;
  };
  }
  
  void TaintTesterChecker::checkPostStmt(const Expr *E,
                                         CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    if (!State)
      return;
  
    if (isTainted(State, E, C.getLocationContext())) {
      if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        auto report = std::make_unique<PathSensitiveBugReport>(BT, "tainted", N);
        report->addRange(E->getSourceRange());
        C.emitReport(std::move(report));
      }
    }
  }
  
  void ento::registerTaintTesterChecker(CheckerManager &mgr) {
    mgr.registerChecker<TaintTesterChecker>();
  }
  
  bool ento::shouldRegisterTaintTesterChecker(const CheckerManager &mgr) {
    return true;
  }
  ```
* 这个 checker 继承了 `public Checker<check::PostStmt<Expr>>`，表示在 CSA 进行分析的过程中，它会在每个 Stmt 执行后调用该 checker。如果在该 StateRef 被污染了，就会产生路径敏感的报告。

  ```cpp
  isTainted(State, E, C.getLocationContext())
  ```
* 最后还需要在 CheckerMananger 中中注册相应的 checker。

  ```cpp
  void ento::registerTaintTesterChecker(CheckerManager &mgr) {
    mgr.registerChecker<TaintTesterChecker>();
  }
  
  bool ento::shouldRegisterTaintTesterChecker(const CheckerManager &mgr) {
    return true;
  }
  ```


下面对 `MallocChecker` 进行简单的分析，希望读者也能有一些收获，关于 `malloc free pair` 和 `new delete pair` 等相关的实现问题。

`MallocChecker` 也在上文提及的目录中，`CSA checkers` 一般都在此实现。

静态分析工具 `CSA` 的核心就是建模，阅读 `MallocChecker` 后很明显能了解到 CSA 的开发者是以何种方式思考，希望能够描述出什么样的 `malloc` 与 `free` 是合法与非法的，以此类推，建立程序语言与形式化方法之间的桥梁。

`MallocChecker` 通过 `AllocationFamilyKind` 标识内存分配/释放的家族，总共有以下几类，对每一个家族有不同的处理，这一点比较好理解。

```cpp
enum AllocationFamilyKind {
  AF_None,
  AF_Malloc,
  AF_CXXNew,
  AF_CXXNewArray,
  AF_IfNameIndex,
  AF_Alloca,
  AF_InnerBuffer,
  AF_Custom,
};
```

分配/释放的内存处于某种状态，可以理解为在有限自动机上的状态转换。每一种都有注释，可以详细阅读一番。其中 `Relinquished` 还是比较有趣的，在统计引用的过程中表示引用已经被"偷走"，不必再对其 `free` 或者减引用，否则有可能导致 UAF。

```cpp
enum Kind {
  // Reference to allocated memory.
  Allocated,
  // Reference to zero-allocated memory.
  AllocatedOfSizeZero,
  // Reference to released/freed memory.
  Released,
  // The responsibility for freeing resources has transferred from
  // this reference. A relinquished symbol should not be freed.
  Relinquished,
  // We are no longer guaranteed to have observed all manipulations
  // of this pointer/memory. For example, it could have been
  // passed as a parameter to an opaque function.
  Escaped
};
```

关于程序建模，以 `Malloc` 的建模为例，程序中的注释表示的还算清楚。分配内存需要考虑分配内存的函数 `AllocationFamily Family` 是什么，需要分配的大小 `const Expr *SizeEx`，是否需要初始化 `Sval Init`，以及内存分配函数的上下文 `CallEvent` 和 `CheckerContext`。

```cpp
/// Models memory allocation.
///
/// \param [in] Call The expression that allocates memory.
/// \param [in] SizeEx Size of the memory that needs to be allocated.
/// \param [in] Init The value the allocated memory needs to be initialized.
/// with. For example, \c calloc initializes the allocated memory to 0,
/// malloc leaves it undefined.
/// \param [in] State The \c ProgramState right before allocation.
/// \returns The ProgramState right after allocation.
[[nodiscard]] ProgramStateRef
MallocMemAux(CheckerContext &C, const CallEvent &Call, const Expr *SizeEx,
         SVal Init, ProgramStateRef State, AllocationFamily Family) const;
```

还需要考虑 `Malloc` 的返回值 `RetVal`，是否分配成功，应该分配怎么样的内存，什么样的情况下需要被污染，什么样的情况下报错，这就需要结合 `FreeMemAux` 考虑。

```cpp
ProgramStateRef MallocChecker::MallocMemAux(CheckerContext &C,
       const CallEvent &Call, SVal Size,
       SVal Init, ProgramStateRef State,
       AllocationFamily Family) const {
  if (!State)
    return nullptr;

  const Expr *CE = Call.getOriginExpr();

  // We expect the malloc functions to return a pointer.
  if (!Loc::isLocType(CE->getType()))
    return nullptr;

  // Bind the return value to the symbolic value from the heap region.
  // TODO: move use of this functions to an EvalCall callback, becasue
  // BindExpr() should'nt be used elsewhere.
  unsigned Count = C.blockCount();
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getPredecessor()->getLocationContext();
  DefinedSVal RetVal = ((Family.Kind == AF_Alloca)
                            ? SVB.getAllocaRegionVal(CE, LCtx, Count)
                            : SVB.getConjuredHeapSymbolVal(CE, LCtx, Count)
                                  .castAs<DefinedSVal>());
  State = State->BindExpr(CE, C.getLocationContext(), RetVal);

  // Fill the region with the initialization value.
  State = State->bindDefaultInitial(RetVal, Init, LCtx);

  // If Size is somehow undefined at this point, this line prevents a crash.
  if (Size.isUndef())
    Size = UnknownVal();

  checkTaintedness(C, Call, Size, State, AllocationFamily(AF_Malloc));

  // Set the region's extent.
  State = setDynamicExtent(State, RetVal.getAsRegion(),
                           Size.castAs<DefinedOrUnknownSVal>(), SVB);

  return MallocUpdateRefState(C, CE, State, Family);
}
```

* `Malloc` 只要分配一块可被追踪的内存，而 `Free` 需要考虑的就很多了。

  ```cpp
  /// Models memory deallocation.
  ///
  /// \param [in] ArgExpr The variable who's pointee needs to be freed.
  /// \param [in] Call The expression that frees the memory.
  /// \param [in] State The \c ProgramState right before allocation.
  ///   normally 0, but for custom free functions it may be different.
  /// \param [in] Hold Whether the parameter at \p Index has the ownership_holds
  ///   attribute.
  /// \param [out] IsKnownToBeAllocated Whether the memory to be freed is known
  ///   to have been allocated, or in other words, the symbol to be freed was
  ///   registered as allocated by this checker. In the following case, \c ptr
  ///   isn't known to be allocated.
  ///      void Haha(int *ptr) {
  ///        ptr = realloc(ptr, 67);
  ///        // ...
  ///      }
  /// \param [in] ReturnsNullOnFailure Whether the memory deallocation function
  ///   we're modeling returns with Null on failure.
  /// \param [in] ArgValOpt Optional value to use for the argument instead of
  /// the one obtained from ArgExpr.
  /// \returns The ProgramState right after deallocation.
  [[nodiscard]] ProgramStateRef
  FreeMemAux(CheckerContext &C, const Expr *ArgExpr, const CallEvent &Call,
         ProgramStateRef State, bool Hold, bool &IsKnownToBeAllocated,
         AllocationFamily Family, bool ReturnsNullOnFailure = false,
         std::optional<SVal> ArgValOpt = {}) const;
  ```
* 实际上，`FreeMemAux` 写的并不是那么完美，首先本身指针分析就不是非常的准确，比如调用有关 Free 的函数指针，就不一定能被检测出来。另外 CSA 本身也有一些问题，迭代的次数也是有限的，全局变量初始化也不一定能被分析到，而且 StateRef 也意味着单线程的分析，得到的报告很可能因为路径不可行而成为 FP，因为 CSA 在分析过程中有太多假设了，这些误报理论上应该通过程序的其他信息/规则来得到或者说优化。
* 在种种对入参进行检查之后，才到检查漏洞的相关代码。关于 Free alloca 分配内存，甚至后面还有合法性的检查（如 Double free 检查），与内存的建模关系非常大。

  ```cpp
  // Memory returned by alloca() shouldn't be freed.
  if (RsBase->getAllocationFamily().Kind == AF_Alloca) {
    HandleFreeAlloca(C, ArgVal, ArgExpr->getSourceRange());
    return nullptr;
  }
  // Check for double free first.
  if ((RsBase->isReleased() || RsBase->isRelinquished()) &&
      !didPreviousFreeFail(State, SymBase, PreviousRetStatusSymbol)) {
    HandleDoubleFree(C, ParentExpr->getSourceRange(), RsBase->isReleased(),
                     SymBase, PreviousRetStatusSymbol);
    return nullptr;
  // If the pointer is allocated or escaped, but we are now trying to free it,
  // check that the call to free is proper.
  } else if (RsBase->isAllocated() || RsBase->isAllocatedOfSizeZero() ||
             RsBase->isEscaped()) {
    // Check if an expected deallocation function matches the real one.
    bool DeallocMatchesAlloc = RsBase->getAllocationFamily() == Family;
    if (!DeallocMatchesAlloc) {
      HandleMismatchedDealloc(C, ArgExpr->getSourceRange(), ParentExpr,
                              RsBase, SymBase, Hold);
      return nullptr;
    }
    // Check if the memory location being freed is the actual location
    // allocated, or an offset.
    RegionOffset Offset = R->getAsOffset();
    if (Offset.isValid() &&
        !Offset.hasSymbolicOffset() &&
        Offset.getOffset() != 0) {
      const Expr *AllocExpr = cast<Expr>(RsBase->getStmt());
      HandleOffsetFree(C, ArgVal, ArgExpr->getSourceRange(), ParentExpr,
                       Family, AllocExpr);
      return nullptr;
    }
  }
  ```
* 从 `MallocChecker` 一些 FIXME，TODO 中可以看出 CSA 还存在一些"奇怪"的 bug，如 Ownership 可能会因为存储发生变化。


* 现在来考虑一下如何在 CSA 中实现最基础的静态分析算法（流不敏感）。可以参考下文摘录的部分代码（比较经典的 worklist）。

  ```clike
  bool CFGBlock::isInevitablySinking() const {
    const CFG &Cfg = *getParent();
  
    const CFGBlock *StartBlk = this;
    if (isImmediateSinkBlock(StartBlk))
      return true;
  
    llvm::SmallVector<const CFGBlock *, 32> DFSWorkList;
    llvm::SmallPtrSet<const CFGBlock *, 32> Visited;
  
    DFSWorkList.push_back(StartBlk);
    while (!DFSWorkList.empty()) {
      const CFGBlock *Blk = DFSWorkList.back();
      DFSWorkList.pop_back();
      Visited.insert(Blk);
  
      // If at least one path reaches the CFG exit, it means that control is
      // returned to the caller. For now, say that we are not sure what
      // happens next. If necessary, this can be improved to analyze
      // the parent StackFrameContext's call site in a similar manner.
      if (Blk == &Cfg.getExit())
        return false;
  
      for (const auto &Succ : Blk->succs()) {
        if (const CFGBlock *SuccBlk = Succ.getReachableBlock()) {
          if (!isImmediateSinkBlock(SuccBlk) && !Visited.count(SuccBlk)) {
            // If the block has reachable child blocks that aren't no-return,
            // add them to the worklist.
            DFSWorkList.push_back(SuccBlk);
          }
        }
      }
    }
  
    // Nothing reached the exit. It can only mean one thing: there's no return.
    return true;
  }
  ```

  ```clike
      // At this point we know that 'N' is not a sink and it has at least one
      // successor.  Use a DFS worklist to find a non-sink end-of-path node.
      using WLItem = FRIEC_WLItem;
      using DFSWorkList = SmallVector<WLItem, 10>;
  
      llvm::DenseMap<const ExplodedNode *, unsigned> Visited;
  
      DFSWorkList WL;
      WL.push_back(errorNode);
      Visited[errorNode] = 1;
  
      while (!WL.empty()) {
        WLItem &WI = WL.back();
        assert(!WI.N->succ_empty());
  
        for (; WI.I != WI.E; ++WI.I) {
          const ExplodedNode *Succ = *WI.I;
          // End-of-path node?
          if (Succ->succ_empty()) {
            // If we found an end-of-path node that is not a sink.
            if (!Succ->isSink()) {
              bugReports.push_back(R);
              if (!exampleReport)
                exampleReport = R;
              WL.clear();
              break;
            }
            // Found a sink?  Continue on to the next successor.
            continue;
          }
          // Mark the successor as visited.  If it hasn't been explored,
          // enqueue it to the DFS worklist.
          unsigned &mark = Visited[Succ];
          if (!mark) {
            mark = 1;
            WL.push_back(Succ);
            break;
          }
        }
  
        // The worklist may have been cleared at this point.  First
        // check if it is empty before checking the last item.
        if (!WL.empty() && &WL.back() == &WI)
          WL.pop_back();
  ```

  ## 六、CSA 控制流分析

  对应于源码中的定义: `llvm-project/clang/Analysis/CFG.h` 基于 AST 构建的 CFG。

  ```cpp
    /// Builds a CFG from an AST.
    static std::unique_ptr<CFG> buildCFG(const Decl *D, Stmt *AST, ASTContext *C,
                                         const BuildOptions &BO);
  ```

  ## 七、CSA CallGraph

  对应于源码中的定义: `llvm-project/clang/Analysis/CallGraph.h` 基于 AST 构建的 CallGraph。

  ```cpp
  /// The AST-based call graph.
  ///
  /// The call graph extends itself with the given declarations by implementing
  /// the recursive AST visitor, which constructs the graph by visiting the given
  /// declarations.
  class CallGraph : public RecursiveASTVisitor<CallGraph> {
    friend class CallGraphNode;
    // ...
  }
  ```

  ## 八、CSA 数据流分析

  对应于源码中的定义: `llvm-project/clang/Analysis/FlowSensitive/DataflowAnalysis.h`

  基本思想是通过控制流图（CFG）的边缘传播有关程序的事实，直到到达固定点。[Data flow analysis: an informal introduction](https://github.com/llvm/llvm-project/blob/main/clang/docs/DataFlowAnalysisIntro.md) 受限于静态分析对路径的执行次数上限，（不能太多次展开循环），同时需要对数据进行一个合理的估计。

  ```cpp
    TypeErasedLattice joinTypeErased(const TypeErasedLattice &E1,
                                     const TypeErasedLattice &E2) final {
      // FIXME: change the signature of join() to avoid copying here.
      Lattice L1 = llvm::any_cast<const Lattice &>(E1.Value);
      const Lattice &L2 = llvm::any_cast<const Lattice &>(E2.Value);
      L1.join(L2);
      return {std::move(L1)};
    }
  ```

  ## 九、总结

  可以看出，CFG，DFG，CG 等关键的图都能基于 AST 构建出来，与时下流行的基于 DSL 的静态分析并驾齐驱，相比于 CodeQL 等 DSL 工具。虽然 CSA 在规则编写上会有一些繁琐，但是能客制化更复杂，功能更强的规则以检测代码缺陷。另外，当前静态分析仍然受制于最基础的指向分析（Point-To Analysis），过程间分析的能力，随着静态分析等理论/工具的发展，能检测到的代码缺陷也会变多。但是代码不会因此变得没有漏洞，只是漏洞可能会更深。

  
  ## 十、参考链接

  
  1. [Precise interprocedural dataflow analysis via graph reachability, T Reps, S Horwitz, and M Sagiv, POPL '95](http://portal.acm.org/citation.cfm?id=199462)
  2. [A memory model for static analysis of C programs, Z Xu, T Kremenek, and J Zhang](http://lcs.ios.ac.cn/\~xzx/memmodel.pdf)
  3. [CSA README.txt](https://github.com/llvm/llvm-project/blob/main/clang/lib/StaticAnalyzer/README.txt)
  4. [Getting Started with the LLVM System](https://llvm.org/docs/GettingStarted.html)
  5. [Clang 的編譯——面向 Clang Static Analyzer 開發的編譯配置指北, Xutong Ma](https://blog.oikawa.moe/2021/06/06/clang-%e7%9a%84%e7%b7%a8%e8%ad%af-%e9%9d%a2%e5%90%91-clang-static-analyzer-%e9%96%8b%e7%99%bc%e7%9a%84%e7%b7%a8%e8%ad%af%e9%85%8d%e7%bd%ae%e6%8c%87%e5%8c%97/)
  6. [Data flow analysis: an informal introduction](https://github.com/llvm/llvm-project/blob/main/clang/docs/DataFlowAnalysisIntro.md)