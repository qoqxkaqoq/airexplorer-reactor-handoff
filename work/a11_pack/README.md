# a11_pack — 崩溃现场与瞬态猎手工具包（board XX-XXI 配套）

## tools/（17 件）
- a11_guard17b-h.py：崩溃现场捕获系列（b=缓冲+深栈、c=JIT 帧 dump、d=可执行页筛选、e-h=exec 区扫描+常量搜索）
- a11_pe.py：PE 解析工具
（注：incept10 为内联脚本未存盘，用法见 board XIX/XX）a9_incept 1-9（8 件）：正常运行瞬态猎手系列（3=资源副本+key 候选、5=大数组、6=桩槽翻转监视、7=t0 高频快照、9=工作缓冲跟踪、10=全保护大区 dump）
- a11_progress.md：崩溃现场深挖进度账本

## crashscene/
- log.txt：guard17b 完整崩溃日志（四异常序列+全线程栈）
- exc80000003/04242420_stack.bin：int3+fail-fast 深栈（0x2000）
- exce06d7363/e0434352_stack.bin：托管异常+.NET 包装深栈
- exc80000003_exec_0x1cd0fe10000.bin：int3 时刻唯一 exec 区（0xe000，含哈希值命中——后判为 CLR LoaderHeap 数据巧合）
- workbuf_viewerdecrypt.bin / workbuf_run2.bin：Viewer 解密工作缓冲快照×2（t=0.0894/0.1091，含骨架+渐进回填覆写）

## 关键结论（board XX/XXI）
- 异常序列：int3(ProcessDebugFlags 反调试) → 0x04242420 fail-fast(code=0x31415927 π) → e06d7363 托管异常 → e0434352
- 校验器架构两说并存：托管 JIT（栈无驱动器帧）vs 驱动器参与（NSTub jmp 0x7ffc1f30d2e8）
- π 常量不嵌机器码（运行时构造）；54 JIT dump=GC 对象指针非代码帧
- 下次：首 Chance 抓异常对象 Message + 反汇编 0x7ffc1f30d2e8

## 未打包（可再生/过大）
- mlres/（626 资源，50MB）：可从 a9_pack/arr_mainlib_1.bin inflate 再生
- incept7/10 大区 dump（216MB）：ASLR 每运行不同，代表性样本已含
