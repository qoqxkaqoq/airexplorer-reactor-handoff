# forcedump (patched)

从 [autoreaktor](https://github.com/0301091405/autoreaktor) `v3/forcedump` 复制并修改。

## 改了什么

原版只对**可解析的 MethodDef** 做 `RuntimeHelpers.PrepareMethod`，泛型方法全部落进
`catch { failed++; }`：

```csharp
var body = m.GetMethodBody();          // 开放泛型 -> IL 为空
RuntimeHelpers.PrepareMethod(m.MethodHandle);   // 开放泛型 -> ArgumentException
```

后果是 `InstantiateStatelessUser<T>`（0x060042AC）这类**泛型方法**在 JIT 收割里
只有 `m_*.eh`、没有 `m_*.bin` —— 而 Reactor 的脚本解释器、`DefineSetSet`、
`GenerateAdaptableExtractor` 全在泛型方法里。

补丁：

1. `Instantiate(MethodInfo)` —— 对 `IsGenericMethodDefinition` 的方法用
   `MakeGenericMethod(object/int/string/Guid)` 造具体实例（依次试，兼容 `where T : struct` 等约束）；
2. `InstantiateType(Type)` —— 开放泛型类型（`List<>`）同样实例化；
3. `PrepareMethod` / `GetMethodBody` 都用**实例**，但落盘仍用原始 `MetadataToken`
   （实例化不改 token，所以文件名不变）；
4. 输出加 `genericMethods=N genericTypes=M` 便于确认补丁生效。

IL 在泛型实例间是**共享**的，所以用 `object` 实例化拿到的就是 NecroBit 解密后的真体。
