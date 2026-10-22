# 内存脱壳任务 · GitHub CI 化执行计划（plan.md）

> 任务：通过 GitHub CI 执行**内存脱壳**，最终交付一份**脱壳后的 zip**。

---

## 1. 任务陈述

- 输出：**脱壳后的 zip**（含脱壳exe、导入表、静态/动态报告、产物 SHA256）。

## 2. 交付物

- 唯一交付物：**脱壳后的 zip**，由 CI 打成一个 Artifact 上传。
- CI YAML 由使用者按本计划自行落地到 `.github/workflows/`。
