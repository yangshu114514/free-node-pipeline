# docs/ 技术文档

面向后续维护者的代码事实手册。所有数字与行为均以代码为准，写文档前逐项核对过源码。

| 文档 | 内容 |
|---|---|
| [architecture.md](architecture.md) | 整体架构：GitHub Actions → CF KV → Worker 分发；KV 键表、订阅与 ETag、6 个策略组、链式代理设计 |
| [pipeline.md](pipeline.md) | 五阶段筛选流水线逐步细节：各脚本输入输出、关键参数、耗时基线、重建触发 |

入口与命令速查见仓库根 [README.md](../README.md)。
