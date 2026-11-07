# GitHub Actions / 提交 / Artifacts

工作流 `.github/workflows/unpack-audit.yml` 在 master 的 APK / tools / tests 修改后启动，也允许手动触发。过程包括测试、真实 APK 审计、CRC 解压、格式扫描、UnityPy 尝试转换、SQLite 导入。

- `reports/4.1.0` 小型元数据由 Actions Bot 提交到 Git；ZIP 源文件及原生解包/批量素材默认不做自动 Git 提交。
- `home-4.1.0-audit`：审计、失败日志、源索引和 SQLite（14 天保留）。
- `home-4.1.0-converted-resources`：合法拥有的转换产物（7 天保留）。
- `Unpack/` 与 `resources/` 默认通过 .gitignore 忽略。
- Artifacts 有保留期且可能存在公开访问，上传前核查授权与私人数据。不能当永久冷存储。

本地重复 `extract` 按 CRC 跳过一致文件；`audit` 随 APK SHA 变化重建。规模很大时应再实现按路径哈希分片、worker 多进程与分片清单。
