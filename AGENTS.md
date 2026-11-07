# Home_Android — Codex / Agent 规则

## 目标
在不修改原始 APK 的前提下，完成版本化 APK 文件审计、可重复解包、Android / Unity / IL2CPP 检测、图片与文本导出、模型与动画资源登记、SQLite 建索引和 Obsidian 记录。任何步骤未实测不得宣称完成。

## 目录
- `ROMS/<version>/`: 原始只读 APK；严禁覆盖、改名或重打包。
- `Unpack/<version>/`: 解包中间产物与原生资源；可重建，不直接提交大文件。
- `resources/<version>/`: 导出的图像、Sprite、文本、音频、模型、动画及索引；默认不向公开 Git 仓库批量提交版权素材。
- `reports/<version>/`: 可公开的元数据报告及校验清单；不含 APK、帐号凭据、私有数据。
- `tools/`: Python 主程序和各种解码适配器。
- `docs/`: Obsidian 技术文档，格式新发现、失败原因与证据同步记载。

## 工作顺序
1. `python tools/home.py audit --version 4.1.0`，核验 ZIP、CRC、文件名合法性、统计文件类型并生成哈希。
2. `python tools/home.py extract --version 4.1.0`，安全解压到 `Unpack/4.1.0/apk/raw`。
3. `python tools/home.py scan --version 4.1.0`，按文件头、路径和大小建立候选列表；不要仅凭扩展名判定格式。
4. 只有证实存在 Unity 文件才调用 `tools/unity_export.py`。若找到 `libil2cpp.so` 和 `global-metadata.dat` 才进入 IL2CPP 恢复。
5. 生成 `reports/`、SQLite 索引及来源链。每轮更新 `docs/08-计划/里程碑.md`。
6. 运行 `python -m unittest discover -s tests -v`，再提交变更。

## 数据与真实性
- 对每个导出项记录原生路径、APK SHA-256、资源类型、Unity PathID（如适用）、导出路径、导出 SHA-256、转换器版本、状态和错误文本。
- 分清 `identified`（检测）、`parsed`（解析）、`exported`（导出）、`validated`（回读验证）；不能混写。
- 原资源、类型和文字/模型来源必须可追溯；不同版本不可混用原生 offset / PathID。
- 未识别或失败文件保留记录，不能丢弃、伪造成功或强行归类。
- 长任务要有可重试、断点跳过、数量统计和明确的体积/内存限制；避免全量装载到内存。

## 法律与安全
- 只对有合法访问权限的安装包和本地缓存开展分析。不绕过在线身份验证、服务端限制或 DRM。
- 不抓取或上传帐号资料、访问令牌、私人线上内容；Android 端 APK 不等于全部在线资源。
- 不向公开仓库自动上传受保护的原版 APK 副本、全部反编译代码或大量游戏素材。审计报告可以提交，素材优先本地保留。
- GitHub 普通 Git 单文件不得超过 100 MiB；>50 MiB 应考虑重构存储策略，Actions Artifacts 会到期。
- 每次报告说明执行环境、输入 SHA-256、真实执行步骤、成功/失败统计与未完成项。

## 给后续 Agent 的验收要求
- M0：真实 APK ZIP 校验通过、文件类型与哈希报告存在。
- M1：真实提取且每个输出 CRC 可复验。
- M2：Unity 序列化对象成功读取，异常有独立记录。
- M3：图像/文本成功导出并重开校验。
- M4：Mesh/Material/AnimationClip 对象有实际来源索引；**没有真实 GLB/动画播放验证前不得宣称模型已完整提取**。
- M5：代码映射、跨版本对照、运行时缓存须分别建立证据。
