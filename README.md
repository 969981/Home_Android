# Home_Android — Pokémon HOME Android 资源研究

当前原始输入：`ROMS/4.1.0/` 下的 APK（versionCode 81 / arm64-v8a）；仓库最初仅有这份 APK。**本仓库的目标是研究和可重复处理资源，不代表 APK 自带完整的宝可梦模型、图鉴、所有语言包或运行时远程资源。**

## 项目结构

```text
ROMS/<version>/           原始 APK（只读）
tools/home.py             audit / extract / scan 入口
tools/unity_export.py     Unity 对象登记、PNG 与 TextAsset 导出
tools/index_db.py         SQLite 索引构建
Unpack/<version>/         原生 APK 解包（默认不入 Git）
resources/<version>/      图片、精灵、文本、数据、模型/动画候选（默认不入 Git）
reports/<version>/        元数据报告（可提交）
docs/                     Obsidian 技术说明与里程碑
tests/                    样本验证
.github/workflows/        GitHub Actions 可重复执行
```

## 本地运行

Python 3.10+：

```bash
python -m unittest discover -s tests -v
python tools/home.py audit --version 4.1.0
python tools/home.py extract --version 4.1.0
python tools/home.py scan --version 4.1.0
python -m pip install -r tools/requirements-unity.txt
python tools/unity_export.py --version 4.1.0
python tools/index_db.py --version 4.1.0
```

无需假定 Unity：`scan` 会报告 `libunity.so` / `libil2cpp.so` / `global-metadata.dat` 是否在 APK 中，并列出 Unity 资源候选。没有证明类型前不盲目调用解析器。没有 Unity 对象时，导出器只报告 0 项或显式跳过。

## GitHub Actions

`.github/workflows/unpack-audit.yml` 在推送后对仓库内实际 APK 运行审计、解包、候选扫描、可选 Unity 导出与 SQLite 建库。工作流将摘要和文件清单保存到 `reports/<version>/`；完整中间文件不应自动提交到公开仓库。Actions Artifacts 有保留期限，不能作为唯一长期存储。

## 验收与边界

- `audit` 成功 ≠ Android 代码反编译成功。
- `scan` 检测 Unity 候选 ≠ 所有 AssetBundle 读取成功。
- Mesh / Material 对象可列出 ≠ 骨骼动画与模型已成功导成 GLB。
- APK 本地文件 ≠ 联网下载的全部素材；运行时缓存必须另外合法收集并独立标明来源。
- 不上传授权不明的批量版权素材或用户帐号数据。

详细进度见 [里程碑](docs/08-计划/里程碑.md)，执行约束见 [AGENTS.md](AGENTS.md)。
