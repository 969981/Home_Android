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

## 已有的真实 4.1.0 解包证据（2026-11-07）

经 Actions [#42330623437](https://github.com/969981/Home_Android/actions/runs/42330623437) 成功执行：
- APK：1,810 个 Entry，CRC 通过，302,672,347 B 解压数据。
- Unity：1,471 个本地资源容器成功解析，72,842 个对象枚举。
- 导出：**831 Sprite PNG、368 Texture2D PNG、85 TextAsset、35 OBJ、35 几何 GLB、36 AudioClip 音频样本、13 Font 文件**。
- 原生媒体：另外保真复制 66 PNG、36 音频候选、3 文本/数据文件。
- 未解决：13 个 `Font Texture` 像素路径引用不完整；GLB 为网格几何，并非骨骼动画完整模型。
- Native：3 DEX、9 AArch64 ELF；IL2CPP metadata 魔数 `0xFAB11BAF` / version 31 已验证；还未执行完整 JADX/Cpp2IL/Ghidra 分析。

可重复生成的摘要与来源清单已提交到 [reports/4.1.0](reports/4.1.0)。图片、模型、音频等转换文件存放于 Actions `home-4.1.0-converted-resources`（保留 7 天），不默认公开提交大量商业素材。
