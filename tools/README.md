# 工具与依赖

- `home.py audit`：逐个读 ZIP Entry、魔数初筛、全量 CRC、SHA-256、CSV/JSON。
- `home.py extract`：阻止 ZIP 穿越和 symlink，原始内容安全落盘，CRC 相同则跳过。
- `home.py scan`：本地文件魔数审计、原生库与 Unity/IL2CPP 指示、最大文件榜单。
- `unity_export.py`：仅遍历扫描确认的候选 Unity 文件，导出 PNG、TextAsset 和 OBJ 几何，登记其他对象及失败原因。
- `index_db.py`：汇总 APK Entry 与 Unity 对象 into SQLite，验证完整性。

```bash
python -m pip install -r tools/requirements-unity.txt
python tools/home.py audit --version 4.1.0
python tools/home.py extract --version 4.1.0
python tools/home.py scan --version 4.1.0
python tools/unity_export.py --version 4.1.0 --max-size-mib 256
python tools/index_db.py --version 4.1.0
```

JADX、Apktool、Android SDK Build Tools、Cpp2IL、Ghidra、Blender、AssetRipper 后续根据扫描事实安装在独立 `tools/third_party/`（默认不入 Git）；请固定版本并记录来源及校验和。严禁把 `libil2cpp.so` 的存在直接当作已经找到完整函数符号表。
