# 使用 ADB 在本地采集 HOME Android 4.1.0 可访问的资源缓存

先安装 Android SDK Platform-Tools，设备通过 USB 调试连接，检查 `adb devices`。在用户自己的测试设备运行 HOME 至模型查看器后，执行：

```powershell
python tools/adb_cache_collect.py
# 先仅列出匹配外部存储文件名的候选；不会复制任何数据

python tools/adb_cache_collect.py --pull --limit 300 --out .\home41_cache_export
# 只允许 __data、.bundle、.unity3d、.assetbundle、.assets、图片、音频和 GLB 等后缀，
# 实际复制后还要检测文件魔数，只保留已知格式并验证 SHA-256。
```

输出目录不包含 APK 所属帐号私有目录、会话令牌或访问凭证；不会进入 `/data/user/0`，不会调用调试注入/提权/协议拦截。

接着运行：

```powershell
python tools/runtime_cache_inventory.py --version 4.1.0 --cache-dir .\home41_cache_export --out .\home41_runtime_assets --report .\home41_runtime_report
pip install -r tools/requirements-unity.txt
python tools/pokemon_cache_scan.py --version 4.1.0 --assets .\home41_runtime_assets --report .\home41_runtime_report --out .\home41_pokemon_export
```

经过检查后只将 `home41_cache_export` 中确认为游戏资源且没有账号资料的文件复制进 **私有** `PokeHome_Resources/Unpack/Android/4.1.0/runtime_cache_input/`，推送到 `4.1.0` 分支即可触发 `android41-runtime-cache-audit.yml`。

**限制：** Android 可能禁止访问 `Android/data`，或者真正 Unity 临时缓存位于普通设备无法读取的私有 `/data/user/0/.../cache`。遇到权限拒绝时脚本直接报告 `external_files_unavailable`，不会假装找到文件或突破访问控制。用户在自己的可授权测试模拟器中取得私有缓存后，可以交给同一个离线分析器，但不应上传整个账户私有数据。
