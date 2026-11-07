# M9 专项：ABA、Unity 引用关系、IL2CPP、运行时缓存

- **ABA**：所有 `.aba` 样本记录文件大小、SHA-256、共同头部、前 64 字节与签名偏移、样本香农熵。头部一致或高熵并不能证明加密，也不代表已完成解包。
- **Unity 材质/动画**：`tools/unity_references.py` 针对 Material / AnimationClip / AnimatorController / MeshRenderer 等从真实序列化对象中枚举 `m_FileID + m_PathID`；`FileID=0` 代表同一 SerializedFile，跨文件对象需要额外解析依赖表。参考 Unity SerializedFile 的 externals/TypeTree 结构。
- **IL2CPP**：已找到真实 metadata v31 及 AArch64 libil2cpp.so，本轮增加 metadata 分段头部校验和 ELF 动态 FUNC 符号审计。只有查到 CodeRegistration / MetadataRegistration 并对照方法表后才能宣布函数地址已恢复，当前不要作该宣称。
- **Runtime cache**：目前仓库只包含 4.1.0 APK。工具允许读取合法获得、去除凭据的缓存目录，仅比较文件名及大小，当前无缓存则输出 `no_runtime_cache_input`，不能推断 CDN 内容。
- **交付**：小型报告提交 Home_Android；实际素材存于私有 PokeHome_Resources `4.1.0/Unpack/Android/4.1.0/`，不与 Switch RomFS 镜像混用。

## 执行命令
```bash
python tools/aba_probe.py --version 4.1.0
python tools/il2cpp_sections.py --version 4.1.0
python tools/unity_references.py --version 4.1.0
python tools/cache_diff.py --version 4.1.0
```

## 新发现：FSB5 子容器
真实 7 个 `.aba` 中，4 个 BGM 文件在偏移 1652、1643、1688、1671 找到 `FSB5` 签名。根据 FSB5 v0/v1 的头部字段实现 `tools/aba_fsb5.py`，校验版本、样本数、sample-header 大小、name-table 大小、data 大小、容器边界后才允许从原始 .aba 中拷贝其子区间至 .fsb。

这只能证明存在有效 FSB5 子容器，不意味着未知 .aba 前部或其他 3 个 cap 文件已解包。公共仓库默认只生成验证报告，私有仓库可用 `--out Unpack/Android/4.1.0` 导出 FSB5 原始流，再用 vgmstream 等工具独立解码。
