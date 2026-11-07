# 图片、音频、模型与 IL2CPP 第三轮实测

Actions #42330421822（2026-11-07）：

- `tools/export_raw_assets.py` 从 APK 原生 ZIP 成员保真复制 **105 个文件**：66 PNG、36 音频候选、3 文本/数据候选，SHA256 均匹配源。
- 原始 DEX 3 个，版本均为 035；classes.dex 有 9,091 class defs，classes3.dex 有 5,737 class defs，classes2.dex 有 13。
- ELF 共 9 个，全部 AArch64；`libil2cpp.so` Build ID `a8788a1e08e2c0f2f1d634115eaa669e3d187184`。
- IL2CPP `global-metadata.dat` 有效魔数 `0xFAB11BAF`，格式版本 **31**；不能把版本 31 误作 Unity 版本。
- 13 个失败的 Texture2D 均叫 `Font Texture`，异常为 `IsADirectoryError`，其引用的源路径落在 `assets/bin/Data` 目录。当前未证明其像素实际存在于 APK；不得导出伪 PNG 或将它归为普通 ASTC 解码失败。
- 前两轮共识别 145 AnimationClip、155 Material、36 AudioClip、35 Mesh；后续逐项导出和验证，不等于已经完成动画与材质还原。

## 下一批
`tools/unity_export.py` 增加 Font 和 AudioClip 的保守导出：可得到内置字节才导出，否则保持 identified_only 并保留原因。
`tools/mesh_to_glb.py` 将 OBJ 网格转换为 GLB，必须验证真实三角面与 GLB 魔数。
保持 **GLB 网格几何成功** 和 **完整动画骨骼模型成功** 两个不同验收级别。
