# Unity 22 序列化资源与 split 分卷重组（2026-11-07）

## 实测证据来源

来自首次 Actions #42329971199 生成的 `reports/4.1.0/apk_entries.csv`：
- ZIP Entry：1,810；原始 Android APK CRC 全部通过；总解压大小 302,672,347 B。
- `assets/bin/Data/` 下有 **1,465 个无扩展名、32 位十六进制名称文件**。它们的前 20 字节为 `00000000 00000000 00000016 00000000 00000000`，与 Unity SerializedFile format=22 的扩展头结构吻合。
- `assets/bin/Data/sharedassets0.assets.split0` 至 `split58` 共 **59 个文件**，其中大多数是 1 MiB；拼接是恢复逻辑上的 `sharedassets0.assets` 所必需。
- `assets/AB/` 下另有 7 个 `.aba` 文件，魔数以 `7e5a93307bfa0ddc` 开始；**格式未确认，不当作普通 UnityFS**。

## 为什么首次 UnityPy 只解析 3 个容器
首次分类仅将 `.assets` 后缀、UnityFS 魔数等列为 Unity 候选，结果 3/3 成功、3,481 个 Unity 对象，基本为 MonoScript / GameObject / MonoBehaviour，未导出图片。该结果说明扫描策略不完整，不能推论“APK 没有图片”。

## 第二轮策略
1. 分类器识别 `assets/bin/Data/` 中 serialized format 22 的扩展头（格式和路径同时命中）；避免把普通全零文件误判。
2. 明确标注 `unity_split_chunk`，按数字顺序拼接 split0..N，拒绝任何不连续分卷；保留所有原始 split 文件不变。
3. 将拼接结果写入 `Unpack/4.1.0/unity/reassembled`，纳入 UnityPy，但标记 `@reassembled/` 以避免将派生文件误认为 APK 原始 Entry。
4. 每个对象建立 `source_path + PathID` 来源链，导出 Texture2D、Sprite、TextAsset、Mesh OBJ，分开计数成功、跳过和失败。
5. 逐条确认对象内容，避免将 Mesh OBJ 当作已完整恢复的骨骼与动画。

## 后续专项
- 解析 `.aba` 的容器头和文件表，先比对格式证据、不要无依据地修改字节。
- Unity SpriteAtlas / 纹理外链支持与图集切片坐标。
- JNI / IL2CPP 映射：`libil2cpp.so` 与 `global-metadata.dat` 已在真实 APK 中同时发现。
- 完整模型 + 贴图 + 骨骼 + 动画导出仍需独立验收。
