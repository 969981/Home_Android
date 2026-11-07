# Unity / AssetBundle 结构与提取

## 检测准则
使用 ZIP Entry 魔数和解压后文件头检查 `UnityFS` / `UnityWeb` / `UnityRaw`，以及 `*.assets`、`assets/bin/Data`、`resources.assets`、`sharedassetsN` 候选。仅发现 `libunity.so` 只能证明运行时存在，不能证明全部模型包在 APK 内。

## 对象定位
对解析成功的容器枚举每个 ObjectReader 的类型与 PathID；关键类型包括 Texture2D、Sprite、TextAsset、Mesh、Material、AnimationClip、AudioClip、MonoBehaviour、GameObject。使用 `容器路径 + PathID` 唯一标识，不要用中文名称或模型文件名作主键。

## 流水线
```bash
python tools/unity_export.py --version 4.1.0 --max-size-mib 256
python tools/index_db.py --version 4.1.0
```

Texture2D / Sprite：使用 UnityPy 解码 PNG，再用 Pillow 验证；
TextAsset：保留 m_Script 原始字节及 surrogateescape，无法 UTF-8 解码时保存 .bin；
Mesh：能得到 OBJ 网格几何时写 .obj，不能把它算作动画或材质成功；
其他对象：先建来源索引，后续增加专属转换器。

## 失败分类
`parse_failed`、`export_failed`、`skipped_too_large`、`identified_only`、`exported_verified`。未知版本、没有 TypeTree、外部资源缺失都应单独记录。
