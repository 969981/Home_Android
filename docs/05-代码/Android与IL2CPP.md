# Java / Native / IL2CPP

## 判定条件
扫描报告明确列出 .so ELF 及其名称。发现 `libil2cpp.so` 和 `global-metadata.dat` 两者后，才启动 Cpp2IL 或 Il2CppDumper。未找到则记录“未在 APK 中证实”，不是判断 APK 完全不可能使用原生代码。

## 路径
AndroidManifest.xml / classes*.dex -> JADX / Apktool；
lib/<abi>/*.so -> readelf / Ghidra；
Unity IL2CPP -> metadata 类型索引、方法名、调用关系以及对应 BuildID。

## 跨平台研究
将 HOME Android 4.1.0 与 Switch HOME 4.1.0 通过稳定的物种/形态/道具等业务 ID 对接，不能把 Switch main+offset 或对象地址复用到 Android 代码。

## 边界
不反编译并公开上传整个商业应用代码；不抓取账号令牌或绕过在线账户认证。
