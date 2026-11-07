---
title: "HOME Android 4.1.0 — 原生 ARM64 实机单次只读 UTID 观察"
aliases: [HOME41 ARM64 Frida UTID 单次观察]
tags: [pokemon-home, android, frida, arm64, utid, read-only, github-actions]
status: "单次观察工具与 CI 单测已实现；真实 ARM64 Android 账号回调尚未执行"
updated: 2026-11-07
---

# HOME 4.1.0 — 原版客户端启动前的 UTID 捕获

> [!important] 范围
> **不绑定 Nintendo Account**。只研究 Pokémon HOME 自身普通初始化中首次接收 `basic.utid` 的时序；不修改 `utid`、不伪造响应、不发起注册或删除请求、不绕过服务器认证与限流。
>
> 本文包含已完成的**本地工具和模拟单测**，不声称已在 ARM64 Android 实机抓到 ID。

## 1. 验证结论及 GitHub 托管环境限制

| Run | 环境 | 实际证据 |
| --- | --- | --- |
| [#42357608036](https://github.com/969981/Home_Android/actions/runs/42357608036) | GitHub Ubuntu / x86_64 Android + Native Bridge | 实际启动 HOME 4.1.0，完成简体中文、地区列表展开；没有注册，也没有 UTID |
| [#42358724802](https://github.com/969981/Home_Android/actions/runs/42358724802) | Ubuntu ARM64 | `sdkmanager --install emulator` 报 `Failed to find package 'emulator'`，没有 Android 进程 |
| [#42358882236](https://github.com/969981/Home_Android/actions/runs/42358882236) | Apple Silicon macOS 15 | Android emulator 启动十余分钟，ADB 一直无法连接，最终 `Timeout waiting for emulator to boot`；没有运行 HOME |
| [只读观察器静态检查 #42358992327](https://github.com/969981/Home_Android/actions/runs/42358992327) | 普通 Linux CI | Frida JavaScript 语法和静态约束通过，不是实机 Hook |

上述 ARM64 托管 Runner 失败不能推断 HOME 4.1.0 本身在 ARM64 Android 上失败，只说明没有得到可用的原生 Android 测试实例。不要因 Actions 结束状态为绿色就误报捕获成功；本项目 ARM64 两轮诊断 `continue-on-error` 的工作流设计只表示**故障被收集**。

## 2. 源码与真实功能

- `ci/home41_utid_readonly_arm64.js`：原生 IL2CPP 只读 Hook；观察注册、token/login 回调及 `UDManager.SetBasic`，把原始 UTID 只在内存中计算六位**候选**值并和目标比较，不发送原数值；接收一次后解除本 Hook。
- `ci/home41_arm64_readonly_runner.py`：ADB/Frida 控制入口：`preflight`、`observe`、`restart-smoke`。用 `frida.spawn` 在原版 HOME 进程启动前装 Hook，再 `resume`；捕获结束后 `session.detach()`，不运行 `pm clear`、不卸载 APK、不停止 APP 进程。
- `ci/test_home41_arm64_readonly_runner.py`：离线夹具，用于防误操作、APK 版本/哈希校验、模拟 Frida 生命周期与输出脱敏。
- `.github/workflows/home41-arm64-readonly-observer-tests.yml`：公共 CI 仅执行静态检查及单测；没有设备/账号/认证数据。

## 3. 实际 ARM64 设备先决条件

- 一部**你本人控制的、原生 ARM64 Android 设备**，不能以 `x86_64 + libndk_translation` 替代。
- 安装原始 APK（versionCode 81），本地文件 SHA-256 必须是 `8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1`；设备实际安装的 `base.apk` 也需要通过 `adb shell sha256sum` 校验。读取不到则暂停，不绕过校验。
- 已启用 USB ADB；本机可用 Python 3.10+、`adb` 命令和与设备服务版本兼容的 Python `frida`。
- Frida 必须有权附加官方原版 APP 的进程（通常需要对自己的测试设备具备 root/Frida Server 权限）；脚本不通过重签名或打补丁改变原始 APK。
- HOME 的地区、真实适用生日、协议及初始宝可梦等正常首次使用流程仍要在官方 UI 中合法完成；本工具不会自动同意条款、注册、删除或绑定 Nintendo Account。

## 4. Windows PowerShell 本地复现

在仓库目录下运行，替换实际 APK 路径：

```powershell
git pull origin master
adb devices
adb shell getprop ro.product.cpu.abi
py -3 -m pip install frida

$apk = (Get-ChildItem "ROMS/4.1.0/*.apk" | Select-Object -First 1).FullName
py -3 ci/home41_arm64_readonly_runner.py preflight --apk "$apk"

# Frida Server 应已在自己控制的 ARM64 Android 设备上正常运行。
# 首次 HOME 数据下发必须从进程创建前观察；目标号码仅在本地内存中比较。
py -3 ci/home41_arm64_readonly_runner.py observe --apk "$apk" --target 888888 --timeout 600

# 命中后若要单独验证官方 APP 冷启动，在确认自身账号状态后显式运行：
py -3 ci/home41_arm64_readonly_runner.py restart-smoke --apk "$apk"
```

`observe` 的重要状态：
- `original_home_running_with_read_only_hooks`：仅说明原版进程已由 Frida 启动；尚未证明注册或 ID 收取。
- `read_only_observer_ready`：对应指定 `libil2cpp.so` 的 Hook 装载成功。
- `first_basic_utid_observed`：首次读到可解析数字，输出 `candidate_matches_target` 布尔值及是否来自已知公共 basic 消费点。
- `first_basic_captured_unverified_display_semantics`：仍需以 HOME 画面确认其是否等于真实六位 ID；**不代表**账号已经保存或可以重启。
- `timeout_no_basic_observed`：超时不代表游戏没有 `utid`，可能注册尚未完成、回调未触发、Hook 地址不适用或服务器通信问题。

## 5. 客户端接管验收

正式完成“目标命中后打开原版 APP 继续使用”至少有三项独立证据：

1. **服务端状态**：原版 APP 正常完成允许的单次初始化，Hook 只读观察到 `basic.utid`（并和官方 HOME UI 显示的 Trainer ID 一致）。
2. **进程可接管**：Frida Host 断开连接后，原版 APP 继续在同一进程内显示菜单、允许正常操作。
3. **冷启动持久性**：主动退出官方 APP，独立运行 `restart-smoke` 后再次进入 HOME，客户端可正常登录且显示同一个 ID；`restart-smoke` 只能自动确认启动命令发出，**同号和会话恢复仍需人工/后续合法的可验证采样**。

单次非 UI **读取**与完全非 UI **注册**是两个不同任务。现有脚本只实现前者的待实机捕获管线，不伪称已经绕开初始化 UI、批量注册或达到目标后保存账号。

## 6. 公开报告安全约定

公开仓库可以保存 Hook、偏移、哈希、布尔目标匹配、测试失败原因、回调相对时间及充分脱敏的结构化报告。不能上传真实 Cookie、UUID、CID、Nintendo 令牌、原始 `basic.utid`、完整 logcat、认证包、设备唯一标识或可能包含这些信息的屏幕私有截图。即使不绑定 Nintendo Account，HOME 仍可能生成自身的登录会话和服务端资料。


## 7. 2026-11-07：双阶段真实验收入口

现在另有 `ci/home41_arm64_runtime_acceptance.py`，它把单次 `observe` 扩展成真正有条件的三个验收门槛：

1. **Hook 与 UI 对账**：原生 ARM64 进程的 `UDManager.SetBasic` 捕获到首个数字候选后，操作者查看 HOME 的真实六位 ID，在本地终端无回显输入。Frida `rpc.exports.comparevisibleid()` 仅返回 `displayed_id_matches` 布尔值。**原 ID 不通过 Frida 消息输出，也不上传 GitHub。**
2. **APP 不被破坏**：第一阶段结束后执行 Frida `session.detach()`；ADB 验证 `jp.pokemon.pokemonhome` 进程仍在运行，操作者在实际手机确认原 APP 可正常操作，只有输入 `yes` 才继续。
3. **真正的冷启动同号**：本地交互允许后，执行官方 Android `am force-stop jp.pokemon.pokemonhome`，再 `frida.spawn → attach → resume` 观察第二次 `SetBasic`。将第二次的原始候选在 APP 内存中与**第一次输入的显示 ID**比对；Frida 断开后再次要求操作者确认 APP 显示同一 ID 且可操作。

本地 PowerShell：

```powershell
git pull origin master
$apk = (Get-ChildItem 'ROMS/4.1.0/*.apk' | Select-Object -First 1).FullName
py -3 -m pip install frida
py -3 ci/home41_arm64_runtime_acceptance.py --apk "$apk" --target 888888 --timeout 600
```

如果同时连接多个 Android 设备，可指定 `--serial <adb-serial>`，但应确保 Frida Device ID 也对应正确设备。必须预先在本人控制的原生 ARM64 测试设备上配置兼容的 Frida Server。原版 APK 应先安装，不使用重签名版本；非原版 APK、ABI 不符、版本号或设备上实际安装的 `base.apk` 哈希不符会直接拒绝 Hook。

### 双阶段状态含义

| 控制台结果 | 实际证明 |
| --- | --- |
| `phase_complete: first_basic_matches_displayed_id` | 对应一次动态 `SetBasic`，从内存读取的候选与手工输入的官方 UI 六位值一致（若设备真实连接且 Hook 成功） |
| `client_handoff: normal_client_usable=true` | Frida 已断开且操作员在真实 APP 中确认能继续使用 |
| `phase_complete` phase=2 | 冷启动产生了**第二次**原生 `SetBasic` 读数，与第一次手工记录的 UI ID 一致 |
| `acceptance_complete: REAL_DEVICE_THREE_GATES_PASSED` | 完整完成双阶段读数 + UI 核对 + 原版接管 + 冷启动验证，且仅在真实 ARM64设备交互脚本执行后才有此含义 |

即使三个门槛都通过，也只能证明测试的 HOME 会话身份连续性，不代表非 UI 批量注册、删除流程或 Nintendo Account 绑定机制被实现。

### 新增离线测试，不可冒充实机验收

- [Actions #42360875688](https://github.com/969981/Home_Android/actions/runs/42360875688)：Python 2 阶段模拟控制流程 **8/8 单元测试通过**，既有 ARM64 启动工具测试 **11/11 通过**，Frida JS 语法检查通过。
- 模拟用例包括两次读到同号通过、第二次读到不同号码必须失败、第一阶段与 UI 不一致时不触发冷启动、拒绝冷启动时不继续、APP 接管失败时停止、第二次界面确认失败时停止、脱敏日志与输入有效性检查。
- **没有连接真实 ARM64 Android、没有访问 HOME 注册服务、没有执行真的 `SetBasic` 回调、没有得到真正的六位 ID。** 假 Frida 事件只用于验证控制程序不会误报或删除 APP 数据。

下一项唯一真正缺失的证据：原生 ARM64 Android 设备的动态 `SetBasic` 入口命中、官方 UI ID 与回调值一致、冷启动后第二次命中与官方显示同号。GitHub 托管 x86_64 模拟器不能代替这项验收。


### 2026-11-07 最新 CI 回归：9 + 11 测试通过

- 最终验证：[Actions #42361056992](https://github.com/969981/Home_Android/actions/runs/42361056992)，共 9 项两阶段流程夹具与 11 项单次 Hook/输出防泄露夹具，**20/20 通过**，Frida JS 已通过 `node --check`。
- 新增约束：仅收到 Android `am force-stop` 退出码不足以宣称冷启动。必须再通过 ADB 确认**旧 HOME 进程确实消失**；否则记录 `previous_home_process_still_alive` 并停止第二阶段。
- 新增离线负例：模拟 `force-stop` 返回成功但进程仍在，确认脚本拒绝宣称 `REAL_DEVICE_THREE_GATES_PASSED`。
- 实际设备尚未连接到当前执行环境，因此 **`UDManager.SetBasic` 的真实动态命中、官方六位 ID 对账、冷启动同号三项仍未实测**。单元测试不能替代这些证据。


### 2026-11-07：补齐来源追溯与独立进程身份检查（最终 22 项离线测试）

这次将“真实验收”严格化，而非只增加静态检测。以下条件已经落在 `ci/home41_arm64_runtime_acceptance.py` 的**实际成功路径**：

1. 捕获前必须收到 `read_only_observer_ready`，不能把未完成安装的回调假定为有效。
2. `UDManager.SetBasic` 在 ARM64 入口读取到的 `UD_Basic.utid`，其 `LR` 必须恰好等于原生公共响应消费点 `libil2cpp.so+0x1D2BA68`；否则返回 `first_basic_caller_not_verified_common_response`，不进行成功上报。由于这只是静态研究给出的候选调用点，如果真实设备 LR 不同，必须先重新分析而不是绕过来源门槛。
3. 显示的六位 ID 与首次 Hook 计算候选值一致；若不一致，返回 `runtime_utid_display_id_mismatch`，禁止冷启动。
4. Frida 断开后，操作者确认原 APP 可正常操作，而且能取得有效运行中 `pidof`。
5. 操作者明确允许执行 `am force-stop`；确认此时 APP 已无进程，且第二次启动的实际 PID 与第一次的 PID **不相等**。否则返回 `new_process_identity_not_confirmed`，不能把热启动伪装为冷启动。
6. 第二次 `SetBasic` 同样来自已知公共响应消费点，且再次与第一阶段仅保存在本机内存的官方显示 ID 相等。操作员还需在画面确认同号。

证据严格分级：
- **已验证（离线）**：最新 [Actions #42367132737](https://github.com/969981/Home_Android/actions/runs/42367132737) 完成 **11 项双阶段负例/流程测试 + 11 项单次运行器测试，共 22/22 项通过**；其中包括伪造公共响应来源和重复 PID 的拒绝测试。
- **尚未验证（真实设备）**：这一轮没有连接 Android 手机或原生 ARM64 客体，也没有真实 `first_basic_utid_observed`、官方 ID 对账或冷启动持久化数据。只有在个人控制的 ARM64 Android 上完成 `ci/home41_arm64_runtime_acceptance.py` 的完整现场操作，才可另行记录真实验收结论。

目前 GitHub 托管 Linux ARM64 / macOS Apple Silicon Android Emulator 实验均无法提供工作中的 ARM64 Android 客体；当前助手运行容器也没有 `adb` 或已连接的 Android 设备。因此**不能将 22 项模拟测试等价为你要求的三项真实验收**。

公开仓库只保存观察器、校验流程和脱敏通过/失败报告；使用者在本人设备上手工输入的六位 ID 不回显、不写入日志，也不上传 Github。
