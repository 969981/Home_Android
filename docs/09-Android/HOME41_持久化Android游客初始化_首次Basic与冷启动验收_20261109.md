---
title: "HOME 4.1.0 持久化 Android：游客初始化 → 注册 → 首次 basic → 冷启动"
date: 2026-11-09
status: "本地验收流程和静态测试已准备；真实持久化设备尚未完成现场验收"
tags: [pokemon-home, android, frida, arm64, guest, il2cpp, utid]
---

# HOME 4.1.0：持久化 Android 官方游客初始化验收

## 当前可靠起点

[Actions #42551816996](https://github.com/969981/Home_Android/actions/runs/42551816996) 的 attempt 2 已证明原版客户端点击“以游客身份开始使用”，`ConfirmGestAccountSecond` 命中一次，画面改变。但当时 `registration_serializer=0`、`registration_response=0`、`token_response=0`、`first_basic_utid=0`。这**不是注册成功，也不能证明服务器一定未收到任何请求**。此时尚未观察到头像选择、初始小火龙、用户六位 ID 或持久会话。

新增本地时间线监控：
- `firstboot_confirm_gest_second_entered`：原始第二确认方法；
- `guest_second_direct_callee_unclassified_entered`：原始二进制中可核实的 `0x1DE53DC → 0x1DEB3C0` 被调位置，**不能直接认作注册闭包**；
- `post_guest_candidate_1098_entered`、`post_guest_candidate_16f4_entered`：两个未完成对象所有权确认的后继候选；
- `auth_manager_register_user_entered`：原始 `ApiManagerLogin.AtuhRegisterUser`，RVA `0x1D2F8DC`；
- `registration_request_serializer_entered`、`registration_response_handler_entered`、Token/Login response、`first_basic_utid_observed`。

时间线 `guest_path.chronological_pairs` 只有**两端都在同一场实验看到时**才比较相对顺序；若缺一个就是 `null`。即使全部显示 `true`，也只是观察到按顺序发生，不能证明这些调用属于同一个服务端事务或已成功持久化。

## 推荐实际环境

使用**本人控制、可保留 /data 的原生 ARM64 Android 手机或持久 Android 环境**，运行原版未重签 HOME 4.1.0 (versionCode 81)，ADB + 兼容 Frida Server。优先原生 `arm64-v8a`；x86_64 + NativeBridge 属于另一类实验，不可冒充原生 ARM64 冷启动验收。需要自行管理设备解锁与 Frida 权限；不要为了测试反复清除 HOME 数据。

必须在本机验证官方 APK SHA-256：

`8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1`

脚本会同时核对设备安装的 `base.apk` SHA。无法核对就停止，不绕过校验。本地 Frida/ADB 只能访问本人授权的设备。

## 阶段 A：真实首次游客初始化 + 原生链路记录

Windows PowerShell（在 `Home_Android` 仓库根目录，原版 APK 已在 `ROMS/4.1.0`）：

```powershell
git pull origin master
py -3 -m pip install "frida==17.26.1"
adb devices
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.dalvik.vm.native.bridge

$apk = (Get-ChildItem '.\ROMS\4.1.0\*.apk' |
    Select-Object -First 1).FullName

py -3 ci/home41_arm64_readonly_runner.py preflight --apk "$apk"

# 在全新的、由本人控制且尚未注册过的本地 HOME 测试环境运行。
# Frida Server 已在设备上正常启动；会 spawn 原版 HOME、注入只读 Hook。
py -3 ci/home41_arm64_auth_timeline.py `
    --apk "$apk" `
    --realm native `
    --timeout 1800 `
    --output ".\local-home41-auth-timeline.json"
```

如需在自己的交互终端核对首个 UTID，可显式加 `--show-local-values`；默认不会显示原始 ID。不要将开启该标志的终端回显、真实 ID 或截图发布到公开 Actions/仓库。

在上面命令运行期间，仅在**官方原始 HOME UI** 中完成已授权的一次流程：出生日期 1999/4/5 → 服务条款/隐私同意 → Nintendo Account **不关联** → 游客第一层“是” → 第二层“以游客身份开始使用” → **检查原版新页面** → 首个有效头像 → **小火龙（Charmander, 图鉴 #0004）** → 正常完成官方注册和引导。初始头像、宝可梦对应的实际控件还未取得验收截图，因此不能硬编码未知坐标，不得通过猜测按钮代替真实选择。

本脚本**不自动同意条款、不点击游客创建、不注册 API 重放、不删除账号**。记录结束会断开 Frida，保留正常 APP 进程和 userdata。实机一次性开户后不要重新运行首次注册 UI；继续在同一持久环境验证登录与冷启动。

## 阶段 B：逐项证据门槛

| 证据 | 通过条件 | 注意 |
| --- | --- | --- |
| 二次确认 | `firstboot_confirm_gest_second_entered` | 仅 UI 回调 |
| 原始直接被调位置 | `guest_second_direct_callee_unclassified_entered` | 不代表注册入口的真实所有权已闭合 |
| 注册管理器 | `auth_manager_register_user_entered` | 必须在 UI 确认后检查 |
| 请求 DTO | `registration_request_serializer_entered` | 不能单独证明 HTTP 已发送 |
| 注册响应 | `registration_response_handler_entered` | 回调可能处理失败响应，仍需核对服务器后续状态 |
| Token/Login | 对应 serializer/response callback | 调用次数和顺序不等于认证成功 |
| 首次资料 | `first_basic_utid_observed`，且 `from_common_basic_consumer=true` | `basic.utid` 是 HOME 账号资料字段，不是 UUID/CID/SUPID |
| 六位 ID | 原版 UI 显示的六位号与从 `basic.utid` 算出的候选相同 | `utid % 1000000` 仅是待验证候选算法 |
| 小火龙 OT | 在正常 UI/合法数据视图核对 OT/TID/SID | 不得直接假定等于 HOME six-digit ID |

出现 Second 回调，但未观察到注册管理器或序列化：**不要重复点击游客注册按钮**。保留当前设备上的原版页面，先排查是否还需选头像/初始宝可梦、网络连接是否正常、提示有无服务端错误；报告未命中，并检查 `guest_hook_coverage` 是 `true`、`false` 或 `null`。仅 Hook 确认安装成功而计数为 0，才可以说本次观察窗口没有命中该入口。

## 阶段 C：冷启动和账号持久化

先确认原版 HOME 菜单已可正常使用，且首次显示的六位 ID 已在**本人的设备上**核对。不要清除 App 数据，不要删除账号，不要重新安装。

首次时间线结束后，可只做 Android 进程停止（不清除 userdata），再启动已有双阶段验收工具：

```powershell
# 前提：阶段 A 已完成真实官方单次注册，界面能正常进入 HOME。
adb shell am force-stop jp.pokemon.pokemonhome

py -3 ci/home41_arm64_runtime_acceptance.py `
    --apk "$apk" `
    --target 888888 `
    --timeout 600
```

该工具会依次运行：
1. 原生 ARM64 Frida spawn + 首次资料 `SetBasic` 事件，并在本地**无回显**输入 HOME UI 六位 ID；RPC 仅返回匹配布尔值。
2. Detach 后确认原版客户端正常继续使用。
3. 再次经操作者确认才 `force-stop`；验证旧 PID 消失，新 PID 与旧 PID 不同。
4. 冷启动后二次 `SetBasic` 与**同一 UI ID**比对，再由操作者确认页面同号。

只有实际私有设备运行并返回 `REAL_DEVICE_THREE_GATES_PASSED`，才可以说冷启动三道门槛全部通过。若冷启动没有新的 `SetBasic`，不得直接宣称账号未持久化；可能命中不同的缓存/启动分支，需要另外审计。

## 本次变更与未完成项

- 新增本地时间线 `guest_path`、六组严格时间顺序比较、Hook 成功覆盖率报告；
- 新增 `ci/test_home41_guest_persistent_chain.py`，静态测试不执行 HOME、不访问注册服务器；
- 更新 `.github/workflows/home41-arm64-auth-timeline-tests.yml` 加入这些离线用例。

**本轮未连接用户本人可持久保存的 Android 实例。** 未执行新的游客开户、未获得真实 `basic.utid`、未核对头像或小火龙、未完成冷启动同号测试，亦未验证新增 CI 的执行结果。不得将本地可复验脚本/公开测试“通过”写成已创建真实账号。


## 2026-11-09：第二次确认后头像／序章／注册链的进一步分界

**阶段枚举取自原版**：`FirstBootBodyController.Phase` 中
15=`MT_SELECT_ICON`、16=`MT_INPUT_NAME`、17=`MT_INPUT_BIRTH`、
21=`PROLOGUE`、22=`PROLOGUE2`、23=`GEST_CONFIRMATION`、24=`ALL_END`。
阶段枚举存在，不代表游客流程必定到达该页，更不代表页面已经渲染。

`ci/home41_arm64_auth_timeline.py` 新增
`guest_path.post_second_phase_requests`：只将同一次 Frida
事件流中 **`firstboot_confirm_gest_second_entered` 之后**真实发生的
`firstboot_go_to_phase_entered` 分类并保留相对时间。
每项都标识 `request_only_not_confirmed_render=true`。
没有第二确认事件（例如观察器附加过晚）时不能将先前 Phase 值错算为“确认后导航”。

应按以下证据分层判断：
1. 看到 `GoToPhase(15)`：仅说明请求了 `MT_SELECT_ICON`，必须再有对应原版 View 初始化证据或设备上可核对的头像 UI，才算真实出现头像选择页面。
2. 看到 `GoToPhase(21/22)`：仅说明请求了 `PROLOGUE/PROLOGUE2`，需要初始宝可梦实际界面或具名原生方法再闭合。
3. `auth_manager_register_user_entered` 命中、随后 `registration_request_serializer_entered` 命中：说明客户端经过注册管理器和序列化入口，仍不能凭这个断言成功发包、服务器建号成功。
4. `registration_response_handler_entered` 出现：响应处理回调被调用，但未核对成功码；必须继续跟 Token/Login 和正常用户资料 `basic.utid` 及 HOME UI。
5. 最终确认之后没有头像／序章阶段请求、也没有注册调用：首先检查动态 Hook 覆盖、真实原版页面、网络错误及是否存在转场后新的控制器对象。不要连续重复点击建号按钮。

### 私人持久设备上的实际页面证据

新增 `ci/home41_private_postguest_screen.py`（**仅本机交互终端**），不触发按钮点击、不重启、不改 HOME 存储、不能在 GitHub Actions 中运行。点击完原版最终游客确认后，保留游戏前台，在另一终端执行：

~~~powershell
py -3 ci/home41_private_postguest_screen.py --label after_guest --i-understand-this-is-private
~~~

如确实出现头像页、初始宝可梦页，可分别在这些页面运行 `--label avatar`、
`--label starter`。每个标签仅创建一张私有照片，
路径为 `local-home41-private/<label>.png`，不会覆盖已有照片。
**标签是操作者填写的说明，不是算法验证的 UI 身份。**
输出目录和 `local-home41-*.json` 已加入仓库根目录 `.gitignore`，
避免误提交；它不代替对截图内容的人工/原生验证。

此类图片可能含用户账号信息，禁止上传到公开 GitHub Actions、
公开 Issue 或公开 Obsidian。只有确认没有任何身份信息后，
才考虑手动裁剪必要的非敏感 UI 局部与研究资料核对。

新添本地安全用例 `ci/test_home41_private_postguest_screen.py`：
禁止 CI/非交互终端、要求 HOME 前台、拒绝覆盖图片和目录穿越。
本轮依旧没有可访问的持久化 Android 设备，**所有新增动态步骤尚待实机**。
