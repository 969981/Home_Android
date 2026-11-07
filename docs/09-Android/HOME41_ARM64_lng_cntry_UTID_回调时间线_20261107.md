---
title: "HOME 4.1.0 ARM64：lng/cntry 注册请求序列化 → 首次 basic.utid 只读时间线"
aliases: [HOME41 ARM64 接口时序, HOME41 lng cntry basic utid]
tags: [pokemon-home, android, arm64, frida, il2cpp, registration, login, utid, obsidian]
status: "原生 RVA 静态核对、只读观察工具和离线测试完成；真实 ARM64 Android 首次接口时序尚待实机"
updated: 2026-11-07
---

# 1. 目的与证据边界

用户希望进一步确认语言 `lng`、地区 `cntry` 在 HOME Android 4.1.0 的什么时候被打入注册请求，以及服务器在何时第一次提供 `ResponseParamCommon.basic.utid`，尽可能避免进入初始小火龙的资料 UI 才知道候选 6 位训练家 ID。

**不绑定 Nintendo Account**；只读观察**官方正常使用过程**。脚本不自动点击出生日期、协议、注册、删除、OAuth、申请或重放任何接口，也不更改请求、响应、HOOK 值或原版 APP 文件。

已知 2026-11-07 真实 x86_64 Android 15 模拟器可以完成简体中文、地区中国大陆的确认，进入出生日期页，并经 Frida 17.26.1 成功附加 `HOME` 进程：[#42373557738](https://github.com/969981/Home_Android/actions/runs/42373557738)。但客体是 `x86_64 + ARM Native Bridge`，所以不能把 ARM64 RVA 直接用于这台客体。该轮没有注册账号、没有拿到 utid，libc 的 `connect/getaddrinfo` 计数为 0 不能证明无 HTTP。

# 2. 来源：已核对的同构建 ARM64 RVA

以下信息来自同一原 APK 和 180,628 条 IL2CppDumper 方法目录，以及**独立 AArch64 指令级反汇编**。

- APK SHA-256：`8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1`。
- `libil2cpp.so` SHA-256：`80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe`。

| 事件名称 | 入口/已识别指令 RVA | 已知含义 |
| --- | --- | --- |
| `registration_request_serializer_entered` | `0x1D334A4` | `ApiRequestAuthRegisterUser.SerializeRequestParameter` 进入 |
| `registration_lng_cntry_packed_write_seen` | `0x1D335C0`，紧接 `0x1D335BC` 后 | 注册 DTO 的 `+0x28/+0x2C` 两个整数 `lng/cntry` 已被写入候选 |
| `registration_request_formatter_entered` | `0x205AEF0` | `ApiAuthRegisterUserRequestParamFormatter.Serialize` 真正格式化请求业务 DTO（仍不等于 HTTP 已发送） |
| `registration_response_formatter_entered` | `0x205DA3C` | `ApiAuthRegisterUserResponseParamFormatter.Deserialize` 开始解析注册专属响应（该专属 DTO 无 UTID） |
| `registration_response_handler_entered` | `0x1D33294` | `ApiRequestAuthRegisterUser.CallAfterResponse` 进入；不代表 HTTP 成功 |
| `token_request_serializer_entered` | `0x1D35888` | `ApiRequestCreateToken.SerializeRequestParameter` |
| `token_response_handler_entered` | `0x1D35AD0` | Token 响应回调进入 |
| `login_request_serializer_entered` | `0x1D3BE50` | `ApiRequestLogin.SerializeRequestParameter` |
| `login_response_handler_entered` | `0x1D3C020` | 登录响应回调进入 |
| `common_response_handler_entered` | `0x1D2AFF0` | `ApiManager.CallbackResponseHook` |
| `first_basic_utid_observed` | `SetBasic 0x1D763D0`，唯一公共调用返回 `LR=0x1D2BA68` | 从 `ResponseParamCommon.basic` 下发到 `UDManager.SetBasic` 的托管 `utid` 字符串首次被读取 |

字段来源的原生汇编：

```asm
0x1D335AC LDR D0,[X19,#0xA0] ; packed language / country
0x1D335BC STR D0,[X20,#0x28] ; 注册 DTO 输出位置
...
0x1D2BA60 LDR X0,[X21,#0x18] ; common response.basic
0x1D2BA64 BL 0x1D763D0    ; UDManager.SetBasic
0x1D2BA68 AND W19,W19,W0   ; 唯一验证的直接返回地址
...
0x1D76C1C LDR X1,[X19,#0xF0] ; UD_Basic.utid 字符串引用
0x1D76C20 STR X1,[X0,#0xF0]! ; 存入基础资料对象
```

请求 DTO 的静态字段列表为 `csrf,state,nonce,lng,cntry,said`，注册**专属响应** DTO 字段是 `uuid,apRes,naRes`（没有 `utid`）。登录**公共响应**可包含 `basic`，但首次哪个 HTTP 响应真包含 `basic.utid` 仍需动态验证，不能直接认定来自注册专属响应。

# 3. 新增工具

- [只读 ARM64 Frida Agent](../../ci/home41_arm64_auth_timeline.js)：监听九个 ARM64 原生位置，记录相对时刻；仅在注册 DTO 打包写入后读取两个候选整数，从不主动发出帐号网络请求。
- [Python 本地运行器](../../ci/home41_arm64_auth_timeline.py)：验证原版 APK 哈希、设备原生 ARM64 ABI、设备安装 APK 哈希后 `spawn → attach → resume`；最多观察指定秒数，首次 `SetBasic` 命中就停止。Frida 会话断开时不清除 APP 数据或杀进程。
- [离线隐私/时序测试](../../ci/test_home41_arm64_auth_timeline.py)：模拟从序列化到回调/首次 Basic 的不同阶段，检验脱敏输出、默认不显示原 ID、预检失败拒绝执行。
- [CI](../../.github/workflows/home41-arm64-auth-timeline-tests.yml)：只验证源码和模拟 Frida 消息，不联网注册、不附加真实 ARM64 Android。

# 4. 在自己的 ARM64 Android 上操作

手机需原生 `arm64-v8a`、USB 调试、允许 Frida 附加原版 HOME 的环境（通常需要 root + 与主机 frida Python 对应的 Frida Server）。x86_64 AVD 不能拿来证明原生 Hook。

从仓库根目录的 Windows PowerShell：

```powershell
git pull origin master
adb devices
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.dalvik.vm.native.bridge

py -3 -m pip install frida
$apk = (Get-ChildItem 'ROMS/4.1.0/*.apk' | Select-Object -First 1).FullName

# 只记录事件名称、相对毫秒、候选是否等于目标、敏感数据全脱敏
py -3 ci/home41_arm64_auth_timeline.py `
    --apk "$apk" `
    --timeout 900 `
    --output "ci-results/home41_auth_timeline_safe.json"

# 如果希望本地直接查看 UTID / lng / cntry 的数字，必须显式选：
py -3 ci/home41_arm64_auth_timeline.py `
    --apk "$apk" `
    --timeout 900 `
    --show-local-values
```

`--show-local-values` 会在使用者**有交互终端的本地 PC**显示以下内容（均是示例，非线上真实账号）：

```text
[LOCAL ONLY] register request DTO lng integer: 8
[LOCAL ONLY] register request DTO cntry integer: 44
[UNVERIFIED] DTO enum numbers; HTTP transmission and country UI mapping not proven.
[LOCAL ONLY] server basic.utid: 4012345678
[LOCAL ONLY] derived six-digit candidate: 345678
[UNVERIFIED] Candidate TID7 is not proven equal to starter Pokémon OT.
```

其中 `lng=8, cntry=44` 只是**伪造的格式示例**，绝不能当成官方语言/国家枚举值。序列化事件刚进入时只能证明调用函数；`packed_write_seen` 触发后才能标记数值已被写入了请求 DTO。映射用户选择的简体中文/中国大陆，需要真实现场选择与该整数做可重复交叉验证。

`--output` 的安全 JSON 不含 raw UTID、登录 token、IP、Cookie、lang/country 原始数值或身份证明材料。原始数值只经由本人 Frida RPC 读取并显示到本地 TTY；GitHub Actions 环境下禁止显示。不要通过终端录屏、重定向或截图将这些私人值传到公开仓库。

# 5. 能确认什么、仍不能确认什么

**第一层：已静态验证**：注册请求 DTO 的结构和写入位置；公共响应接收和复制 UTID 的 AArch64 路径；登录/注册回调的原生函数地址。

**第二层：完成本次真实实机 Hook 后才能验证**：某次注册序列化调用发生的实际毫秒；对应的 DTO 两个数值可读；注册/Token/登录回调先后；真正从公共 Basic 消费点收到第一次 UTID。

**第三层：实机 Hook 本身仍不能单独证明**：HTTP 请求确实已发出并由服务器接受、`lng/cntry` 与 UI 枚举的对应、哪一个具体 HTTP endpoint 返回了 UTID、`utid % 1_000_000` 是否就是小火龙的 OT ID、断开 Hook 后冷启动是否持久化。如果这些问题要升格成事实，需分别观察请求发送证据、返回 DTO 的归属以及官方 UI/宝可梦个体 ID，最后再次冷启动确认。

不要使用相邻回调的时间差代替特定响应的身份归属；也不应用本工具重复发送注册/注销请求、批量换号或绕过服务端控制。

# 6. 最新离线结果

[Actions #42374973314](https://github.com/969981/Home_Android/actions/runs/42374973314)：**12/12 项离线测试通过**（含脱敏、负例、纯模拟 Frida lifecycle）。实际的 ARM64 账号回调、`lng/cntry` 数值和首个 `basic.utid` 均**未被真实抓取**，不能将该 CI success 写为在线 API 取数成功。


## 7. 补充：已把注册 DTO Formatter 和 Deserialize 真正加入监控

在原来仅监测 `ApiRequestAuthRegisterUser.SerializeRequestParameter` / `CallAfterResponse` 的基础上，新增独立 Frida 原生 Hook：

- `ApiAuthRegisterUserRequestParamFormatter.Serialize`，RVA `0x205AEF0`：`registration_request_formatter_entered`；
- `ApiAuthRegisterUserResponseParamFormatter.Deserialize`，RVA `0x205DA3C`：`registration_response_formatter_entered`。

其意义是**将业务 DTO 的构造、格式化，以及专属响应的反序列化三件事区分开**。不获取原始 JSON / token，不把 `Deserialize` 当作“服务器发给了 utid”，因为该专属响应类型只包含 `uuid,apRes,naRes`。

这两个 Hook 的 RVA 属于静态研究索引，需要实机确认函数确实命中且不会干扰官方 APP。调用 `Deserialize` 并不能单独证明请求发出、HTTP 200 或响应来自何 endpoint。真正 `utid` 首次出现仍以 `SetBasic` 的公共响应调用源、实机动态值与官方 UI 三重证据为准。
