---
title: "HOME 4.1.0：AtuhRegisterUser 尾调用、CreateToken 构造函数与同一请求对象实测"
date: 2026-11-09
status: "原版机器码与 IL2CPP 方法索引静态核对；请求对象匹配 Hook 已实现但未实机验收"
tags: [HOME, Android, ARM64, IL2CPP, Frida, CreateToken, guest, registration, Obsidian]
---

# 研究目的与结论

研究范围是原版 Pokémon HOME Android 4.1.0，原始 APK SHA-256：
`8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1`；
原版 ARM64 `libil2cpp.so` SHA-256：
`80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe`。

原版机器码已证实：
`AtuhRegisterUser @ 0x1D2F8DC` 的尾段通过 `B` 到达 `0x1D2F1F8`，
后者在 `0x1D2F324` 直接 `BL 0x1D35CC8`。
原始方法索引进一步给出 `0x1D35CC8` 的身份为
**ApiRequestCreateToken 类的 .ctor 构造函数**，不是 AuthRegisterUser 的序列化器。

`0x1D2F2F4` 的直接调用目标 `0x1F27198` 对应
**ILib.Unity.Net.ApiRequestBase.get_IsTokenExpire**。
因此这段尾调用代码至少涉及 Token 过期状态查询及 CreateToken 请求对象构造，
但两条 `BL` 中间的条件/分支仍需以同一真实执行实例确证。

**静态方法身份已闭合；同一游客事务及真实服务器注册结果尚未闭合。**

# 1. 机器码逐行研究

以下是此前经过原版 ELF 字节校验的重要 RVA；均为模块相对虚拟地址，
不是 ASLR 后的绝对地址：

```asm
0x1D2F9C8   BL   0x1D2F584       ; 注册管理器内部直接调用，方法身份单独判断
0x1D2F9E4   LDP  X30,X27,[SP],#0x50
0x1D2F9E8   B    0x1D2F1F8       ; 尾调用：不是 BL、不会新增普通返回地址

0x1D2F1F8   STR  X30,[SP,#-0x40]! ; 新函数窗口/栈帧
0x1D2F214   LDRB W8,[X19,#0x119] ; 静态初始化状态字节
0x1D2F220   TBNZ W8,#0,0x1D2F2A4
0x1D2F2F4   BL   0x1F27198       ; ApiRequestBase.get_IsTokenExpire
0x1D2F324   BL   0x1D35CC8      ; ApiRequestCreateToken..ctor
0x1D2F384   BL   0x1D4BF14       ; 需单独解析方法身份
0x1D2F38C   BL   0x1D656BC       ; 需单独解析方法身份
0x1D2F3A4   BL   0x1D8AA54       ; 需单独解析方法身份
0x1D2F418   B    0x1F27404      ; 条件路径上的另一尾调用
0x1D2F460   B    0x1D2EFEC      ; 条件路径上的另一尾调用
```

注意：上述是有限窗口中选出的**准确指令位置**，不是声称每条都
在同一次初始化中按照文本先后必然执行。尤其不能把 `BL` 视为
“服务端 HTTP 请求已经发送”。

`0x1D2F9F8` 存在另一个独立函数的序言。其内部 `0x1D2FA20 BLR X8`
与以上注册管理器尾调用不属于已验证的相同函数体，**不要并入必经链**。

# 2. 原版方法索引对照

| RVA | 原版类 / 方法身份 | 角色 | 动态证据 |
| --- | --- | --- | --- |
| `0x1D2F8DC` | `ApiManagerLogin.AtuhRegisterUser` | 注册管理器入口 | 待本次单次实测 |
| `0x1D2F1F8` | 尾调用目标：入口归属仍待完整索引确认 | 进入 Token 相关逻辑的函数窗口 | 待实测 |
| `0x1F27198` | `ILib.Unity.Net.ApiRequestBase.get_IsTokenExpire` | Token 过期状态 getter | 待实测 |
| `0x1D35CC8` | `ApiRequestCreateToken` 的 `.ctor` | 创建 Token 请求对象 | 待实测 |
| `0x1D35888` | `ApiRequestCreateToken.SerializeRequestParameter` | Token 请求序列化 | 待实测 |
| `0x1D35AD0` | `ApiRequestCreateToken.CallAfterResponse` | Token 响应回调入口 | 待实测 |
| `0x1D334A4` | `ApiRequestAuthRegisterUser.SerializeRequestParameter` | 注册请求序列化 | 待实测 |
| `0x1D33294` | `ApiRequestAuthRegisterUser.CallAfterResponse` | 注册响应回调入口 | 待实测 |
| `0x1D763D0` | `UDManager.SetBasic` | 公共用户资料写入 | 待实测 |

索引交叉引用：
`PokeHome_Resources@4.1.0/Unpack/Android/4.1.0/_meta/auth_method_candidates.csv`。
原始 ScriptMethod 表为
`PokeHome_Resources@4.1.0/Unpack/Android/4.1.0/il2cpp/script.json`，
其版本锁定 Git blob SHA-1：
`895419550af1e00a2482f01fcc6d1c07592a5995`。

原版 ELF 的分支地址验证与方法索引名字核对是**两种不同证据**。
尚未看到原版脚本的完整精确索引报告成功发布时，
不能把它说成已完成新的 Actions 运行时验收。

# 3. 应当分成两个流程观察

```text
官方游客确认（实际调用的正向委托需验证）
  └─ DecisionGestAccount
       └─ AtuhRegisterUser @ 0x1D2F8DC
            └─ B -> 0x1D2F1F8
                 ├─ 可能调用 get_IsTokenExpire
                 ├─ 可能构造 ApiRequestCreateToken
                 └─ 其他分支与调用尚待还原

独立记录（不能强制拼成同一 C# 调用栈）：
  A. AuthRegisterUser.SerializeRequestParameter
     AuthRegisterUser.CallAfterResponse
  B. CreateToken..ctor
     CreateToken.SerializeRequestParameter
     CreateToken.CallAfterResponse
  C. Login / common response / UDManager.SetBasic
```

以伪代码表述已观察到的事实、但不强加未知的分支条件：

```c
void AtuhRegisterUser(/* 原始参数身份待确认 */) {
    // 部分真实初始化/内部准备逻辑
    goto tail_target_1D2F1F8; // 原版 B 尾跳转
}

void tail_target_1D2F1F8(/* 未命名的原版函数 */) {
    // 初始化状态判断与条件跳转
    bool tokenExpiredCandidate = ApiRequestBase_get_IsTokenExpire(/*...*/);
    // 上句仅表示静态调用目标和候选返回类型，非已观察实际结果
    // ...
    ApiRequestCreateToken_ctor(/* request instance */);
    // ...
    // 该路径是否执行注册序列化、网络发送、响应回调仍需继续追踪
}
```

# 4. 新增只读对象身份对照

`Home_Android/ci/home41_arm64_auth_timeline.js` 的观察器：

1. 在 `0x1D35CC8` 构造函数入口**仅在 Frida 进程内**记录 `args[0]` 对象地址，最多 64 个候选。
2. 在 `0x1D35888`、`0x1D35AD0` 的方法入口比较各自 `args[0]` 是否与已见构造对象相等。
3. 仅在实际匹配时输出固定布尔位 `same_token_ctor_instance_observed: true`；没有匹配不输出该字段，绝不把未知变成 false。
4. 脱敏 Python 报告单独输出 `token_request_hook_coverage` 的布尔安装状态，以及 `guest_register_entry_order.same_create_token_request_instance_observed`。
5. 保留旧事件名 `auth_manager_tail_callee_35cc8_entered` 以兼容历史 JSON，新的方法身份在报告字段 `original_method_identity` 中表示。
6. 不读取或报告 Token、Cookie、UUID、UTID、请求正文、原始对象指针，也不会触发注册函数或修改游戏状态。

**证据上限：** 如果同一次观察中看到了匹配的入口对象，
只能证明这些 IL2CPP 方法进入时使用了同一原生对象地址。
不能证明 HTTP 发出、Token 有效、同一次服务端事务或云端账号建立。
如果对象已销毁且内存地址被复用，还需要对象生命周期或调用栈进一步核对。

# 5. 一次官方游客初始化的验收

在**个人控制且可持久保存 HOME 应用数据**的 Android ARM64 设备上，
于最终第二次游客确认之前开启观察器。必须使用版本锁定的原版 APK。
不重复创建或删除账号，不关联 Nintendo Account。

```powershell
git pull origin master
$apk = (Get-ChildItem '.\ROMS\4.1.0\*.apk' | Select-Object -First 1).FullName
py -3 ci/home41_arm64_readonly_runner.py preflight --apk "$apk"
py -3 ci/home41_arm64_auth_timeline.py `
  --apk "$apk" `
  --realm native `
  --attach-running `
  --timeout 1800 `
  --output ".\local-home41-guest-chain.json"
```

已定本次原版 UI 条件：生日 1999/04/05、不关联 Nintendo Account、
仅一次游客注册，后续以原版有效头像和小火龙作为选择。

读取本地脱敏 JSON 时：

| 字段 | 满足时的意义 | 不代表什么 |
| --- | --- | --- |
| `guest_register_entry_order.all_seven_stages_observed_in_order` | 七个监听入口按收到的消息顺序出现 | 不是同一调用栈/请求 |
| `registration_tail_observer_hook_coverage` | 两个尾调用监听点成功安装 | 不是执行次数 |
| `token_request_hook_coverage` | Token 序列化与回调 Hook 成功安装 | 不是发送或成功 |
| `same_create_token_request_instance_observed` | 已见同一 Token 请求对象入口匹配 | 不是服务器发 Token |
| `registration_tail_same_transaction_verified` | 当前始终为 false | 不得伪造 true |
| `first_basic_utid_observed` | 原版公共 Basic 消费点发现可用资料 | 不是 UI 六位 ID 等价证明 |

**旧运行记录**：`Home_Android` Actions #42551816996
有一次 `ConfirmGestAccountSecond` 入口命中，
但注册序列化、注册回调、Token 回调及首次 Basic 均为 0，
故不能声称那次已经完成建号或 Token/注册调用链。

# 6. 下一阶段需要的证据

目前没有本次新增只读对象匹配的真实 Frida 运行输出。
真正需要补上的不是再列候选 RVA，而是：

- 在原版持久 Android 中取得正向委托、管理器、尾调用、Token 构造、
  Token 序列化和注册序列化的**一次连续实际事件记录**；
- 当匹配同一 Token 对象时，进一步用调用栈/线程与对象生命周期
  区分异步事件及潜在地址复用；
- 仅在实际服务器成功响应后，观察 Token/Login 与公共 Basic；
- 最后才对照 UI 六位 ID、头像、小火龙与冷启动同号恢复。

文档状态：**STATIC_INDEX_MATCH + READ_ONLY_OBSERVER_PREPARED；
RUNTIME_SAME_REQUEST_NOT_OBSERVED；SERVER_ACCOUNT_NOT_VERIFIED。**


# 7. 2026-11-09：AuthRegisterUser 与 CreateToken 双请求分离、原版直接调用点证明

本轮继续将注册请求构造函数加入观察，避免把 `0x1D35CC8` 的 Token 对象误当作注册 DTO：

| 观察点 | 原版入口 RVA | 作用 | 输出 |
| --- | --- | --- | --- |
| AuthRegisterUser 构造函数 | `0x1D336C8` | 观察注册请求实例地址 | `registration_request_constructor_entered` |
| AuthRegisterUser 序列化 | `0x1D334A4` | 对照注册实例地址 | 仅匹配时 `same_register_ctor_instance_observed: true` |
| AuthRegisterUser 响应回调 | `0x1D33294` | 对照注册实例地址 | 仅匹配时 `same_register_ctor_instance_observed: true` |
| CreateToken 构造函数 | `0x1D35CC8` | 观察 Token 请求实例、验证调用点 | 仅匹配时 `create_token_ctor_from_tail_callsite_observed: true` |
| CreateToken 序列化 | `0x1D35888` | 对照 Token 实例地址 | `same_token_ctor_instance_observed`；仅尾调用对象匹配时 `same_token_ctor_from_tail_instance_observed` |
| CreateToken 响应回调 | `0x1D35AD0` | 对照 Token 实例地址 | 同上 |

**新增 AArch64 调用点确认：**

```asm
0x1D2F324  BL 0x1D35CC8   ; 已静态验证的调用指令
0x1D2F328  ...              ; BL 的架构返回位置（callsite+4）
```

此时在 `ApiRequestCreateToken..ctor` 函数入口，Frida 的 `this.returnAddress`
正常应指向 `libil2cpp.so + 0x1D2F328`。
观察器只在 Frida 内部与这个模块基址加 RVA 比较，不输出绝对返回地址或指针。
未观察到这个返回地址时不标记匹配，不能据此断言代码路径未运行。

**新的脱敏报告证据字段（均非服务端证明）：**

- `guest_register_entry_order.same_auth_register_request_instance_observed`：
  同一次 Second 确认之后，注册请求序列化或回调曾与本窗口内的注册构造函数出现地址相等；
- `guest_register_entry_order.create_token_ctor_direct_register_tail_caller_observed`：
  Token 构造函数实际观察到来自静态验证的 `0x1D2F324 BL` 调用点；
- `guest_register_entry_order.same_token_request_from_register_tail_callsite_observed`：
  后续 Token 序列化/响应的对象地址与这个调用点产生的构造对象匹配；
- `register_request_ctor_hook_attached`：注册构造入口的实际 Hook 安装布尔状态；
- `token_request_hook_coverage`：Token 序列化/响应 Hook 的真实安装布尔值。

Second 确认时只清除 Frida 私有的缓存集合，不修改 HOME 内存状态；
AuthRegisterUser、CreateToken 使用两个独立集合，各最多存储 64 个候选对象地址。
未匹配的输出只代表**没有取得匹配证据**，不是明确对象不一致；
地址复用和线程交错仍需由调用栈、对象生命周期及服务器响应进一步排除。

回归用例位于 `ci/test_home41_guest_persistent_chain.py`。
本轮仅提交了脚本、测试与静态研究文档，尚未取得新的 Android 会话；
**不能写为某次真实游客建号或首次 basic.utid 已成功。**


# 8. 构造函数返回、地址复用与重复 Second 窗口防误判（2026-11-09 晚）

对第 4、7 节的**实现语义作进一步收紧**：早期“构造函数一进入即缓存地址”的
方案会在构造函数尚未结束时允许匹配，也无法有效区分同一进程中不同游客确认。
现版以 `onLeave` 完成证据为门禁，入口仅记录只读元数据。

```text
第一次 ConfirmGestAccountSecond
    ├─ guestObservationEpoch += 1，清空三个私有对象缓存
    ├─ AuthRegisterUser..ctor onEnter
    │    └─ 暂存私有地址和 epoch，不允许后续直接匹配
    ├─ AuthRegisterUser..ctor onLeave
    │    └─ epoch 未改变 → 记录完成地址和时间
    ├─ AuthRegisterUser.SerializeRequestParameter
    │    └─ 完成地址一致且不超过 120 秒 → 布尔候选证据
    │
    ├─ CreateToken..ctor onEnter
    │    └─ 检查返回 RVA 是否为 0x1D2F328，暂存私有信息
    ├─ CreateToken..ctor onLeave
    │    └─ epoch 未改变 → 记录完成地址和时间
    └─ CreateToken.SerializeRequestParameter / CallAfterResponse
         └─ 完成地址一致且不超过 120 秒 → 布尔候选证据

第二次 ConfirmGestAccountSecond（如意外重入）
    └─ 新 epoch，清空上一轮缓存；Python 只统计第一次确认到此处的窗口
```

两个新增的原生只读事件为：

- `registration_request_constructor_returned`：注册请求构造函数已返回；
- `auth_manager_tail_callee_35cc8_returned`：Token 构造函数已返回，
  如实际原版返回地址匹配则另有 `create_token_ctor_from_tail_callsite_observed:true`。

Python `observe_guest_register_order` 对证据增加了保守判定：对应构造函数
`returned` 事件必须在匹配的序列化或回调之前出现；只见入口而未见返回，
即使测试数据中出现匹配布尔值也**不能**宣称对象已完成构造。
已增加早到序列化、缺失 onLeave、第二次确认跨窗口污染和脱敏反例。

新的 120 秒是证据保鲜上限，**不是原版协议超时时间**。
对象地址复用仍可发生于 120 秒内，因此这类证据只能叫
“同一观察窗口中的已完成构造地址匹配”，
不能把它升级为持久托管对象身份、相同服务器事务或成功建号。
Hook 安装失败、超过 64 个对象或超过 120 秒造成的缺失应标为
`NOT_OBSERVED/UNKNOWN`，而不是相反的业务结论。

与之前一样，本节新增结果是代码和离线测试条件，
目前**没有新的实机 Frida 事件、真实六位 ID 或服务端注册回执**。
