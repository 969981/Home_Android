---
title: "HOME 4.1.0 — GitHub Actions Android 模拟器原生 ARM64 IL2CPP Frida Hook 实测"
aliases: [HOME41 Android NativeBridge Frida ARM64 实测]
tags: [pokemon-home, android, frida, arm64, emulated-realm, il2cpp, github-actions, obsidian]
updated: "2026-11-07"
status: "ARM64 Emulated Realm / libil2cpp Hook 安装已真机式模拟器实测通过；注册 / UTID 未触发"
---

# 重要结论（真实运行，不是 mock）

已在 GitHub Actions 上使用真实的 **Android 15 x86_64 模拟器 + Google APIs + NativeBridge** 启动原版 Pokémon HOME Android 4.1.0。使用 **Frida 17.26.1 的 emulated realm** 进入被翻译执行的 ARM64 `libil2cpp.so`，成功安装原生时间线 Hook。至此，之前“x86_64 模拟器只能观察 x64 libc、无法动态 Hook ARM64 IL2CPP”的限制，已经在此模拟器配置和 Frida 版本上解除。

## 1. 可重现实测证据

- **实测工作流**：[Actions #42378951870](https://github.com/969981/Home_Android/actions/runs/42378951870)
- **实际脱敏工件**：`home41-arm64-emulated-realm-proof`，Artifact ID **13577116263**，到期 **2026-11-10 13:56:29 UTC**。包含 `home41_emulator_report.json` 和原版 HOME 从语言选择、亚太地区到确认中国大陆后的实际截图。
- 原版 APK SHA-256：`8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1`
- `libil2cpp.so` SHA-256（静态已归档）：`80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe`
- 真实 Action 作业结果：`success`，而且最后独立的成功门槛必须同时确认 APK 进程仍在、`realm="emulated"` 成功、`native_arm64=true`、`native_module_ready=true`、`hooks_ready=true`。因此这里不是利用 `continue-on-error` 制造的绿色成功。

实际 `home41_emulator_report.json` 的 ARM64 摘要（仅白名单字段）：

```json
{
  "arm64_emulated_realm": {
    "status": "emulated_realm_attached",
    "error_type": null,
    "agent_script_error": false,
    "events": [
      {
        "event": "arm64_auth_observer_ready",
        "elapsed_ms": 1419,
        "hook_failures": 0,
        "actual_http_request_send_verified": false
      }
    ],
    "snapshot": {
      "status": "snapshot_received",
      "native_arm64": true,
      "native_module_ready": true,
      "hooks_ready": true,
      "first_basic_seen": false,
      "serialized_lng_cntry_seen": false,
      "registered_account": false,
      "counts": {
        "registration_request_serializer_entered": 0,
        "registration_lng_cntry_packed_write_seen": 0,
        "registration_request_formatter_entered": 0,
        "registration_response_formatter_entered": 0,
        "registration_response_handler_entered": 0,
        "token_request_serializer_entered": 0,
        "token_response_handler_entered": 0,
        "login_request_serializer_entered": 0,
        "login_response_handler_entered": 0,
        "common_response_handler_entered": 0,
        "first_basic_utid_observed": 0
      }
    }
  }
}
```

页面实际推进：简体中文 → 亚太地区 → 中国大陆 → **出生日期选择页**。该次 Actions 未填写生日、未点击协议、未创建账号、未登录；因此 `registration`、`token`、`login`、`SetBasic` 的调用次数全部为 0，恰恰符合用户界面的流程阶段。**这次只证明 Hook 正确安装，不证明已动态命中这些方法的 onEnter。**

## 2. 成功的技术原因

Frida 在 Android NativeBridge 有两个独立 Realm：

```text
Android 15 AVD: x86_64
    │
    ├─ Frida native realm → Process.arch = x64
    │        └─ 可监听 libc；ARM64 原生代码并不在 x64 realm
    │
    └─ Frida emulated realm → Process.arch = arm64
             └─ 能观察 ARM64 libil2cpp.so / 安装原生 Hook
```

本轮采用的是官方 Frida Python API：

```python
session = device.attach(home_pid, realm="emulated")
script = session.create_script(arm64_il2cpp_js)
script.load()
```

重要条件：
1. 原版 HOME 已**先启动并且 ARM64 NativeBridge 加载完成**，再 Attach 到现有进程；直接 Spawn 后马上进入 emulated realm 可能过早。
2. 使用匹配的 `frida==17.26.1` + `frida-server-17.26.1-android-x86_64`。
3. Frida x64 Realm 和 Emulated ARM64 Realm 同时存在；ARM64 静态 RVA **绝不**交给 x64 Interceptor.attach。
4. 原版 Unity IL2CPP 的实际 `libil2cpp.so` 需要正确发现，并验证每个已识别 RVA 在模块范围内。

## 3. 本地模拟器复现

使用来自同一原版 APK 的已知校验哈希，模拟器须有 ARM NativeBridge、root/Frida 授权，且 HOME 已经启动、停在尚未执行注册的正常 UI 页面。与前面的 `ci/home41_arm64_auth_timeline.js` 搭配，使用增强后的 Python 运行器：

```powershell
git pull origin master
py -3 -m pip install 'frida==17.26.1'

# 在你自己本机启动并保持 HOME 正常运行。
adb devices
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.dalvik.vm.native.bridge

# 安装并启动与 x86_64 客体同架构的官方 frida-server（需提前下载并解压）
adb root
adb push .\frida-server-17.26.1-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 700 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server -l 127.0.0.1:27042 >/dev/null 2>&1 </dev/null &"
adb forward tcp:27042 tcp:27042

# 本机原版 APK 路径
$apk = (Get-ChildItem 'ROMS/4.1.0/*.apk' | Select-Object -First 1).FullName

# 模拟器使用 realm=emulated + 已运行的 HOME PID，不重建或重签 APK
py -3 ci/home41_arm64_auth_timeline.py `
    --apk "$apk" `
    --realm emulated `
    --remote-frida `
    --timeout 900 `
    --output 'ci-results/home41_arm64_timeline_safe.json'

# 只在本人交互终端显示真实 lng/cntry/utid，绝不上传 GitHub
# 需要 HOME 正在运行且随后正常执行相关的官方认证/注册 UI
py -3 ci/home41_arm64_auth_timeline.py `
    --apk "$apk" `
    --realm emulated `
    --remote-frida `
    --timeout 900 `
    --show-local-values
```

Python 运行器现在对 `--realm emulated` 进行特别预检：原始本地 APK、模拟器 x86 ABI + NativeBridge、实际安装 HOME versionCode 81 以及设备内 `base.apk` 的 SHA-256 均须相符，否则拒绝附加；运行期间还要由真正的 ARM64 Agent 自证 `hooks_ready`。`--remote-frida` 只连接本机 ADB 转发 `127.0.0.1:27042`，不能指向公开 Frida 服务。

## 4. 下一项仍未完成的事实

已证明 **ARM64 动态代码地址可挂 Hook**，尚未证明：
- 实际注册时 `lng`、`cntry` 被写入请求 DTO 的运行时取值；
- 对应 API 的实际发送时间和响应内容；
- 哪个 HTTP 回包先携带 `ResponseParamCommon.basic.utid`；
- 首次六位候选值是否等于 APP 显示的训练家 ID、小火龙宝可梦原始训练家 ID；
- Hook 脱离、冷启动后账户与身份持久化。

需要在一个本人授权、正常操作的 HOME 客户端会话中进一步执行注册及后续页面，再读取已解析业务 DTO。此次测试并无账号，因此不能将 `first_basic_utid_observed=0` 当作失败或服务端未发号。

**证据核对**：本轮最值得注意的是 `hooks_ready=true` 与 `first_basic_utid_observed=0` 同时出现，两者完全兼容——代表 Frida 成功准备好，但没有发生应该触发该业务调用的会话动作。禁止将“Hook 安装成功”写成“捕获 ID 成功”。

## 5. 相关代码与回归

- [真实模拟器工作流](../../.github/workflows/home41-emulator-arm64-realm.yml)
- [ARM64 Emulated Realm 一体化实验运行器](../../ci/home41_emulator_arm64_realm.py)
- [Frida ARM64 IL2CPP Agent](../../ci/home41_arm64_auth_timeline.js)
- [原生/Emulated 双环境 Python 时序运行器](../../ci/home41_arm64_auth_timeline.py)
- [脱敏与防误报测试](../../ci/test_home41_emulator_arm64_realm.py)
- [ARM64 请求/回调时间线测试](../../ci/test_home41_arm64_auth_timeline.py)


## 6. 1999-04-05 年份滚轮问题：独立真实运行与字节级审计

目标测试生日固定 **1999-04-05**；已在 `PokeHome_Resources` 私有分支的真实模拟器图像 [#42368887392](https://github.com/969981/PokeHome_Resources/actions/runs/42368887392) 验证本地表单 **月=4、日=5，年份为空，未提交**。统一实验继续保留不绑定 Nintendo Account、头像首个有效选项、小火龙 #0004；不自动提交生日、同意服务协议、创建/删除账号。

### 无副作用输入方式的实际反例

| 真实运行 | 结果 |
|---|---|
| [#42360115832](https://github.com/969981/PokeHome_Resources/actions/runs/42360115832) | 文字区域 ADB swipe 意外选中 `2019` 并关闭弹窗，没有滚动 |
| [#42366372912](https://github.com/969981/PokeHome_Resources/actions/runs/42366372912) | 选择 `2018` 后重开仍从 `2026..2018` 开始，不会锚点分页 |
| [#42360703091](https://github.com/969981/PokeHome_Resources/actions/runs/42360703091) | Android mouse ACTION_SCROLL 返回成功，实际年份文字无像素变化 |
| [#42362631400](https://github.com/969981/PokeHome_Resources/actions/runs/42362631400) | KEYCODE_PAGE_DOWN 无视觉移动，UIAutomator 无年份 Text 节点 |
| [#42383783516](https://github.com/969981/Home_Android/actions/runs/42383783516) | ARM64 Frida 就绪状态下，在年份菜单按一次 `KEYCODE_DPAD_DOWN`，菜单仍打开；真实字体像素掩码前后 9348/9348，异或零、交并比 1.0，说明没有移动。源码的 `year_keyboard_image_changed` 只报告整图部分像素变化，**不得**充作年份移动的证据 |

为定位真实滚动与选项数据，新的只读代码通过 `FirstBootViewInputBirthData` 实例捕获 `yearOptionDataList`，按实际 64-bit IL2CPP 的 `List<T>._items` 与 `OptionData.m_Text` 解析年份字符串，公开日志只保留 `year_option_count`、`year_1999_index`（如果找到）与 `first_option_is_2026`，不导出年份列表、DOB、指针或登录会话。

### 方法原理的真实静态证据

私有 [180628 方法索引 #42383949461](https://github.com/969981/PokeHome_Resources/actions/runs/42383949461) 找到 `FirstBootViewInputBirthData`、`CustomTMPDropdown`、`CustomTMPDropdownScrollList` 等候选。随后 [私有 dump.cs 类布局 #42384315106](https://github.com/969981/PokeHome_Resources/actions/runs/42384315106) 闭合字段：

- `FirstBootViewInputBirthData.yearDropdown +0x28`、`yearOptionDataList +0x40`，`inputedYear +0x58`，`inputedMonth +0x5C`，`inputedDay +0x60`，`START_YEAR = 1900`。
- `CustomTMPDropdown.m_Value +0x138`、`m_Options +0x140`；`CustomTMPDropdown.OptionData.m_Text +0x10`（托管字符串）。
- `FirstBootViewInputBirthData.SetData = 0x1C80964`，`OnYearChageValue = 0x1C80EF8`；`CustomTMPDropdown.set_value = 0x1F14014`、内部 `SetValue = 0x1F1401C`。

**原版 ARM64 ELF 真正反汇编**：[Actions #42384802086](https://github.com/969981/Home_Android/actions/runs/42384802086)，SHA 同版本双重校验，通过原生字节核验后导出 `birthdata_setdata.asm`、`birthdata_onyear.asm`、`custom_dropdown_setvalue.asm`、`custom_dropdown_onselect.asm`、`custom_scroll_open.asm`：

```asm
; CustomTMPDropdown.set_value(int)
0x1F14014 MOV W2,#1           ; sendCallback=true
0x1F14018 B 0x1F1401C         ; delegated SetValue
; CustomTMPDropdown.SetValue
0x1F140E0 STR W8,[X19,#312]  ; m_Value (+0x138)
0x1F140E4 BL  0x1F13D14       ; RefreshShownValue

; FirstBootViewInputBirthData.OnYearChageValue(int index)
0x1C80FD4 LDR X0,[X19,#64]   ; yearOptionDataList (+0x40)
0x1C80FE4 B.LE ...            ; range-check index
0x1C81008 BL 0x3782360       ; parse OptionData.m_Text numeric
0x1C81018 STR W0,[X19,#88]   ; inputedYear (+0x58)
```

因此，**静态上**已闭合“下拉选中某个整数 index → 列表解析年份文字 → 写入客户端本地 inputedYear”的路径。但是 Frida 的 `OnYearChageValue` 并未实测命中；只有在真实运行中读取到 `1999` 的正确选项索引、方法实际被调用且本地 UI 显示 `1999` 后，才可以声称选中了 1999。更不能用调用客户端 setter 推断生日已提交服务器。

当前公开 ARM64 agent 在 `ci/home41_arm64_auth_timeline.js` 增加只读 `SetData/OnYearChageValue/OnMonthChangeValue/OnDayChangeValue` 观察和 `yearOptionDataList` 查找。Action 以 `ci/home41_emulator_arm64_realm.py` 严格脱敏输出，只在模拟器中安装 Hook、不发出修改应用内存的指令。


## 2026-11-08：年份内部字段与界面显示不一致，追加月份/日期原生选项审计

真实 [Actions #42385406639](https://github.com/969981/Home_Android/actions/runs/42385406639) 先已验证：
- `Frida emulated realm` 与原版 `libil2cpp.so` 均可运行，所有 Hook 安装成功；
- `yearOptionDataList._size=127`，首项 `2026`，`1999` 位于索引 `27`；
- 用户显式测试模式仅调用一次原版 `CustomTMPDropdown.set_value(27)`，并由本地 `inputedYear==1999` 读回验收；
- 但人工查看真实截图 `10_year1999_form_after_back.png`，**年份框显示的仍是“年”，不是“1999”**。因此本地字段的正确性**不能替代界面显示已选择**，也不能提交生日。
- `inputedMonth`、`inputedDay` 均未设定；注册、Token、登录和 `SetBasic` 事件为零，未拿到 UTID。

本阶段从私有原版 `dump.cs` 的 **真实类型布局**（[审计 Actions #42384315106](https://github.com/969981/PokeHome_Resources/actions/runs/42384315106)，`birthdate_class_layouts.json`）补齐：
- `FirstBootViewInputBirthData.monthDropdown +0x30`，`dayDropdown +0x38`；
- `monthOptionDataList +0x48`，`dayOptionDataList +0x50`；
- 原版月/日变更回调 RVA：`OnMonthChangeValue 0x1C814C0`、`OnDayChangeValue 0x1C8181C`；
- `CustomTMPDropdown.m_Value +0x138` 是独立于控制器 `inputedYear +0x58` 的组件当前索引。

新增只读 Agent 辅助方法 `describeSmallDropdown`，只读取 4 月、5 日目标选项的**唯一索引、列表长度、组件当前索引是否匹配**。限制：只有可信的短数字标签（例如 `4`、`04`、`4月`）和 `12/31` 个预期选项才认定目标位置；不上传任何完整列表、出生日期、账号信息或原始指针。若文字含本地化附加符号或列表排序不同，安全输出 `target_found_uniquely=false`，不会猜索引。

下一步应对 **`inputedYear==1999` 与年份框依然显示“年”**的现象做 A/B 测试：先检查 `yearDropdown.m_Value` 是否等于 27，再观察弹窗关闭后 `RefreshShownValue` 是否让显示文字回到占位符。只有内存状态、组件索引和真实界面同时通过才执行下一步的 4 月/5 日选择。当前代码不自动提交日期或接受服务条款，不批量创建账号。

