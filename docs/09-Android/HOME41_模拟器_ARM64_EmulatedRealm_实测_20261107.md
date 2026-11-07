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



## 2026-11-08：月日 OptionData 实机闭合和单次本地选择实验

**真实运行**：[Actions #42389541537](https://github.com/969981/Home_Android/actions/runs/42389541537)，已完成且通过（不是模拟消息）。

- 原始月列表 `monthOptionDataList +0x48` 有 **12** 个条目，`4` 的唯一索引为 **3**，组件尚未选择该索引。
- 原始日列表 `dayOptionDataList +0x50` 初始有 **31** 个条目，`5` 的唯一索引为 **4**，组件尚未选择该索引。
- `yearOptionDataList +0x40` 有 **127** 个条目，`1999` 索引 **27**，本次 `inputedYear==1999` 且 `yearDropdown.m_Value==27` 已通过。
- **重要视觉差异未消除**：上一次真实截图 `10_year1999_form_after_back.png` 的年份框仍显示占位符“年”；组件内存值正确不等于证明 Unity 文本显示正确。

本阶段另外新增一个 **显式单次测试标志** `--select-local-month-day`，调用原版 `CustomTMPDropdown.set_value`，但只允许在 HOME 自有 `Show()` 主线程回调中处理，保证索引由原版 OptionData 文本验证；没有直接改动 IL2CPP 对象内存。严格要求先验证 1999 年，才能选择 4 月，再验证 4 月，才能选择 5 日。按钮【下一步】及任何服务条款/注册操作均不触发。

**动态日历注意点**：初始月份未确定时日列表可有 31 项；选择 4 月后，如果游戏根据 `GetDaysOfMonth(1999,4)` 重建日期选项，应当是 **30 项**，不能拿先前的 31 项作为后续索引校验依据。因此日列表检查已改为基于已选择的 4 月动态期待 30 项，并保留 5 日索引必须唯一且为 4。

模拟器新工作流将采集两次原生 Setter 后的截图、组件 `m_Value` 与 `inputedMonth/inputedDay`，公开 Artifact 仅含布尔状态和固定菜单索引。**即使三个内部日期字段都成立，也不表示 DOB 已提交服务器**；直到实际 UI 显示及单账号官方流程验收之前，不得称已成功注册或获取 UTID。


## 2026-11-08：实测原版内部完整生日 1999-04-05，但界面仍显示占位符

**真实 Actions [#42390521446](https://github.com/969981/Home_Android/actions/runs/42390521446)**（Artifact `home41-arm64-emulated-realm-proof`，ID **13581097873**）完成了严格只读监控及一次性原版 Unity 下拉框 Setter 实验：

| 原生证据 | 实测 |
|---|---|
| ARM64 Emulated Realm / `libil2cpp.so` | 附加成功，全部 Hook 安装 |
| `inputedYear == 1999`，`yearDropdown.m_Value==27` | true |
| `inputedMonth == 4`，`monthDropdown.m_Value==3` | true |
| `inputedDay == 5`，`dayDropdown.m_Value==4` | true |
| 年列表 / 月列表 / 日期列表 | 127 / 12 / **30**（4 月已更新） |
| `exact_birthdate_selected` | true，**只代表 HOME 内存控制器的当前字段** |
| 原版年月日 Setter `attempted/returned` | 全部 true，且 failure 全部 false |
| `birthday_submitted` / `registration_status` | false / not_attempted |
| `first_basic_utid_observed` | false |

真实阶段截图 `16_full_date_form_after_back.png` 人工检查：**仍显示“年 / 月 / 日”三个占位符！** 因此不可认定 GUI 层已正确选择出生日期，更不可立即点击【下一步】。关键问题可能在 `CustomTMPDropdown.RefreshShownValue`、`OnSelectItem`、`OnValueChanged` 及关闭弹窗后的显示文字更新，需要与真正的 UI 选项点击做 A/B。

本次 Actions 在最后检查阶段失败，直接原因是旧的**只验证年份**门槛仍要求 `exact_birthdate_selected=false`；而这轮完整内部生日变为 true。真实数据和原版回调 **已经成功**，失败不是 Frida/Unity 失败。已将旧门槛改为只接受完整日期模式，并在新代码中加入 **重新打开年份菜单（内部 `m_Value=27`）的真实截图实验**：如果菜单能滚到 1999，可进一步使用原生 UI 选择来修复三个下拉框的可见占位符。这一后续实验结果未出之前，不宣称可视 UI 成功。

全程：未提交生日、未同意条款、未执行账户创建/删除、未绑定 Nintendo Account、未读取或保存服务器原始 UTID、未取得六位训练家 ID。


## 2026-11-08：占位符问题根因候选——Setter 与 OnSelectItem 并非同一路径

上一轮实测 [#42391228890](https://github.com/969981/Home_Android/actions/runs/42391228890)：通过原版 HOME 的下拉组件 setter 得到 `inputedYear=1999, inputedMonth=4, inputedDay=5`，组件索引分别为 `27/3/4`，然而 `16_full_date_form_after_back.png` 及 **重新打开年份列表** `17_year_reopened_index27.png` 的界面仍呈现【年／月／日】占位符，重新打开年份列表依旧从 2026 显示。

这不是登录 API 问题，原版 AArch64 反汇编（[方法静态审计 #42384802086](https://github.com/969981/Home_Android/actions/runs/42384802086)，`custom_dropdown_onselect.asm`、`custom_dropdown_setvalue.asm`、`custom_scroll_open.asm`）揭示两个不同语义的代码路径：

```asm
; CustomTMPDropdown.OnSelectItem(int dataIndex), RVA 0x1F15084
0x1F15150 MOV  W8,#1
0x1F15160 STRB W8,[X20,#352]     ; isSelected=true，+0x160
0x1F15164 BL   0x1F1401C          ; SetValue(dataIndex,true)
0x1F15178 B    0x1F14BE0          ; Hide()
```

而原版 `CustomTMPDropdown.set_value(int)`（RVA `0x1F14014`）调用 `SetValue(index,true)`，主要改变 `m_Value(+0x138)` 并刷新文字；**没有上述 `isSelected=true` 与 `Hide()` 完整交互路径**。所以先前只用 Setter 看似成功，却没有证明控件被 UI 真正确认。另一处 `CustomTMPDropdownScrollList.Open(int value)`（`0x1F14C90`）反汇编未发现读取 X1 参数值来控制初始滚动位置，因此 `m_Value=27` 不自动将列表滚到 1999 是符合当前原版指令证据的。

本次新增：
- 原生 Hook `CustomTMPDropdownScrollList.Open`（`0x1F14C90`）：在不输出私人字符串/指针前提下记录年份菜单实际接收的合法索引。
- 原生 Hook `CustomTMPDropdown.OnSelectItem`（`0x1F15084`）：只观察是否真的走用户选项选择事件。
- `birthdate_ui.year_dropdown_is_selected/month_dropdown_is_selected/day_dropdown_is_selected`：读取原版 `isSelected +0x160` 的布尔状态，而不是用 `m_Value` 代替。
- **实验模式** `--probe-native-year-select`：必须本人显式传入；在 1999-04-05 内部已核验、`yearDropdown.m_Value=27`、`isSelected=false` 的情况下，才允许在原版 Unity Show 主线程调用一次原版 `OnSelectItem(27)` 并核对 `isSelected` 与新截图。不会提交生日、协议或创建账号。若内存状态或 NativeBridge RVA 不符，就拒绝调用。
- **另一独立模式** `--probe-year-touch-scroll`：在截图匹配年份弹窗后最多进行四次短滑动，保存每步屏幕，尝试确定用户自然选择是否可行。两种模式应分别验证，不应同时用于同一次测试。

此处只是根因候选：即便 `isSelected=true`，仍须在真实截图独立验证年份框是否真的显示 **1999**，不能仅凭事件计数推断 GUI 已修复。当前尚未点击出生日期【下一步】，更无真实服务端 `basic.utid`。

## 2026-11-08：原版 OnSelectItem 修复可见年份——真实 A/B 成功

**真实 Actions**：[ #42392593321 ](https://github.com/969981/Home_Android/actions/runs/42392593321)；Artifact `home41-arm64-emulated-realm-proof` ID **13581822910**。

对比同一次真实 Android 15 x86_64 + ARM NativeBridge 模拟器的截屏：

- `16_full_date_form_after_back.png`：三个原版 Setter 的内存结果为 1999 / 4 / 5，但 UI 仍显示【年／月／日】。
- `16b_year_before_reopen.png`：在原版年份控件上，`isSelected=false`。
- `17_native_year_OnSelectItem_after.png`：通过 Frida **显式**对下一次原版 `CustomTMPDropdown.Show()` 结束时调用同一 Unity 线程上的原版 `CustomTMPDropdown.OnSelectItem(27)`，UI **确实显示“1999”**，月份/日期仍保持占位符。
- `birthdate_ui.year_dropdown_is_selected=true`、`inputedYear==1999`、`m_Value==27`；`native_year_item_select_attempted/returned/confirmed=true`，`native_year_item_select_failure=false`。HOME 进程存活，没提交生日。

这证明**完整 UI 选项路径不是单纯 `set_value`**；原版 OnSelectItem 设置 `isSelected=true` 后使年份可见。无需通过网络篡改、重签 APK 或重写任意内存来修正当前实验界面。

这轮 Action 最终状态 `failure` 源于一条额外的、现已确认不成立的测试假设：要求 `NativeFunction(OnSelectItem)` 调用同时触发同一 Frida Agent 的 `Interceptor.attach(OnSelectItem)` 事件（该计数实际为 0）。真实原版方法副作用、原版字段回读与截图**已独立验证**，不能因这条事件计数为零就否认 OnSelectItem 实际执行。因此 CI 已更换为可靠的三个证据：原版调用成功 + `isSelected=true` + 目标下拉文字局部像素变化，仍需人工最终核对具体文字。

新扩展 `--probe-native-full-date-select` 使用同一原版 `OnSelectItem` 路径依次确认 **1999、4、5**；需要每步 UI 截图变化、组件 `isSelected=true`、`m_Value` 和控制器字段匹配，不会触碰【下一步】或服务端注册。**完整年月日 UI 可见测试尚需以最新实际 Actions Artifact 核对**，在此之前不声明已通过。


## 2026-11-08：年份 UI 已修复；月份未执行原因是旧截图门槛

最新 [Actions #42393405039](https://github.com/969981/Home_Android/actions/runs/42393405039)，Artifact `home41-arm64-emulated-realm-proof` ID **13582841225**，独立实机式模拟器运行结果：

- 年：`native_year_item_select_attempted/returned/confirmed=true`，`year_dropdown_is_selected=true`，`year_caption_roi_changed=true`；截图 `17_native_year_OnSelectItem_after.png` 显示 **1999**，不再是【年】占位符。
- 月/日：`native_month_item_select_attempted=false`、`native_day_item_select_attempted=false`；`native_month_select_arm_result=not_attempted`，说明**压根没有调用**原版月份选择方法，不能归咎于月日方法失效。
- 真实截图 `18_native_month_before.png`：年份已显示“1999”，月份和日期仍为占位符。自动页面鉴别代码仍使用适合未选年份表单的旧像素规则 `at(.2,.29)≈(248,250,245)`；然而 1999 出现在此处后真实像素变为 **`(142,142,142)`**，因此页面前置检查错误拒绝了后续月份步骤。
- 已新增严格的 `birthday_month_native` / `birthday_day_native` 页面状态签名，只有年份已可见时才识别该阶段。仍验证中文确认年龄标题、浅绿色背景、红字说明、原版下拉框底色和橙色下一步按钮位置；并由 Frida RPC 独立验证正确 Unity 控件实例、4月/5日原生 OptionData 索引。没有降低原版内存与用户选项安全条件。
- 仍未点击【下一步】，没有账户创建、服务端回包和 UTID。

此轮 Action `failure` 是刻意的严格 fail-closed：没有实际选月/日，就必须失败，不允许报告完整生日可视选择成功。最新重跑需检验 `month_dropdown_is_selected=true`、`day_dropdown_is_selected=true` 和截图中的“1999/4/5”。
