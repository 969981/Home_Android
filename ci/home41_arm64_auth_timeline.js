/* Pokémon HOME Android 4.1.0 — native ARM64 first-response time line.
 *
 * Read-only: no API replay, auth bypass, request edits, memory writes, or
 * automated registration/deletion. This is for an original APK on a personally
 * controlled ARM64 Android device with Frida permission.
 *
 * Original APK SHA256: 8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1
 * ARM64 libil2cpp.so SHA256: 80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe
 *
 * Static trace:
 * - 0x1D335AC: LDR D0,[X19,#0xA0] (packed lng/cntry)
 * - 0x1D335BC: STR D0,[X20,#0x28] (registration DTO)
 * - 0x1D2BA60: LDR X0,[X21,#0x18] (ResponseParamCommon.basic)
 * - 0x1D2BA64: BL UDManager.SetBasic (return LR 0x1D2BA68)
 * - UD_Basic.utid: managed System.String pointer +0xF0
 *
 * Never claim that request serialization alone proves network transmission,
 * or that the common basic caller identifies the upstream HTTP endpoint.
 * Neither the six-digit convention nor the Pokemon starter's OT ID is proven.
 */
'use strict';
const KIND = 'home41_arm64_auth_timeline';
const VERSION = '4.1.0';
const TARGET = '888888';
const RVA = Object.freeze({
  registerSerialize: 0x1D334A4,
  registerPackedWriteComplete: 0x1D335C0,
  registerRequestFormatter: 0x205AEF0,
  registerResponseFormatter: 0x205DA3C,
  registerCallback: 0x1D33294,
  tokenSerialize: 0x1D35888,
  tokenCallback: 0x1D35AD0,
  loginSerialize: 0x1D3BE50,
  loginCallback: 0x1D3C020,
  commonResponseHook: 0x1D2AFF0,
  setBasic: 0x1D763D0,
  commonBasicReturn: 0x1D2BA68,
  birthSetData: 0x1C80964,
  birthOnYearChange: 0x1C80EF8,
  birthOnMonthChange: 0x1C814C0,
  birthOnDayChange: 0x1C8181C
});
const begun = Date.now();
const counts = {
  registration_request_serializer_entered: 0,
  registration_lng_cntry_packed_write_seen: 0,
  registration_request_formatter_entered: 0,
  registration_response_formatter_entered: 0,
  registration_response_handler_entered: 0,
  token_request_serializer_entered: 0,
  token_response_handler_entered: 0,
  login_request_serializer_entered: 0,
  login_response_handler_entered: 0,
  common_response_handler_entered: 0,
  first_basic_utid_observed: 0,
  firstboot_birthdata_setdata_entered: 0,
  firstboot_birthdata_year_change_entered: 0,
  firstboot_birthdata_month_change_entered: 0,
  firstboot_birthdata_day_change_entered: 0
};
const LIMIT_PER_EVENT = 16;
let hooksReady = false;
let basicObserved = false;
let firstRawUtid = null;
let firstCandidate = null;
let packedLNG = null;
let packedCNTRY = null;
let fromCommonBasicCaller = false;
let nativeModuleReady = false;
// FirstBootViewInputBirthData instance, strictly private to this local Agent.
// Original managed offsets verified in IL2CppDumper dump.cs:
// yearDropdown +0x28, yearOptionDataList +0x40, inputedYear +0x58,
// inputedMonth +0x5C, inputedDay +0x60.
let birthViewPtr = null;

function readYearOptionText(optionPtr) {
  // Actual HOME CustomTMPDropdown.OptionData.m_Text is a managed string
  // at +0x10. Only 4 ASCII digits are accepted; never expose other strings.
  if (optionPtr.isNull()) return null;
  try {
    const str = optionPtr.add(0x10).readPointer();
    if (str.isNull() || str.add(0x10).readS32() !== 4) return null;
    const value = str.add(0x14).readUtf16String(4);
    return /^\\d{4}$/.test(value) ? value : null;
  } catch (_) {
    return null;
  }
}

function readBirthdateUIState() {
  const empty = {
    controller_seen: birthViewPtr !== null,
    year_dropdown_present: false,
    year_option_list_present: false,
    year_option_count: null,
    year_1999_index: null,
    first_option_is_2026: false,
    inputed_year_in_supported_range: false,
    inputed_year_equals_1999: false,
    inputed_month_in_range: false,
    inputed_day_in_range: false,
    exact_birthdate_selected: false
  };
  if (birthViewPtr === null) return empty;
  try {
    const yearDropdown = birthViewPtr.add(0x28).readPointer();
    const yearList = birthViewPtr.add(0x40).readPointer();
    const year = birthViewPtr.add(0x58).readS32();
    const month = birthViewPtr.add(0x5C).readS32();
    const day = birthViewPtr.add(0x60).readS32();
    let count = null;
    let targetIndex = null;
    let firstIs2026 = false;
    if (!yearList.isNull()) {
      const n = yearList.add(0x18).readS32(); // List<T>._size on 64-bit IL2CPP
      if (n >= 0 && n <= 500) count = n;
      if (count !== null && count <= 300) {
        const items = yearList.add(0x10).readPointer(); // List<T>._items
        if (!items.isNull()) {
          // 64-bit SZArray: object header 0x10 + length 0x08 +
          // 8-byte padding then reference slots begin at +0x20.
          for (let i = 0; i < count; i++) {
            const opt = items.add(0x20 + i * 8).readPointer();
            const value = readYearOptionText(opt);
            if (i === 0) firstIs2026 = value === '2026';
            if (value === '1999') targetIndex = i;
          }
        }
      }
    }
    return {
      controller_seen: true,
      year_dropdown_present: !yearDropdown.isNull(),
      year_option_list_present: !yearList.isNull(),
      year_option_count: count,
      year_1999_index: targetIndex,
      first_option_is_2026: firstIs2026,
      inputed_year_in_supported_range: year >= 1900 && year <= 2100,
      inputed_year_equals_1999: year === 1999,
      inputed_month_in_range: month >= 1 && month <= 12,
      inputed_day_in_range: day >= 1 && day <= 31,
      exact_birthdate_selected: year === 1999 && month === 4 && day === 5
    };
  } catch (_) {
    return empty;
  }
}

function emit(event, extra = {}) {
  // All messages are categorical. NEVER send raw UTID, lng, cntry, token,
  // UUID, URI, IP, headers or memory pointers in the public event stream.
  send({kind: KIND, version: VERSION, event,
        elapsed_ms: Date.now() - begun, ...extra});
}
function milestone(event, extra = {}) {
  counts[event]++;
  if (counts[event] <= LIMIT_PER_EVENT) {
    emit(event, {index: counts[event], ...extra});
  }
}
rpc.exports = {
  snapshot() {
    return {
      native_arm64: Process.arch === 'arm64',
      native_module_ready: nativeModuleReady,
      hooks_ready: hooksReady,
      first_basic_seen: basicObserved,
      observed_common_basic_caller: fromCommonBasicCaller,
      serialized_lng_cntry_seen: packedLNG !== null && packedCNTRY !== null,
      birthdate_ui: readBirthdateUIState(),
      counts: {...counts}
    };
  },
  // Only a local, explicitly opted-in Frida host may call this.
  // The Python host MUST NOT write this RPC result to Actions artifacts/logs.
  localvalues() {
    return {
      first_basic_seen: basicObserved,
      from_common_basic_caller: fromCommonBasicCaller,
      raw_utid: firstRawUtid,
      six_digit_candidate: firstCandidate,
      candidate_matches_target: firstCandidate !== null && firstCandidate === TARGET,
      request_packed_values_seen: packedLNG !== null && packedCNTRY !== null,
      lng_candidate: packedLNG,
      cntry_candidate: packedCNTRY,
      // Private local RPC, not included in sanitized public artifacts.
      birthdate_ui: readBirthdateUIState(),
      interpretation: 'LANGUAGE_COUNTRY_DTO_FIELDS_AND_TID7_UI_SEMANTICS_UNVERIFIED'
    };
  }
};

function readBasicUtid(ptr) {
  if (ptr.isNull()) return null;
  const str = ptr.add(0xF0).readPointer();
  if (str.isNull()) return null;
  const length = str.add(0x10).readS32();
  if (length < 1 || length > 10) return null;
  const raw = str.add(0x14).readUtf16String(length);
  if (!/^[0-9]{1,10}$/.test(raw)) return null;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n > 4294967295) return null;
  return {raw, six: String(n % 1000000).padStart(6, '0')};
}
function install(lib) {
  if (hooksReady) return;
  nativeModuleReady = true;
  if (Process.arch !== 'arm64') {
    emit('native_preflight_failed', {reason: 'not_native_arm64'});
    return;
  }
  if (lib.size <= Math.max(...Object.values(RVA))) {
    emit('native_preflight_failed', {reason: 'rva_outside_module'});
    return;
  }
  const ptr = rva => lib.base.add(rva);
  let errors = 0;
  function hook(name, rva, callbacks) {
    try {
      Interceptor.attach(ptr(rva), callbacks);
    } catch (_) {
      errors++;
      emit('hook_attach_failed', {observer: name});
    }
  }
  function onEntered(name) {
    return {onEnter() {milestone(name);}};
  }

  hook('register_serialize', RVA.registerSerialize,
       onEntered('registration_request_serializer_entered'));

  // Static store at 0x1D335BC has ALREADY executed at this instruction.
  // X20 denotes the request DTO and two S32 members start at +0x28/+0x2C.
  // The integer values are never emitted, and only accessible via local RPC.
  hook('register_packed_write', RVA.registerPackedWriteComplete, {
    onEnter() {
      try {
        const dto = this.context.x20;
        const language = dto.add(0x28).readS32();
        const country = dto.add(0x2C).readS32();
        // Wide bounds distinguish readable candidates from arbitrary pointers;
        // they DO NOT validate the game's enum semantics or UI equivalence.
        if (language < 0 || language > 10000 ||
            country < 0 || country > 10000) {
          emit('registration_packed_fields_invalid');
          return;
        }
        packedLNG = language;
        packedCNTRY = country;
        milestone('registration_lng_cntry_packed_write_seen',
                  {values_redacted: true, fields_readable: true});
      } catch (_) {
        emit('registration_packed_fields_unreadable');
      }
    }
  });
  // The native formatter entry identifies *serialization/deserialization*,
  // not verified HTTP send/receive completion.
  hook('register_request_formatter', RVA.registerRequestFormatter,
       onEntered('registration_request_formatter_entered'));
  hook('register_response_formatter', RVA.registerResponseFormatter,
       onEntered('registration_response_formatter_entered'));
  hook('register_callback', RVA.registerCallback,
       onEntered('registration_response_handler_entered'));
  hook('token_serialize', RVA.tokenSerialize,
       onEntered('token_request_serializer_entered'));
  hook('token_callback', RVA.tokenCallback,
       onEntered('token_response_handler_entered'));
  hook('login_serialize', RVA.loginSerialize,
       onEntered('login_request_serializer_entered'));
  hook('login_callback', RVA.loginCallback,
       onEntered('login_response_handler_entered'));
  hook('common_response', RVA.commonResponseHook,
       onEntered('common_response_handler_entered'));

  // The birthdate VIEW is observable before account creation. This is not
  // registration or service response instrumentation and never sets DOB.
  hook('birthview_setdata', RVA.birthSetData, {
    onEnter(args) {
      birthViewPtr = args[0];
      milestone('firstboot_birthdata_setdata_entered', {
        raw_birthdate_values_redacted: true,
        field_offsets_static_only: true
      });
    }
  });
  hook('birthview_year_change', RVA.birthOnYearChange, {
    onEnter(args) {
      birthViewPtr = args[0];
      milestone('firstboot_birthdata_year_change_entered', {
        raw_year_value_redacted: true
      });
    }
  });
  hook('birthview_month_change', RVA.birthOnMonthChange, {
    onEnter(args) {
      birthViewPtr = args[0];
      milestone('firstboot_birthdata_month_change_entered', {
        raw_month_value_redacted: true
      });
    }
  });
  hook('birthview_day_change', RVA.birthOnDayChange, {
    onEnter(args) {
      birthViewPtr = args[0];
      milestone('firstboot_birthdata_day_change_entered', {
        raw_day_value_redacted: true
      });
    }
  });
  hook('set_basic', RVA.setBasic, {
    onEnter(args) {
      if (basicObserved) return;
      let callerIsVerified = false;
      try {
        callerIsVerified = this.context.lr.equals(ptr(RVA.commonBasicReturn));
      } catch (_) {
        emit('basic_caller_unreadable');
        return;
      }
      if (!callerIsVerified) {
        emit('setbasic_unverified_caller');
        return;
      }
      try {
        const identity = readBasicUtid(args[0]); // X0 = basic, per actual BL.
        if (identity === null) {
          emit('basic_missing_numeric_utid');
          return;
        }
        basicObserved = true;
        fromCommonBasicCaller = true;
        firstRawUtid = identity.raw;
        firstCandidate = identity.six;
        milestone('first_basic_utid_observed', {
          from_common_basic_consumer: true,
          candidate_matches_target: firstCandidate === TARGET,
          source_endpoint_verified: false,
          display_id_semantics_verified: false
        });
      } catch (_) {
        emit('basic_read_failed');
      }
    }
  });
  hooksReady = errors === 0;
  emit(errors === 0 ? 'arm64_auth_observer_ready' : 'arm64_auth_observer_partial', {
    hook_failures: errors, registered_dto_static_fields: 'lng,cntry',
    actual_http_request_send_verified: false
  });
}

const watch = setInterval(() => {
  try {
    const lib = Process.findModuleByName('libil2cpp.so');
    if (lib !== null) {
      clearInterval(watch);
      install(lib);
    }
  } catch (_) {
    clearInterval(watch);
    emit('native_preflight_failed', {reason: 'module_watcher_failed'});
  }
}, 200);
