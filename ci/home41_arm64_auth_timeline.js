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
  birthOnDayChange: 0x1C8181C,
  customDropdownShow: 0x1F14920,
  customDropdownScrollOpen: 0x1F14C90,
  customDropdownOnSelectItem: 0x1F15084,
  customDropdownSetValue: 0x1F14014,
  // Static originals in 4.1.0 IL2CppDumper ScriptMethod; NOT yet runtime
  // validated (separate candidate events never authorize consent clicks).
  firstBootAddClauseAgree: 0x1DE09D8,
  firstBootSetupConfirmationTerms: 0x1DE2400,
  firstBootCheckboxValueChanged: 0x1C7FD54,
  termsConfirmDialogOpen: 0x1E22360,
  termsConfirmDialogOkClick: 0x1E22738,
  firstBootBodyStart: 0x1DDFAF0,
  firstBootBodyDestroy: 0x1DDFD6C,
  firstBootContentsFirst: 0x1DE1D84,
  firstBootConfirmTerms: 0x1DE2E4C,
  firstBootConfirmAdvertisementSDK: 0x1DE30E8,
  firstBootGoToPhase: 0x1DE1C10,
  // Original 4.1.0 FirstBootBodyController guest-confirmation methods.
  // Read-only observations; never invoke callbacks or create a guest.
  firstBootConfirmationGestAccount: 0x1DE369C,
  firstBootConfirmGestAccountFirst: 0x1DE5140,
  firstBootConfirmGestAccountSecond: 0x1DE5318,
  // Byte-verified direct BL targets, still UNCLASSIFIED: these addresses do
  // not prove a delegate, registration API, or account-creation identity.
  guestSecondDirectCalleeUnclassified: 0x1DEB3C0,
  // Original A64 tail thunks: 0x1DEB4A4 B DecisionGestAccount,
  // 0x1DEB58C B DenialGestAccount. The binding of official UI buttons
  // to those delegates is still a separate runtime observation.
  guestSecondDecisionThunk: 0x1DEB490,
  guestSecondDenialThunk: 0x1DEB578,
  postGuestCandidate1098: 0x1DE1098,
  postGuestCandidate16F4: 0x1DE16F4,
  // The two old "postGuestCandidate" labels are legacy only:
  // 0x1DE1098 = FirstBootBodyController._AddWarningPart,
  // 0x1DE16F4 = FirstBootBodyController._AddPadder.
  // They are UI construction helpers, NOT registration callbacks.
  // Original IL2CPP class declarations verified in PokeHome_Resources
  // static Actions #42460662202.
  firstBootDecisionGestAccount: 0x1DE5508,
  firstBootDenialGestAccount: 0x1DE5698,
  firstBootGuestStartCallbackB84_6: 0x1DE64C0,
  firstBootStartCallbackB84_9: 0x1DE64FC,
  firstBootStartCallbackB84_10: 0x1DE65B8,
  firstBootStartCallbackB84_13: 0x1DE65DC,
  firstBootSelectTrainerIcon: 0x1DE48F8,
  firstBootInputName: 0x1DE4764,
  firstBootLogin: 0x1DE4520,
  firstBootConfirmMTDetail: 0x1DE4A98,
  firstBootPlayPrologue: 0x1DE45E8,
  firstBootPlayPrologue2: 0x1DE4CF4,
  firstBootAddIconSelecter: 0x1DE11D0,
  firstBootAddProloguePanel: 0x1DE1894,
  firstBootSetUpContentsForMTAccountSetting: 0x1DE2490,
  firstBootIconSelectorSetData: 0x1C800C4,
  firstBootIconSelectorCreateImages: 0x1C800E0,
  firstBootIconSelectorOnTapIcon: 0x1C803AC,
  firstBootProloguePanelSetPokemonView: 0x1C7D658,
  firstBootProloguePanelCastPokemonSelect: 0x1C7DE6C,
  firstBootProloguePokemonPanelOpen: 0x1C7DC8C,
  firstBootProloguePokemonPanelOnTapPokemon: 0x1C7F0F4,
  firstBootProloguePokemonPanelSelectedIcon: 0x1C7F230,
  firstBootProloguePanelOnTapYes: 0x1C7E008,
  authManagerRegisterUser: 0x1D2F8DC
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
  firstboot_birthdata_day_change_entered: 0,
  firstboot_year_scroll_open_entered: 0,
  firstboot_year_item_selection_entered: 0,
  firstboot_clause_agree_part_entered: 0,
  firstboot_terms_confirmation_setup_entered: 0,
  firstboot_agreement_checkbox_changed: 0,
  terms_confirm_dialog_open_entered: 0,
  terms_confirm_dialog_ok_clicked: 0,
  firstboot_controller_start_entered: 0,
  firstboot_contents_first_entered: 0,
  firstboot_confirmation_terms_entered: 0,
  firstboot_confirmation_advertisement_sdk_entered: 0,
  firstboot_go_to_phase_entered: 0,
  firstboot_confirmation_gest_account_entered: 0,
  firstboot_confirm_gest_first_entered: 0,
  firstboot_confirm_gest_second_entered: 0,
  guest_second_direct_callee_unclassified_entered: 0,
  guest_second_decision_thunk_entered: 0,
  guest_second_denial_thunk_entered: 0,
  post_guest_candidate_1098_entered: 0,
  post_guest_candidate_16f4_entered: 0,
  auth_manager_register_user_entered: 0,
  firstboot_decision_gest_account_entered: 0,
  firstboot_denial_gest_account_entered: 0,
  firstboot_guest_start_callback_b84_6_entered: 0,
  firstboot_start_callback_b84_9_entered: 0,
  firstboot_start_callback_b84_10_entered: 0,
  firstboot_start_callback_b84_13_entered: 0,
  firstboot_select_trainer_icon_entered: 0,
  firstboot_input_name_entered: 0,
  firstboot_login_entered: 0,
  firstboot_confirm_mt_detail_entered: 0,
  firstboot_play_prologue_entered: 0,
  firstboot_play_prologue2_entered: 0,
  firstboot_add_icon_selector_entered: 0,
  firstboot_add_prologue_panel_entered: 0,
  firstboot_setup_mt_account_setting_entered: 0,
  firstboot_icon_selector_set_data_entered: 0,
  firstboot_icon_selector_create_images_entered: 0,
  firstboot_icon_selector_on_tap_icon_entered: 0,
  firstboot_prologue_panel_set_pokemon_view_entered: 0,
  firstboot_prologue_panel_cast_pokemon_select_entered: 0,
  firstboot_prologue_pokemon_panel_open_entered: 0,
  firstboot_prologue_pokemon_panel_on_tap_pokemon_entered: 0,
  firstboot_prologue_pokemon_panel_selected_icon_entered: 0,
  firstboot_prologue_panel_on_tap_yes_entered: 0
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
// Original FirstBootBodyController._currentPhase at +0xEC, from 4.1.0 dump.cs.
// Its numerical value is an unverified enum until independent mapping.
let firstBootBodyPtr = null;
let lastRequestedFirstBootPhaseIndex = null;
let firstBootGoToPhaseHookAttached = false;
let firstBootAdvertisementSDKHookAttached = false;
// Fixed-name coverage bits; never contain pointers or captured objects.
let guestCallbackHookCoverage = {
  second_direct: false, decision_thunk: false, denial_thunk: false,
  post_1098: false, post_16f4: false, register_manager: false
};
// Each value is the actual Interceptor.attach outcome, not a guess based
// on whether the method has been invoked yet.
let postGuestUiHookCoverage = {};
function readCurrentFirstBootPhase() {
  if (firstBootBodyPtr === null) return null;
  try {
    const phase = firstBootBodyPtr.add(0xEC).readS32();
    return Number.isInteger(phase) && phase >= 0 && phase <= 128
      ? phase : null;
  } catch (_) {return null;}
}
// FirstBootViewInputBirthData instance, strictly private to this local Agent.
// Original managed offsets verified in IL2CppDumper dump.cs:
// yearDropdown +0x28, yearOptionDataList +0x40, inputedYear +0x58,
// inputedMonth +0x5C, inputedDay +0x60.
let birthViewPtr = null;
let optInYearSetArmed = false;
let localYearSetAttempted = false;
let localYearSetterReturned = false;
let localYearSetterFailure = false;
let yearScrollOpenInputIndex = null;
let yearScrollOpenInputEquals1999 = false;
let yearItemSelectedIndex = null;
let yearItemSelectionCount = 0;
let optInNativeYearItemSelect = false;
let nativeYearItemSelectAttempted = false;
let nativeYearItemSelectReturned = false;
let nativeYearItemSelectConfirmed = false;
let nativeYearItemSelectFailure = false;
let optInNativeMonthItemSelect = false, optInNativeDayItemSelect = false;
let nativeMonthItemSelectAttempted = false, nativeDayItemSelectAttempted = false;
let nativeMonthItemSelectReturned = false, nativeDayItemSelectReturned = false;
let nativeMonthItemSelectConfirmed = false, nativeDayItemSelectConfirmed = false;
let nativeMonthItemSelectFailure = false, nativeDayItemSelectFailure = false;
let optInMonthSetArmed = false, optInDaySetArmed = false;
let localMonthSetAttempted = false, localDaySetAttempted = false;
let localMonthSetterReturned = false, localDaySetterReturned = false;
let localMonthSetterFailure = false, localDaySetterFailure = false;

function readShortOptionLabel(optionPtr) {
  // Only tiny decimal month/day labels from the game's own OptionData.
  // No arbitrary text, strings containing account details, or raw pointers
  // ever leave this agent.
  if (optionPtr.isNull()) return null;
  try {
    const str = optionPtr.add(0x10).readPointer();
    if (str.isNull()) return null;
    const len = str.add(0x10).readS32();
    if (len < 1 || len > 4) return null;
    const label = str.add(0x14).readUtf16String(len);
    return /^(?:0?[1-9]|1[0-2]|[12][0-9]|3[01])(?:月|日)?$/.test(label) ?
      label : null;
  } catch (_) { return null; }
}
function describeSmallDropdown(view, dropdownOffset, listOffset, target, expectedCount) {
  const unknown = {
    dropdown_present: false, option_list_present: false,
    option_count: null, target_index: null,
    target_found_uniquely: false, value_index_equals_target: false,
    target_option_text_verified: false
  };
  try {
    const dropdown = view.add(dropdownOffset).readPointer();
    const list = view.add(listOffset).readPointer();
    if (dropdown.isNull() || list.isNull()) return unknown;
    unknown.dropdown_present = true;
    unknown.option_list_present = true;
    const count = list.add(0x18).readS32();
    if (count < 1 || count > 32) return unknown;
    unknown.option_count = count;
    const items = list.add(0x10).readPointer();
    if (items.isNull()) return unknown;
    let found = -1, matches = 0;
    for (let i = 0; i < count; i++) {
      const option = items.add(0x20 + i * 8).readPointer();
      const label = readShortOptionLabel(option);
      if (label !== null) {
        const numeric = parseInt(label, 10);
        if (numeric === target) { matches++; found = i; }
      }
    }
    if (matches === 1 && count === expectedCount) {
      unknown.target_index = found;
      unknown.target_found_uniquely = true;
      unknown.target_option_text_verified = true;
      unknown.value_index_equals_target =
        dropdown.add(0x138).readS32() === found;
    }
    return unknown;
  } catch (_) { return unknown; }
}

function readYearOptionText(optionPtr) {
  // Actual HOME CustomTMPDropdown.OptionData.m_Text is a managed string
  // at +0x10. Only 4 ASCII digits are accepted; never expose other strings.
  if (optionPtr.isNull()) return null;
  try {
    const str = optionPtr.add(0x10).readPointer();
    if (str.isNull() || str.add(0x10).readS32() !== 4) return null;
    const value = str.add(0x14).readUtf16String(4);
    return /^\d{4}$/.test(value) ? value : null;
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
    year_dropdown_value_index: null,
    year_dropdown_value_equals_1999_option: false,
    year_dropdown_is_selected: null,
    month_dropdown_is_selected: null,
    day_dropdown_is_selected: null,
    month_dropdown: {
      dropdown_present: false, option_list_present: false,
      option_count: null, target_index: null,
      target_found_uniquely: false, value_index_equals_target: false,
      target_option_text_verified: false
    },
    day_dropdown: {
      dropdown_present: false, option_list_present: false,
      option_count: null, target_index: null,
      target_found_uniquely: false, value_index_equals_target: false,
      target_option_text_verified: false
    },
    inputed_year_in_supported_range: false,
    inputed_year_equals_1999: false,
    inputed_month_in_range: false,
    inputed_month_equals_4: false,
    inputed_day_in_range: false,
    inputed_day_equals_5: false,
    exact_birthdate_selected: false
  };
  if (birthViewPtr === null) return empty;
  try {
    const yearDropdown = birthViewPtr.add(0x28).readPointer();
    const yearList = birthViewPtr.add(0x40).readPointer();
    const year = birthViewPtr.add(0x58).readS32();
    const month = birthViewPtr.add(0x5C).readS32();
    const day = birthViewPtr.add(0x60).readS32();
    const monthStatus = describeSmallDropdown(
      birthViewPtr, 0x30, 0x48, 4, 12);
    // Day options may be rebuilt on month selection. April has 30 days.
    const dayStatus = describeSmallDropdown(
      birthViewPtr, 0x38, 0x50, 5, month === 4 ? 30 : 31);
    const yearValue = yearDropdown.isNull() ? null :
      yearDropdown.add(0x138).readS32();
    const yearSelected = yearDropdown.isNull() ? null :
      yearDropdown.add(0x160).readU8() === 1;
    const monthDropdown = birthViewPtr.add(0x30).readPointer();
    const dayDropdown = birthViewPtr.add(0x38).readPointer();
    const monthSelected = monthDropdown.isNull() ? null :
      monthDropdown.add(0x160).readU8() === 1;
    const daySelected = dayDropdown.isNull() ? null :
      dayDropdown.add(0x160).readU8() === 1;
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
      year_dropdown_value_index: yearValue >= -1 && yearValue <= 126 ?
          yearValue : null,
      year_dropdown_value_equals_1999_option: targetIndex !== null &&
          yearValue === targetIndex,
      year_dropdown_is_selected: yearSelected,
      month_dropdown_is_selected: monthSelected,
      day_dropdown_is_selected: daySelected,
      month_dropdown: monthStatus,
      day_dropdown: dayStatus,
      inputed_year_in_supported_range: year >= 1900 && year <= 2100,
      inputed_year_equals_1999: year === 1999,
      inputed_month_in_range: month >= 1 && month <= 12,
      inputed_month_equals_4: month === 4,
      inputed_day_in_range: day >= 1 && day <= 31,
      inputed_day_equals_5: day === 5,
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
      firstboot_ui: {
        original_controller_seen: firstBootBodyPtr !== null,
        original_phase_enum_index: readCurrentFirstBootPhase(),
        original_phase_mapping_verified: false,
        last_requested_phase_enum_index: lastRequestedFirstBootPhaseIndex,
        go_to_phase_hook_attached: firstBootGoToPhaseHookAttached,
        advertisement_sdk_hook_attached: firstBootAdvertisementSDKHookAttached
      },
      birthdate_ui: {
        ...readBirthdateUIState(),
        year_setter_opted_in: optInYearSetArmed,
        year_setter_attempted: localYearSetAttempted,
        year_setter_returned: localYearSetterReturned,
        year_setter_failure: localYearSetterFailure,
        year_scroll_open_input_index: yearScrollOpenInputIndex,
        year_scroll_open_input_equals_1999: yearScrollOpenInputEquals1999,
        year_item_selection_count: yearItemSelectionCount,
        year_item_selected_index: yearItemSelectedIndex,
        native_year_item_select_attempted: nativeYearItemSelectAttempted,
        native_year_item_select_returned: nativeYearItemSelectReturned,
        native_year_item_select_confirmed: nativeYearItemSelectConfirmed,
        native_year_item_select_failure: nativeYearItemSelectFailure,
        native_month_item_select_attempted: nativeMonthItemSelectAttempted,
        native_month_item_select_returned: nativeMonthItemSelectReturned,
        native_month_item_select_confirmed: nativeMonthItemSelectConfirmed,
        native_month_item_select_failure: nativeMonthItemSelectFailure,
        native_day_item_select_attempted: nativeDayItemSelectAttempted,
        native_day_item_select_returned: nativeDayItemSelectReturned,
        native_day_item_select_confirmed: nativeDayItemSelectConfirmed,
        native_day_item_select_failure: nativeDayItemSelectFailure,
        month_setter_attempted: localMonthSetAttempted,
        month_setter_returned: localMonthSetterReturned,
        month_setter_failure: localMonthSetterFailure,
        day_setter_attempted: localDaySetAttempted,
        day_setter_returned: localDaySetterReturned,
        day_setter_failure: localDaySetterFailure
      },
      counts: {...counts},
      guest_callback_hook_coverage: {...guestCallbackHookCoverage},
      post_guest_ui_hook_coverage: {...postGuestUiHookCoverage}
    };
  },
  // Explicit single local-form interaction. Never used by the ordinary
  // read-only observer or without a native year-option scan and unselected UI.
  // The actual call happens within HOME's original Unity Show callback.
  armlocalyear1999() {
    if (!hooksReady || Process.arch !== 'arm64' || optInYearSetArmed ||
        localYearSetAttempted) return false;
    const ui = readBirthdateUIState();
    if (ui.year_option_count !== 127 || ui.year_1999_index !== 27 ||
        !ui.first_option_is_2026 || !ui.year_dropdown_present ||
        ui.inputed_year_in_supported_range || ui.exact_birthdate_selected) return false;
    optInYearSetArmed = true;
    emit('year_1999_local_setter_armed', {
      original_dropdown_index_verified: true,
      birthday_submission_attempted: false
    });
    return true;
  },
  armnativeyearitemselect() {
    // One controlled A/B experiment: reproduce the ORIGINAL OnSelectItem
    // pipeline that sets isSelected and calls SetValue+Hide, not just SetValue.
    // Only permitted when 1999-04-05 is already internally selected.
    if (!hooksReady || Process.arch !== 'arm64' ||
        optInNativeYearItemSelect || nativeYearItemSelectAttempted ||
        optInYearSetArmed || optInMonthSetArmed || optInDaySetArmed) return false;
    const ui = readBirthdateUIState();
    if (!ui.exact_birthdate_selected ||
        !ui.year_dropdown_value_equals_1999_option ||
        ui.year_dropdown_is_selected !== false ||
        ui.year_1999_index !== 27 ||
        !ui.first_option_is_2026 ||
        ui.month_dropdown.value_index_equals_target !== true ||
        ui.day_dropdown.value_index_equals_target !== true) return false;
    optInNativeYearItemSelect = true;
    emit('year_native_item_select_armed', {
      original_onselect_pipeline: true,
      birthday_submission_attempted: false
    });
    return true;
  },
  armnativemonthitemselect() {
    if (!hooksReady || Process.arch !== 'arm64' ||
        optInNativeMonthItemSelect || nativeMonthItemSelectAttempted ||
        !nativeYearItemSelectConfirmed) return false;
    const ui=readBirthdateUIState();
    if (!ui.inputed_year_equals_1999 || !ui.year_dropdown_is_selected ||
        !ui.year_dropdown_value_equals_1999_option ||
        !ui.month_dropdown.target_found_uniquely ||
        ui.month_dropdown.target_index !== 3 ||
        ui.month_dropdown.option_count !== 12 ||
        ui.month_dropdown.value_index_equals_target !== true ||
        ui.month_dropdown_is_selected !== false) return false;
    optInNativeMonthItemSelect = true;
    emit('month_native_item_select_armed', {
      birthday_submission_attempted: false
    });
    return true;
  },
  armnativedayitemselect() {
    if (!hooksReady || Process.arch !== 'arm64' ||
        optInNativeDayItemSelect || nativeDayItemSelectAttempted ||
        !nativeYearItemSelectConfirmed ||
        !nativeMonthItemSelectConfirmed) return false;
    const ui=readBirthdateUIState();
    if (!ui.inputed_year_equals_1999 || !ui.year_dropdown_is_selected ||
        !ui.inputed_month_equals_4 || !ui.month_dropdown_is_selected ||
        !ui.day_dropdown.target_found_uniquely ||
        ui.day_dropdown.target_index !== 4 ||
        ui.day_dropdown.option_count !== 30 ||
        ui.day_dropdown.value_index_equals_target !== true ||
        ui.day_dropdown_is_selected !== false) return false;
    optInNativeDayItemSelect = true;
    emit('day_native_item_select_armed', {
      birthday_submission_attempted: false
    });
    return true;
  },
  armlocalmonth4() {
    if (!hooksReady || Process.arch !== 'arm64' ||
        optInMonthSetArmed || localMonthSetAttempted) return false;
    const ui = readBirthdateUIState();
    if (!ui.inputed_year_equals_1999 ||
        !ui.year_dropdown_value_equals_1999_option ||
        !ui.month_dropdown.target_found_uniquely ||
        !ui.month_dropdown.target_option_text_verified ||
        ui.month_dropdown.option_count !== 12 ||
        ui.month_dropdown.target_index !== 3 ||
        ui.inputed_month_in_range || ui.inputed_day_in_range) return false;
    optInMonthSetArmed = true;
    emit('month_4_local_setter_armed', {
      original_dropdown_index_verified: true,
      birthday_submission_attempted: false
    });
    return true;
  },
  armlocalday5() {
    if (!hooksReady || Process.arch !== 'arm64' ||
        optInDaySetArmed || localDaySetAttempted) return false;
    const ui = readBirthdateUIState();
    if (!ui.inputed_year_equals_1999 ||
        !ui.year_dropdown_value_equals_1999_option ||
        !ui.inputed_month_equals_4 ||
        !ui.month_dropdown.value_index_equals_target ||
        !ui.day_dropdown.target_found_uniquely ||
        !ui.day_dropdown.target_option_text_verified ||
        ui.day_dropdown.option_count !== 30 ||
        ui.day_dropdown.target_index !== 4 ||
        ui.inputed_day_in_range) return false;
    optInDaySetArmed = true;
    emit('day_5_local_setter_armed', {
      original_dropdown_index_verified: true,
      birthday_submission_attempted: false
    });
    return true;
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
  // Static HOME FirstBoot terms UI discovery: these are informational
  // observers only, not consent controls. Optional so a changed/unsupported
  // UI candidate never breaks the original auth or birthday hooks.
  function optionalUiObserver(name, rva, event) {
    try {
      Interceptor.attach(ptr(rva), onEntered(event));
      return true;
    } catch (_) {
      emit('optional_hook_attach_failed', {observer: name});
      return false;
    }
  }
  optionalUiObserver('firstboot_clause', RVA.firstBootAddClauseAgree,
                     'firstboot_clause_agree_part_entered');
  optionalUiObserver('firstboot_terms_setup', RVA.firstBootSetupConfirmationTerms,
                     'firstboot_terms_confirmation_setup_entered');
  optionalUiObserver('firstboot_checkbox', RVA.firstBootCheckboxValueChanged,
                     'firstboot_agreement_checkbox_changed');
  optionalUiObserver('terms_dialog_open', RVA.termsConfirmDialogOpen,
                     'terms_confirm_dialog_open_entered');
  optionalUiObserver('terms_dialog_ok', RVA.termsConfirmDialogOkClick,
                     'terms_confirm_dialog_ok_clicked');
  optionalUiObserver('guest_confirmation',
                     RVA.firstBootConfirmationGestAccount,
                     'firstboot_confirmation_gest_account_entered');
  optionalUiObserver('guest_confirm_first',
                     RVA.firstBootConfirmGestAccountFirst,
                     'firstboot_confirm_gest_first_entered');
  optionalUiObserver('guest_confirm_second',
                     RVA.firstBootConfirmGestAccountSecond,
                     'firstboot_confirm_gest_second_entered');
  // Pure entry counters for next observation: no args, pointers, return
  // values or network content are emitted, and no callback is invoked.
  guestCallbackHookCoverage.second_direct =
    optionalUiObserver('guest_second_direct_callee_unclassified',
                       RVA.guestSecondDirectCalleeUnclassified,
                       'guest_second_direct_callee_unclassified_entered');
  guestCallbackHookCoverage.decision_thunk =
    optionalUiObserver('guest_second_decision_thunk',
                       RVA.guestSecondDecisionThunk,
                       'guest_second_decision_thunk_entered');
  guestCallbackHookCoverage.denial_thunk =
    optionalUiObserver('guest_second_denial_thunk',
                       RVA.guestSecondDenialThunk,
                       'guest_second_denial_thunk_entered');
  guestCallbackHookCoverage.post_1098 =
    optionalUiObserver('post_guest_candidate_1098',
                       RVA.postGuestCandidate1098,
                       'post_guest_candidate_1098_entered');
  guestCallbackHookCoverage.post_16f4 =
    optionalUiObserver('post_guest_candidate_16f4',
                       RVA.postGuestCandidate16F4,
                       'post_guest_candidate_16f4_entered');
  guestCallbackHookCoverage.register_manager =
    optionalUiObserver('auth_manager_register_user',
                       RVA.authManagerRegisterUser,
                       'auth_manager_register_user_entered');
  // Exact original IL2CPP UI method names and entry RVAs. Pure read-only
  // counters, with the original client's own clicks/decisions. No code calls
  // these native functions, no fields/args/pointers or account IDs exposed.
  for (const item of [
    ['decision_gest', RVA.firstBootDecisionGestAccount,
      'firstboot_decision_gest_account_entered'],
    ['denial_gest', RVA.firstBootDenialGestAccount,
      'firstboot_denial_gest_account_entered'],
    ['guest_start_b84_6', RVA.firstBootGuestStartCallbackB84_6,
      'firstboot_guest_start_callback_b84_6_entered'],
    ['start_b84_9', RVA.firstBootStartCallbackB84_9,
      'firstboot_start_callback_b84_9_entered'],
    ['start_b84_10', RVA.firstBootStartCallbackB84_10,
      'firstboot_start_callback_b84_10_entered'],
    ['start_b84_13', RVA.firstBootStartCallbackB84_13,
      'firstboot_start_callback_b84_13_entered'],
    ['select_trainer_icon', RVA.firstBootSelectTrainerIcon,
      'firstboot_select_trainer_icon_entered'],
    ['input_name', RVA.firstBootInputName,
      'firstboot_input_name_entered'],
    ['firstboot_login', RVA.firstBootLogin,
      'firstboot_login_entered'],
    ['confirm_mt_detail', RVA.firstBootConfirmMTDetail,
      'firstboot_confirm_mt_detail_entered'],
    ['play_prologue', RVA.firstBootPlayPrologue,
      'firstboot_play_prologue_entered'],
    ['play_prologue2', RVA.firstBootPlayPrologue2,
      'firstboot_play_prologue2_entered'],
    ['add_icon_selector', RVA.firstBootAddIconSelecter,
      'firstboot_add_icon_selector_entered'],
    ['add_prologue_panel', RVA.firstBootAddProloguePanel,
      'firstboot_add_prologue_panel_entered'],
    ['setup_mt_account', RVA.firstBootSetUpContentsForMTAccountSetting,
      'firstboot_setup_mt_account_setting_entered'],
    ['icon_selector_set_data', RVA.firstBootIconSelectorSetData,
      'firstboot_icon_selector_set_data_entered'],
    ['icon_selector_create_images', RVA.firstBootIconSelectorCreateImages,
      'firstboot_icon_selector_create_images_entered'],
    ['icon_selector_on_tap', RVA.firstBootIconSelectorOnTapIcon,
      'firstboot_icon_selector_on_tap_icon_entered'],
    ['prologue_set_pokemon_view', RVA.firstBootProloguePanelSetPokemonView,
      'firstboot_prologue_panel_set_pokemon_view_entered'],
    ['prologue_cast_pokemon_select', RVA.firstBootProloguePanelCastPokemonSelect,
      'firstboot_prologue_panel_cast_pokemon_select_entered'],
    ['prologue_pokemon_panel_open', RVA.firstBootProloguePokemonPanelOpen,
      'firstboot_prologue_pokemon_panel_open_entered'],
    ['prologue_pokemon_tap', RVA.firstBootProloguePokemonPanelOnTapPokemon,
      'firstboot_prologue_pokemon_panel_on_tap_pokemon_entered'],
    ['prologue_pokemon_selected_icon', RVA.firstBootProloguePokemonPanelSelectedIcon,
      'firstboot_prologue_pokemon_panel_selected_icon_entered'],
    ['prologue_on_tap_yes', RVA.firstBootProloguePanelOnTapYes,
      'firstboot_prologue_panel_on_tap_yes_entered'],
  ]) {
    postGuestUiHookCoverage[item[0]] =
      optionalUiObserver(item[0], item[1], item[2]);
  }
  // Read-only original FirstBoot phase observation, no workflow changes.
  // Start and original setup callbacks capture the managed instance only
  // inside this private Frida agent. Never publish the instance pointer.
  try {
    Interceptor.attach(ptr(RVA.firstBootBodyStart), {
      onEnter(args) {
        firstBootBodyPtr = args[0];
        milestone('firstboot_controller_start_entered');
      }
    });
    Interceptor.attach(ptr(RVA.firstBootContentsFirst), {
      onEnter(args) {
        firstBootBodyPtr = args[0];
        milestone('firstboot_contents_first_entered');
      }
    });
    Interceptor.attach(ptr(RVA.firstBootConfirmTerms), {
      onEnter(args) {
        firstBootBodyPtr = args[0];
        milestone('firstboot_confirmation_terms_entered');
      }
    });
    Interceptor.attach(ptr(RVA.firstBootConfirmAdvertisementSDK), {
      onEnter(args) {
        firstBootBodyPtr = args[0];
        milestone('firstboot_confirmation_advertisement_sdk_entered');
      }
    });
    firstBootAdvertisementSDKHookAttached = true;
    Interceptor.attach(ptr(RVA.firstBootGoToPhase), {
      onEnter(args) {
        firstBootBodyPtr = args[0];
        try {
          const requested = args[1].toInt32();
          if (Number.isInteger(requested) && requested >= 0 && requested <= 128) {
            lastRequestedFirstBootPhaseIndex = requested;
            milestone('firstboot_go_to_phase_entered', {phase_index: requested});
          }
        } catch (_) {}
      }
    });
    firstBootGoToPhaseHookAttached = true;
    Interceptor.attach(ptr(RVA.firstBootBodyDestroy), {
      onEnter(args) {
        if (firstBootBodyPtr !== null && firstBootBodyPtr.equals(args[0]))
          firstBootBodyPtr = null;
      }
    });
  } catch (_) {
    emit('optional_hook_attach_failed', {observer: 'firstboot_phase'});
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
  // Controlled, OPT-IN local UI selection. This is NOT a read-only
  // operation, so it is inert until the host calls armlocalyear1999().
  // Running on the same Unity main thread as the original Show() avoids
  // invoking Unity setters from Frida's RPC worker thread.
  const originalSetValue = new NativeFunction(
    ptr(RVA.customDropdownSetValue), 'void', ['pointer', 'int']);
  const originalOnSelectItem = new NativeFunction(
    ptr(RVA.customDropdownOnSelectItem), 'void', ['pointer', 'int']);
  // Native UI scroll lifecycle: observe the *actual Open(int value)* input.
  // Being open at 2026 with m_Value 27 is not itself proof of an Open bug:
  // here we distinguish what the original ScrollList receives.
  hook('birthyear_scroll_open', RVA.customDropdownScrollOpen, {
    onEnter(args) {
      try {
        if (birthViewPtr === null) return;
        const year = birthViewPtr.add(0x28).readPointer();
        if (year.isNull()) return;
        const scrollList = year.add(0x128).readPointer();
        if (scrollList.isNull() || !args[0].equals(scrollList)) return;
        const idx = args[1].toInt32();
        if (idx < -1 || idx > 126) return;
        yearScrollOpenInputIndex = idx;
        yearScrollOpenInputEquals1999 = idx === 27;
        milestone('firstboot_year_scroll_open_entered', {
          year_target_index_27_requested: idx === 27
        });
      } catch (_) {
        emit('year_scroll_open_unreadable');
      }
    }
  });
  // OnSelectItem is the original UI item-selection pipeline, unlike
  // CustomTMPDropdown.set_value which only updates selected numeric state.
  hook('birthyear_item_selected', RVA.customDropdownOnSelectItem, {
    onEnter(args) {
      try {
        if (birthViewPtr === null) return;
        const year = birthViewPtr.add(0x28).readPointer();
        const idx = args[1].toInt32();
        if (year.isNull() || !year.equals(args[0]) || idx < 0 || idx > 126)
          return;
        yearItemSelectedIndex = idx;
        yearItemSelectionCount++;
        milestone('firstboot_year_item_selection_entered', {
          year_target_index_27_selected: idx === 27
        });
      } catch (_) {
        emit('year_item_selection_unreadable');
      }
    }
  });
  hook('birthdate_dropdown_show', RVA.customDropdownShow, {
    onEnter(args) {
      this.yearTarget = null;
      this.monthTarget = null;
      this.dayTarget = null;
      this.nativeYearItemSelectTarget = null;
      this.nativeMonthItemSelectTarget = null;
      this.nativeDayItemSelectTarget = null;
      if (birthViewPtr === null) return;
      try {
        const ui = readBirthdateUIState();
        const yearDropdown = birthViewPtr.add(0x28).readPointer();
        const monthDropdown = birthViewPtr.add(0x30).readPointer();
        const dayDropdown = birthViewPtr.add(0x38).readPointer();
        if (optInNativeYearItemSelect && !nativeYearItemSelectAttempted &&
            !yearDropdown.isNull() && args[0].equals(yearDropdown) &&
            ui.exact_birthdate_selected &&
            ui.year_dropdown_value_equals_1999_option &&
            ui.year_dropdown_is_selected === false &&
            ui.year_1999_index === 27) {
          nativeYearItemSelectAttempted = true;
          this.nativeYearItemSelectTarget = yearDropdown;
        } else if (optInNativeMonthItemSelect && !nativeMonthItemSelectAttempted &&
            !monthDropdown.isNull() && args[0].equals(monthDropdown) &&
            ui.year_dropdown_is_selected === true &&
            ui.month_dropdown_is_selected === false &&
            ui.month_dropdown.target_index === 3 &&
            ui.month_dropdown.value_index_equals_target) {
          nativeMonthItemSelectAttempted = true;
          this.nativeMonthItemSelectTarget = monthDropdown;
        } else if (optInNativeDayItemSelect && !nativeDayItemSelectAttempted &&
            !dayDropdown.isNull() && args[0].equals(dayDropdown) &&
            ui.year_dropdown_is_selected === true &&
            ui.month_dropdown_is_selected === true &&
            ui.day_dropdown_is_selected === false &&
            ui.day_dropdown.target_index === 4 &&
            ui.day_dropdown.option_count === 30 &&
            ui.day_dropdown.value_index_equals_target) {
          nativeDayItemSelectAttempted = true;
          this.nativeDayItemSelectTarget = dayDropdown;
        } else if (optInYearSetArmed && !localYearSetAttempted &&
            !yearDropdown.isNull() && args[0].equals(yearDropdown) &&
            ui.year_option_count === 127 && ui.year_1999_index === 27 &&
            ui.first_option_is_2026 && !ui.inputed_year_in_supported_range) {
          localYearSetAttempted = true;
          this.yearTarget = yearDropdown;
        } else if (optInMonthSetArmed && !localMonthSetAttempted &&
            !monthDropdown.isNull() && args[0].equals(monthDropdown) &&
            ui.inputed_year_equals_1999 &&
            ui.year_dropdown_value_equals_1999_option &&
            ui.month_dropdown.target_found_uniquely &&
            ui.month_dropdown.target_index === 3 &&
            ui.month_dropdown.option_count === 12 &&
            !ui.inputed_month_in_range) {
          localMonthSetAttempted = true;
          this.monthTarget = monthDropdown;
        } else if (optInDaySetArmed && !localDaySetAttempted &&
            !dayDropdown.isNull() && args[0].equals(dayDropdown) &&
            ui.inputed_year_equals_1999 &&
            ui.inputed_month_equals_4 &&
            ui.month_dropdown.value_index_equals_target &&
            ui.day_dropdown.target_found_uniquely &&
            ui.day_dropdown.target_index === 4 &&
            ui.day_dropdown.option_count === 30 &&
            !ui.inputed_day_in_range) {
          localDaySetAttempted = true;
          this.dayTarget = dayDropdown;
        }
      } catch (_) {
        localYearSetterFailure = localYearSetterFailure || optInYearSetArmed;
        localMonthSetterFailure = localMonthSetterFailure || optInMonthSetArmed;
        localDaySetterFailure = localDaySetterFailure || optInDaySetArmed;
      }
    },
    onLeave() {
      if (this.nativeYearItemSelectTarget !== null) {
        optInNativeYearItemSelect = false;
        try {
          // The real UI selection method sets isSelected first, then
          // SetValue(index,true), then Hide. It is called on Unity's
          // original Show thread; no separate RPC-worker Unity call.
          originalOnSelectItem(this.nativeYearItemSelectTarget, 27);
          nativeYearItemSelectReturned = true;
          const ui = readBirthdateUIState();
          nativeYearItemSelectConfirmed =
            ui.year_dropdown_is_selected === true &&
            ui.year_dropdown_value_equals_1999_option &&
            ui.inputed_year_equals_1999;
          emit('year_native_item_select_returned', {
            actual_native_ui_method_called: true,
            original_is_selected_verified: nativeYearItemSelectConfirmed,
            birthday_submission_attempted: false
          });
        } catch (_) {
          nativeYearItemSelectFailure = true;
          emit('year_native_item_select_failed', {
            birthday_submission_attempted: false
          });
        }
      }
      for (const item of [
        {target: this.nativeMonthItemSelectTarget, index: 3, label: 'month_4'},
        {target: this.nativeDayItemSelectTarget, index: 4, label: 'day_5'}
      ]) {
        if (item.target === null) continue;
        if (item.label === 'month_4') optInNativeMonthItemSelect = false;
        if (item.label === 'day_5') optInNativeDayItemSelect = false;
        try {
          originalOnSelectItem(item.target, item.index);
          const ui=readBirthdateUIState();
          const matched = item.label === 'month_4'
            ? ui.inputed_month_equals_4 &&
              ui.month_dropdown_is_selected === true &&
              ui.month_dropdown.value_index_equals_target
            : ui.inputed_day_equals_5 &&
              ui.day_dropdown_is_selected === true &&
              ui.day_dropdown.value_index_equals_target;
          if (item.label === 'month_4') {
            nativeMonthItemSelectReturned = true;
            nativeMonthItemSelectConfirmed = matched;
          } else {
            nativeDayItemSelectReturned = true;
            nativeDayItemSelectConfirmed = matched;
          }
          emit(item.label + '_native_item_select_returned', {
            original_onselect_called: true,
            is_selected_verified: matched,
            birthday_submission_attempted: false
          });
        } catch (_) {
          if (item.label === 'month_4') nativeMonthItemSelectFailure = true;
          else nativeDayItemSelectFailure = true;
          emit(item.label + '_native_item_select_failed', {
            birthday_submission_attempted: false
          });
        }
      }
      for (const item of [
        {target: this.yearTarget, index: 27, field: 'inputed_year_equals_1999', label: 'year_1999'},
        {target: this.monthTarget, index: 3, field: 'inputed_month_equals_4', label: 'month_4'},
        {target: this.dayTarget, index: 4, field: 'inputed_day_equals_5', label: 'day_5'}
      ]) {
        if (item.target === null) continue;
        if (item.label === 'year_1999') optInYearSetArmed = false;
        if (item.label === 'month_4') optInMonthSetArmed = false;
        if (item.label === 'day_5') optInDaySetArmed = false;
        try {
          // Native UI callback on the game's Unity thread, not the RPC thread.
          originalSetValue(item.target, item.index);
          const ui = readBirthdateUIState();
          const selected = ui[item.field] === true;
          if (item.label === 'year_1999') localYearSetterReturned = selected;
          if (item.label === 'month_4') localMonthSetterReturned = selected;
          if (item.label === 'day_5') localDaySetterReturned = selected;
          emit(item.label + '_local_setter_returned', {
            original_setter_called: true,
            controller_field_verified: selected,
            birthday_submission_attempted: false
          });
        } catch (_) {
          if (item.label === 'year_1999') localYearSetterFailure = true;
          if (item.label === 'month_4') localMonthSetterFailure = true;
          if (item.label === 'day_5') localDaySetterFailure = true;
          emit(item.label + '_local_setter_failed', {
            birthday_submission_attempted: false
          });
        }
      }
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
