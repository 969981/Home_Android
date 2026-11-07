/* Pokémon HOME Android 4.1.0 - public-safe, read-only UTID runtime observer.
 * Use ONLY on an authorized, original ARM64 4.1.0 installation.
 * Does not bind Nintendo Account, replay API calls, mutate UTID, create or
 * delete users, or print account numbers, cookies, credentials or tokens.
 *
 * Expected exact APK SHA256:
 * 8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1
 * Expected libil2cpp.so SHA256:
 * 80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe
 *
 * IMPORTANT: The six-digit conversion is a hypothesis until compared with
 * the HOME UI. 'match' is NOT proof of a valid/applicable HOME Trainer ID.
 */
'use strict';

const VERSION = '4.1.0';
const EXPECTED_TARGET = '888888';
const RVA = Object.freeze({
  registerCallback: 0x1D33294,
  tokenCallback: 0x1D35AD0,
  loginCallback: 0x1D3C020,
  setBasic: 0x1D763D0,
  commonBasicReturn: 0x1D2BA68
});
const STAGE = {
  register_response_seen: false,
  token_response_seen: false,
  login_response_seen: false
};
const began = Date.now();
let armed = false;
let captured = false;
// Stay in the Frida agent memory only; never send the six digits to the host.
let cachedCandidate = null;
let observedCommonBasicCaller = false;
rpc.exports = {
  comparevisibleid(id) {
    const valid = typeof id === 'string' && /^[0-9]{6}$/.test(id);
    return {
      first_basic_seen: cachedCandidate !== null,
      valid_six_digit_input: valid,
      displayed_id_matches: valid && cachedCandidate !== null && cachedCandidate === id,
      source_common_response_consumer: observedCommonBasicCaller
    };
  },
  observerstatus() {
    return {
      native_arm64: Process.arch === 'arm64',
      hooks_initialized: armed,
      first_basic_seen: cachedCandidate !== null
    };
  }
};
// Deliver structured, redacted events to the locally attached Frida host.
// Do not print the raw UTID, UUID, CID, session cookie or authorization token.
const output = (event, details = {}) => send({
  kind: 'home41_utid_readonly',
  version: VERSION,
  event,
  ms_since_attach: Date.now() - began,
  ...details
});

function getUtidCandidate(basicPtr) {
  if (basicPtr.isNull()) return null;
  // IL2CPP object field +0xF0 is a pointer to managed System.String.
  const stringPtr = basicPtr.add(0xF0).readPointer();
  if (stringPtr.isNull()) return null;
  const length = stringPtr.add(0x10).readS32();
  if (length <= 0 || length > 10) return null;
  const value = stringPtr.add(0x14).readUtf16String(length);
  if (!/^[0-9]{1,10}$/.test(value)) return null;
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric > 0xffffffff) return null;
  return String(numeric % 1000000).padStart(6, '0');
}

function observe(name, address, callback) {
  Interceptor.attach(address, {onEnter: callback});
  output('hook_armed', {observer: name});
}
function activate(lib) {
  if (armed) return;
  armed = true;
  output('guest_arch_preflight', {
    process_arch: Process.arch,
    native_arm64: Process.arch === 'arm64',
    status: Process.arch === 'arm64' ? 'ready' : 'unsupported_process_arch'
  });
  if (Process.arch !== 'arm64') return;
  if (lib.size <= Math.max(...Object.values(RVA))) {
    output('hook_preflight_failed', {reason: 'native_module_rva_out_of_range'});
    return;
  }
  const ptr = rva => lib.base.add(rva);
  observe('registration_callback_entered', ptr(RVA.registerCallback), () => {
    STAGE.register_response_seen = true;
    output('registration_callback_entered');
  });
  observe('token_callback_entered', ptr(RVA.tokenCallback), () => {
    STAGE.token_response_seen = true;
    output('token_callback_entered');
  });
  observe('login_callback_entered', ptr(RVA.loginCallback), () => {
    STAGE.login_response_seen = true;
    output('login_callback_entered');
  });
  const idHook = Interceptor.attach(ptr(RVA.setBasic), {
    onEnter(args) {
      if (captured) return;
      try {
        const candidate = getUtidCandidate(args[0]);
        if (candidate === null) {
          output('basic_received_without_numeric_utid');
          return;
        }
        captured = true;
        cachedCandidate = candidate;
        observedCommonBasicCaller = this.context.lr.equals(ptr(RVA.commonBasicReturn));
        output('first_basic_utid_observed', {
          public_output_is_redacted: true,
          candidate_matches_target: candidate === EXPECTED_TARGET,
          source_common_response_consumer: observedCommonBasicCaller,
          registration_callback_seen: STAGE.register_response_seen,
          token_callback_seen: STAGE.token_response_seen,
          login_callback_seen: STAGE.login_response_seen,
          ui_tid_conversion_status: 'UNVERIFIED',
          normal_client_handoff_status: 'UNVERIFIED'
        });
        idHook.detach(); // Preserve original application's ordinary flow.
      } catch (e) {
        output('read_failed', {reason: 'invalid_or_unavailable_managed_string'});
      }
    }
  });
  output('read_only_observer_ready', {nintendo_binding_attempted: false});
}

// A Frida spawn can attach before Unity has loaded libil2cpp.so.
const watcher = setInterval(() => {
  try {
    const lib = Process.findModuleByName('libil2cpp.so');
    if (lib) {
      clearInterval(watcher);
      activate(lib);
    }
  } catch (e) {
    clearInterval(watcher);
    output('hook_preflight_failed', {reason: 'runtime_unavailable'});
  }
}, 250);
