/* HOME Android 4.1.0 disposable x86_64 AVD connectivity metadata ONLY.
 * Do not read socket payloads, URLs, DNS names, IP addresses, account data,
 * HTTP headers, tokens, request parameters, response JSON, or guest UTID.
 * ARM64 IL2CPP RVAs cannot be trusted on an x86_64 Native Bridge guest.
 * Frida 17 GumJS native hooks need no Java bridge.
 */
'use strict';
const KIND = 'home41_emulator_network_meta';
const STAGES = ['launch', 'language_selected', 'language_confirmed',
                'region_expanded', 'country_selected'];
let stage = 'launch';
const counts = {};
for (const name of STAGES) {
  counts[name] = {connect: 0, resolver: 0, ipv4_connect: 0,
                  ipv6_connect: 0, other_socket_connect: 0};
}
const hookStatus = {connect: 'not_checked', getaddrinfo: 'not_checked'};
let totalCallbacks = 0;
const MAX_CALLBACKS = 10000;
function safeNotify(event, status) {
  send({kind: KIND, event, status,
        process_arch: Process.arch});
}
function bump(key, addr) {
  if (++totalCallbacks > MAX_CALLBACKS) return;
  const counter = counts[stage];
  if (!counter) return;
  counter[key]++;
  if (key === 'connect') {
    let family = 0;
    try { family = addr.readU16(); } catch (_) {}
    if (family === 2) counter.ipv4_connect++;
    else if (family === 10) counter.ipv6_connect++;
    else counter.other_socket_connect++;
  }
}
function installSymbol(name, counter) {
  try {
    const address = Module.findGlobalExportByName(name);
    if (address === null) {
      hookStatus[name] = 'symbol_not_found';
      return;
    }
    Interceptor.attach(address, {onEnter(args) {
      if (counter === 'connect') bump(counter, args[1]);
      else bump(counter, null);
    }});
    hookStatus[name] = 'attached';
  } catch (_) {
    hookStatus[name] = 'hook_failed';
  }
}
rpc.exports = {
  setstage(value) {
    if (!STAGES.includes(value)) return false;
    stage = value;
    return true;
  },
  snapshot() {
    // Only numeric aggregates, no addresses or HTTP content.
    return {
      stage, process_arch: Process.arch,
      connect_hook_status: hookStatus.connect,
      resolver_hook_status: hookStatus.getaddrinfo,
      callbacks_capped: totalCallbacks > MAX_CALLBACKS,
      counts
    };
  }
};
installSymbol('connect', 'connect');
installSymbol('getaddrinfo', 'resolver');
safeNotify('observer_installed', 'native_socket_metadata_only');
