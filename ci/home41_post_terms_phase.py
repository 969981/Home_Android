#!/usr/bin/env python3
"""Classify read-only original FirstBoot phase evidence after Terms UI.

Only categorical values and bounded enum indices are accepted. No screenshots,
raw UI text, account identifiers, network payloads, or tokens are handled here.
"""
from __future__ import annotations

PHASES = (
    "NONE", "LANGUAGE", "MD_DOWNLOAD", "TERM_OF_SERVICE",
    "ADVERTISEMENT_SDK", "WARNING", "APPLE_ID_LINK",
    "NA_LINK_CONTINUE", "NA_LINK_BEGIN", "NA_LINK_PROCEDURE",
    "NA_LINK_PROCEDURE_WAIT", "NA_LIMK_SUCCESS", "NA_LINK_FAILD",
    "NA_NOT_LINK", "MT_LOGIN", "MT_SELECT_ICON", "MT_INPUT_NAME",
    "MT_INPUT_BIRTH", "MT_SELECT_COUNTRY", "MT_CONFIRMATION",
    "MT_MOVING", "PROLOGUE", "PROLOGUE2",
    "GEST_CONFIRMATION", "ALL_END", "ATT",
)


def _bounded_index(value: object) -> int | None:
    return value if type(value) is int and 0 <= value < len(PHASES) else None


def classify_post_terms_phase(snapshot: object, terms_status: object) -> dict:
    source = snapshot if isinstance(snapshot, dict) else {}
    ui = source.get("firstboot_ui")
    ui = ui if isinstance(ui, dict) else {}
    counts = source.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    terms = terms_status if isinstance(terms_status, dict) else {}

    current = _bounded_index(ui.get("original_phase_enum_index"))
    requested = _bounded_index(ui.get("last_requested_phase_enum_index"))
    sdk_count = counts.get("firstboot_confirmation_advertisement_sdk_entered")
    go_count = counts.get("firstboot_go_to_phase_entered")
    sdk_count = sdk_count if type(sdk_count) is int and 0 <= sdk_count <= 100000 else 0
    go_count = go_count if type(go_count) is int and 0 <= go_count <= 100000 else 0

    native_ready = (
        source.get("native_arm64") is True
        and source.get("hooks_ready") is True
        and ui.get("original_controller_seen") is True
        and ui.get("original_phase_mapping_verified") is True
    )
    terms_advanced = (
        terms.get("terms_next_tapped") is True
        and terms.get("post_terms_page_changed") is True
    )
    phase4_confirmed = bool(
        native_ready and terms_advanced
        and current == 4
        and requested == 4
        and ui.get("go_to_phase_hook_attached") is True
        and ui.get("advertisement_sdk_hook_attached") is True
        and sdk_count > 0 and go_count > 0
    )

    if phase4_confirmed:
        status = "phase_4_advertisement_sdk_confirmed"
    elif native_ready and terms_advanced and current is not None:
        status = "post_terms_phase_observed_needs_more_evidence"
    elif not native_ready:
        status = "native_phase_observer_not_ready"
    elif not terms_advanced:
        status = "terms_navigation_not_verified"
    else:
        status = "post_terms_phase_unreadable"

    return {
        "status": status,
        "native_arm64": source.get("native_arm64") is True,
        "hooks_ready": source.get("hooks_ready") is True,
        "firstboot_controller_seen": ui.get("original_controller_seen") is True,
        "current_phase_index": current,
        "current_phase_name": PHASES[current] if current is not None else None,
        "phase_mapping_verified": ui.get("original_phase_mapping_verified") is True,
        "last_requested_phase_index": requested,
        "last_requested_phase_name": PHASES[requested] if requested is not None else None,
        "go_to_phase_hook_attached": ui.get("go_to_phase_hook_attached") is True,
        "advertisement_sdk_hook_attached": ui.get("advertisement_sdk_hook_attached") is True,
        "advertisement_sdk_method_entries": sdk_count,
        "go_to_phase_entries": go_count,
        "terms_next_tapped": terms.get("terms_next_tapped") is True,
        "post_terms_page_changed": terms.get("post_terms_page_changed") is True,
        "account_registration_attempted": False,
        "nintendo_account_linking_attempted": False,
        "utid_saved": False,
        "http_body_saved": False,
        "raw_screen_saved": False,
    }
