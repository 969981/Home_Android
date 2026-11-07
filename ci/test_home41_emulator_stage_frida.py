#!/usr/bin/env python3
"""Synthetic, privacy-safe tests for HOME x86 emulator Frida stage counts."""
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

CI=Path(__file__).parent
sys.path.insert(0,str(CI))
from PIL import Image

spec=importlib.util.spec_from_file_location(
    "home41_emulator_stage_frida",CI/"home41_emulator_stage_frida.py")
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class NetworkMetadataTests(unittest.TestCase):
    def test_only_known_fields_and_numeric_counts_leave_frida(self):
        src={
            "stage":"region_expanded","process_arch":"x64",
            "connect_hook_status":"attached","resolver_hook_status":"attached",
            "callbacks_capped":False,
            "cookie":"auth=secret","raw_http":"super-secret",
            "counts":{
                "launch":{"connect":2,"resolver":3,"server_token":"secret"},
                "region_expanded":{"connect":5,"resolver":0,
                                   "ipv4_connect":2, "ipv6_connect":1,
                                   "raw_url":"https://private.example"},
                "bad_stage":{"connect":999999},
            }
        }
        clean=stage.report_only_safe_counts(src)
        self.assertEqual(clean["counts"]["launch"]["connect"],2)
        self.assertEqual(clean["counts"]["region_expanded"]["connect"],5)
        self.assertNotIn("cookie",str(clean))
        self.assertNotIn("secret",str(clean))
        self.assertNotIn("private.example",str(clean))
        self.assertNotIn("bad_stage",str(clean))
        self.assertFalse(clean["payload_or_response_body_captured"])
        self.assertFalse(clean["utid_captured"])

    def test_reject_arbitrary_counts(self):
        clean=stage.report_only_safe_counts({"counts":{
            "launch":{"connect":-1,"resolver":"token","ipv4_connect":True,
                      "ipv6_connect":25000}}})
        self.assertIsNone(clean["counts"]["launch"]["connect"])
        self.assertIsNone(clean["counts"]["launch"]["resolver"])
        self.assertIsNone(clean["counts"]["launch"]["ipv4_connect"])
        self.assertIsNone(clean["counts"]["launch"]["ipv6_connect"])

    def test_unknown_or_insecure_stage_rejected(self):
        m=stage.StageMonitor(Path("unavailable"),Path("unavailable"))
        self.assertFalse(m.mark("birth_date"))
        self.assertFalse(m.mark("accept_terms"))
        self.assertFalse(m.mark("send_auth"))
        self.assertFalse(m.mark("country_selected"))

    def test_real_screenshot_signature_has_safe_target_position(self):
        # Render synthetic known-color test pixels, NEVER a captured screen.
        image=Image.new("RGB",(1080,2340),(10,10,10))
        expected=[
            ((.5,.02),(202,244,161)),
            ((.5,.14),(38,179,151)),
            ((.5,.24),(248,250,245)),
            ((.2,.54),(18,166,168)),
            ((.2,.57),(18,166,168)),
        ]
        for (x,y),color in expected:
            image.putpixel((int(1080*x),int(2340*y)),color)
        buf=io.BytesIO()
        image.save(buf,format="PNG")
        loc=stage.diag.match_known_ui(buf.getvalue(),"china_mainland")
        self.assertEqual(loc,(540,int(2340*.54)))
        self.assertIsNone(stage.diag.match_known_ui(buf.getvalue(),"terms"))

    def test_country_confirmation_requires_real_modal_signature(self):
        img=Image.new("RGB",(1080,2340),(17,17,17))
        pts=[
            ((.5,.02),(126,151,101)),
            ((.5,.14),(23,107,91)),
            ((.5,.36),(247,251,247)),
            ((.5,.53),(247,251,247)),
            ((.71,.635),(255,175,12)),
            ((.2,.635),(247,251,247)),
        ]
        for (x,y),color in pts:
            img.putpixel((int(1080*x),int(2340*y)),color)
        buf=io.BytesIO()
        img.save(buf,format="PNG")
        self.assertEqual(
            stage.diag.match_known_ui(buf.getvalue(),"country_confirmation"),
            (int(1080*.71),int(2340*.635)))
        img.putpixel((int(1080*.71),int(2340*.635)),(10,10,10))
        buf=io.BytesIO()
        img.save(buf,format="PNG")
        self.assertIsNone(
            stage.diag.match_known_ui(buf.getvalue(),"country_confirmation"))

    def test_unknown_ui_never_selects_country(self):
        self.assertIsNone(stage.diag.match_known_ui(b"","china_mainland"))
        self.assertIsNone(stage.diag.match_known_ui(b"not-an-image","china_mainland"))

    def test_native_arm64_offsets_are_never_used_for_x86_metadata(self):
        js=(CI/"home41_emulator_network_meta.js").read_text(encoding="utf-8")
        self.assertNotIn("0x1D763D0",js)
        self.assertNotIn("ApiRequestAuthRegisterUser",js)
        self.assertNotIn("readUtf8String",js)
        self.assertNotIn("readUtf16String",js)
        self.assertNotIn("SSL_read",js)
        self.assertNotIn("SSL_write",js)
        self.assertNotIn("Java.perform",js)


if __name__=="__main__":
    unittest.main()
