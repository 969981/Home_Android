#!/usr/bin/env python3
"""Offline guards for the disposable HOME Android emulator probe."""
import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("home41_emulator_diagnostics.py")
spec = importlib.util.spec_from_file_location("home41_ci_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_unknown_png_never_clicks(self):
        self.assertIsNone(probe.match_known_ui(b"", "language"))
        self.assertIsNone(probe.match_known_ui(b"not a png", "region_dropdown"))
        self.assertIsNone(probe.match_known_ui(probe.PNG_MAGIC, "language_confirmation"))

    def test_known_ui_signature_but_unknown_stage_never_clicks(self):
        from PIL import Image
        img = Image.new("RGB", (1080, 2340), (240, 246, 236))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.assertIsNone(probe.match_known_ui(buf.getvalue(), "terms"))
        self.assertIsNone(probe.match_known_ui(buf.getvalue(), "registration"))
        self.assertIsNone(probe.match_known_ui(buf.getvalue(), "delete"))

    def test_real_china_region_color_variation_keeps_other_pixel_guards(self):
        from PIL import Image
        points = [
            ((.5,.02),(215,255,174)),  # observed real AVD #42394891266
            ((.5,.14),(38,179,151)),
            ((.5,.24),(248,250,245)),
            ((.2,.54),(18,166,168)),
            ((.2,.57),(18,166,168)),
        ]
        image=Image.new("RGB",(1080,2340),(10,10,10))
        for (x,y),rgb in points:
            image.putpixel((int(1080*x),int(2340*y)),rgb)
        buf=io.BytesIO();image.save(buf,format="PNG")
        self.assertEqual(
            probe.match_known_ui(buf.getvalue(),"china_mainland"),
            (540,int(2340*.54)))
        image.putpixel((int(1080*.2),int(2340*.57)),(10,10,10))
        buf=io.BytesIO();image.save(buf,format="PNG")
        self.assertIsNone(probe.match_known_ui(buf.getvalue(),"china_mainland"))

    def test_selected_1999_birthpage_uses_distinct_month_day_ui_guard(self):
        from PIL import Image
        img=Image.new("RGB",(1080,2340),(20,20,20))
        for norm,color in [
            ((.5,.14),(38,179,151)),
            ((.5,.24),(198,242,161)),
            ((.2,.29),(142,142,142)),
            ((.8,.29),(248,250,245)),
            ((.4,.34),(240,30,30)),
            ((.7,.95),(255,173,4)),
        ]:
            img.putpixel((int(norm[0]*1080),int(norm[1]*2340)),color)
        out=io.BytesIO();img.save(out,format="PNG")
        self.assertEqual(probe.match_known_ui(
            out.getvalue(),"birthday_month_native"),
            (int(1080*.59),int(2340*.287)))
        self.assertEqual(probe.match_known_ui(
            out.getvalue(),"birthday_day_native"),
            (int(1080*.88),int(2340*.287)))
        self.assertIsNone(probe.match_known_ui(
            out.getvalue(),"birthday_month_dropdown"))
        img.putpixel((216,int(.29*2340)),(248,250,245))
        out=io.BytesIO();img.save(out,format="PNG")
        self.assertIsNone(probe.match_known_ui(
            out.getvalue(),"birthday_month_native"))

    def test_date_caption_roi_change_only_detects_target_field(self):
        from PIL import Image, ImageDraw
        base=Image.new("RGB",(1080,2340),(245,246,242))
        changed=base.copy()
        d=ImageDraw.Draw(changed)
        d.rectangle((185,655,235,710),fill=(20,20,20))
        def png(image):
            buffer=io.BytesIO()
            image.save(buffer,format="PNG")
            return buffer.getvalue()
        before,after=png(base),png(changed)
        self.assertTrue(probe.caption_visual_changed(before,after,"year"))
        self.assertFalse(probe.caption_visual_changed(before,after,"month"))
        self.assertFalse(probe.caption_visual_changed(before,after,"day"))
        self.assertFalse(probe.caption_visual_changed(before,before,"year"))
        self.assertFalse(probe.caption_visual_changed(before,after,"terms"))
        self.assertFalse(probe.caption_visual_changed(b"no png",after,"year"))

    def test_native_sha_check_fails_closed_on_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture.apk"
            with zipfile.ZipFile(target, "w") as z:
                z.writestr("lib/arm64-v8a/libil2cpp.so", b"fixture")
            result = probe.inspect_native(target)
            self.assertTrue(result["arm64_libil2cpp_present"])
            self.assertFalse(result["arm64_libil2cpp_hash_matched"])

    def test_native_absence_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture.apk"
            with zipfile.ZipFile(target, "w") as z:
                z.writestr("classes.dex", b"fixture")
            result = probe.inspect_native(target)
            self.assertFalse(result["arm64_libil2cpp_present"])
            self.assertFalse(result["arm64_libil2cpp_hash_matched"])


if __name__ == "__main__":
    unittest.main()
