#!/usr/bin/env python3
"""Pure static tests. No APK, server, ADB, signup or agreement interactions."""
from __future__ import annotations

import io
import unittest
from PIL import Image, ImageDraw

from home41_terms_both_and_next import checkbox_status, substantial_page_transition


def png(frame):
    raw=io.BytesIO()
    frame.save(raw,format="PNG")
    return raw.getvalue()


def frame(terms="unchecked", privacy="unchecked"):
    w,h=1080,2340
    im=Image.new("RGB",(w,h),(173,240,182))
    def center(y,color):
        x=int(w*.135)
        im.putpixel((x,int(h*y)),color)
    center(.450,(101,203,195) if terms=="checked" else (247,251,247))
    center(.504,(101,203,195) if privacy=="checked" else (247,251,247))
    return im


class TermsTwoCheckboxTests(unittest.TestCase):
    def test_checked_white_circle_and_teal_state_are_distinct(self):
        for status in ("checked","unchecked"):
            with self.subTest(status=status):
                self.assertEqual(checkbox_status(png(frame(terms=status)),"terms"),status)
                self.assertEqual(checkbox_status(png(frame(privacy=status)),"privacy"),status)

    def test_invalid_or_wrong_choice_is_unknown(self):
        self.assertEqual(checkbox_status(b"broken","terms"),"unknown")
        self.assertEqual(checkbox_status(png(frame()),"other"),"unknown")
        bad=frame()
        bad.putpixel((int(1080*.135),int(2340*.504)),(1,1,1))
        self.assertEqual(checkbox_status(png(bad),"privacy"),"unknown")

    def test_a_substantial_page_change_is_detectable(self):
        before=frame("checked","checked")
        after=before.copy()
        pen=ImageDraw.Draw(after)
        w,h=after.size
        pen.rectangle((int(w*.22),int(h*.25),int(w*.75),int(h*.75)),
                      fill=(40,180,154))
        self.assertTrue(substantial_page_transition(png(before),png(after)))
        self.assertFalse(substantial_page_transition(png(before),png(before)))

    def test_only_a_single_checkbox_change_is_not_a_new_page(self):
        before=frame("unchecked","unchecked")
        after=frame("checked","unchecked")
        self.assertFalse(substantial_page_transition(png(before),png(after)))


if __name__=="__main__":
    unittest.main()
