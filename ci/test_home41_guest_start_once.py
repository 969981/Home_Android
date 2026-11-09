#!/usr/bin/env python3
"""Fully synthetic guard tests. No ADB, internet, account, or real UI click."""
import io
import unittest
from PIL import Image, ImageDraw

from home41_guest_start_once import verified_original_guest_yes_point


def png(image):
    raw=io.BytesIO()
    image.save(raw,format="PNG")
    return raw.getvalue()


def guest_confirmation():
    w,h=1080,2340
    img=Image.new("RGB",(w,h),(171,240,180))
    pen=ImageDraw.Draw(img)
    pen.rectangle((int(w*.045),int(h*.965),
                   int(w*.45),h),fill=(247,251,247))
    pen.rectangle((int(w*.55),int(h*.965),
                   int(w*.955),h),fill=(255,173,4))
    for x,y,rgb in (
        (.50,.15,(38,179,151)),
        (.50,.17,(38,179,151)),
        (.50,.22,(255,255,244)),
        (.04,.205,(235,94,65)),
        (.96,.25,(235,94,65)),
        (.50,.28,(196,245,166)),
        (.50,.70,(248,250,245)),
        (.50,.745,(248,250,245)),
        (.25,.975,(247,251,247)),
        (.75,.975,(255,173,4)),
        (.75,.985,(255,173,4)),
    ):
        img.putpixel((int(w*x),int(h*y)),rgb)
    # White guest "是" and dark guest "否" one-character clusters.
    pen.rectangle((int(w*.265),int(h*.982),
                   int(w*.281),int(h*.986)),fill=(141,141,141))
    pen.rectangle((int(w*.725),int(h*.982),
                   int(w*.741),int(h*.986)),fill=(255,255,255))
    return img


class ExactGuestYesTests(unittest.TestCase):
    def test_right_yes_center_never_left_no(self):
        self.assertEqual(
            verified_original_guest_yes_point(png(guest_confirmation())),
            (810,2280))

    def test_bad_dimensions_and_invalid_image_fail_closed(self):
        self.assertIsNone(verified_original_guest_yes_point(b"invalid"))
        self.assertIsNone(verified_original_guest_yes_point(
            png(guest_confirmation().resize((720,1560)))))

    def test_swapped_button_colors_and_missing_warning_fail(self):
        for x,y in ((.5,.15),(.5,.17),(.04,.205),(.96,.25),
                    (.25,.975),(.75,.975),(.75,.985)):
            with self.subTest(sample=(x,y)):
                im=guest_confirmation()
                im.putpixel((int(im.width*x),int(im.height*y)),(0,0,0))
                self.assertIsNone(verified_original_guest_yes_point(png(im)))

    def test_missing_no_and_yes_captions_are_rejected(self):
        for left in (True,False):
            with self.subTest(left=left):
                img=guest_confirmation()
                d=ImageDraw.Draw(img)
                w,h=img.size
                rect=((int(w*.22),int(h*.978),
                       int(w*.32),int(h*.989)) if left else
                      (int(w*.70),int(h*.978),
                       int(w*.80),int(h*.989)))
                d.rectangle(rect, fill=(247,251,247) if left else (255,173,4))
                self.assertIsNone(verified_original_guest_yes_point(png(img)))


if __name__ == "__main__":
    unittest.main()
