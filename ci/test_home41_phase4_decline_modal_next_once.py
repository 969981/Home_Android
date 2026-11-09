#!/usr/bin/env python3
"""Synthetic UI contract tests. Never click HOME or change any accounts."""
import io
import unittest
from PIL import Image,ImageDraw
from home41_phase4_decline_modal_next_once import official_decline_modal_next_point


def sample():
    w,h=1080,2340
    im=Image.new("RGB",(w,h),(95,145,124))
    pen=ImageDraw.Draw(im)
    pen.rectangle((int(w*.05),int(h*.34),int(w*.95),int(h*.65)),
                  fill=(247,251,247))
    pen.rectangle((int(w*.58),int(h*.585),int(w*.85),int(h*.625)),
                  fill=(255,173,4))
    pixels=(
        (.5,.14,(23,107,91)),
        (.5,.38,(247,251,247)),
        (.5,.50,(243,251,247)),
        (.5,.70,(95,145,124)),
        (.22,.60,(247,251,247)),
        (.28,.59,(247,251,247)),
        (.70,.59,(255,173,4)),
        (.70,.60,(255,173,4)),
        (.70,.61,(255,173,4)),
        (.70,.62,(255,173,4)),
    )
    for x,y,c in pixels:
        im.putpixel((int(w*x),int(h*y)),c)
    return im


def png(im):
    out=io.BytesIO()
    im.save(out,format="PNG")
    return out.getvalue()


class OriginalOptOutModalTests(unittest.TestCase):
    def test_exact_modal_right_orange_next_is_only_action_point(self):
        self.assertEqual(
            official_decline_modal_next_point(png(sample())),
            (int(1080*.70),int(2340*.605)))

    def test_invalid_image_and_other_resolution_refused(self):
        self.assertIsNone(official_decline_modal_next_point(b"bad"))
        self.assertIsNone(official_decline_modal_next_point(
            png(sample().resize((720,1560)))))

    def test_missing_popup_or_orange_next_is_refused(self):
        for x,y in ((.5,.14),(.5,.38),(.22,.60),(.70,.61),(.5,.70)):
            with self.subTest(x=x,y=y):
                im=sample()
                im.putpixel((int(im.width*x),int(im.height*y)),(0,0,0))
                self.assertIsNone(official_decline_modal_next_point(png(im)))

    def test_single_orange_pixel_is_not_a_valid_confirm_button(self):
        im=sample()
        pen=ImageDraw.Draw(im)
        w,h=im.size
        pen.rectangle((int(w*.58),int(h*.585),int(w*.85),int(h*.625)),
                      fill=(247,251,247))
        for y in (.59,.60,.61,.62):
            im.putpixel((int(w*.70),int(h*y)),(255,173,4))
        self.assertIsNone(official_decline_modal_next_point(png(im)))


if __name__=="__main__":
    unittest.main()
