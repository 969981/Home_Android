#!/usr/bin/env python3
"""Only synthetic screen tests. No ADB, no HOME, no real agreement click."""
import io
import unittest
from PIL import Image, ImageDraw
from home41_phase4_decline_once import phase4_decline_point


def synthetic_phase4():
    w,h=1080,2340
    img=Image.new("RGB",(w,h),(181,240,185))
    for x,y,c in (
        (.50,.14,(38,179,151)),
        (.50,.16,(38,179,151)),
        (.50,.20,(207,247,166)),
        (.50,.68,(158,239,203)),
        (.25,.925,(247,251,247)),
        (.75,.925,(247,251,247)),
        (.25,.955,(247,251,247)),
        (.75,.955,(247,251,247)),
        (.50,.930,(163,245,220)),
    ):
        img.putpixel((int(w*x),int(h*y)),c)
    pen=ImageDraw.Draw(img)
    # Approximate the left 3-character and right 2-character grey glyph
    # coverage within the exact original button caption bounding rectangles.
    pen.rectangle((int(w*.215),int(h*.934),
                   int(w*.315),int(h*.946)),fill=(150,150,150))
    pen.rectangle((int(w*.690),int(h*.934),
                   int(w*.790),int(h*.944)),fill=(150,150,150))
    return img


def png(im):
    buf=io.BytesIO()
    im.save(buf,format="PNG")
    return buf.getvalue()


class Phase4DeclineVisualTests(unittest.TestCase):
    def test_exact_phase4_opt_out_button_is_left_not_right(self):
        image=synthetic_phase4()
        self.assertEqual(phase4_decline_point(png(image)),
                         (int(1080*.25),int(2340*.94)))

    def test_fails_on_wrong_dimension_or_invalid_image(self):
        self.assertIsNone(phase4_decline_point(b"not-a-real-png"))
        image=synthetic_phase4().resize((720,1560))
        self.assertIsNone(phase4_decline_point(png(image)))

    def test_fails_when_header_or_buttons_change(self):
        for at in ((.50,.14),(.25,.925),(.75,.925),(.50,.930)):
            with self.subTest(sample=at):
                image=synthetic_phase4()
                image.putpixel((int(image.width*at[0]),int(image.height*at[1])),
                               (0,0,0))
                self.assertIsNone(phase4_decline_point(png(image)))

    def test_fails_when_organic_button_captions_missing(self):
        image=synthetic_phase4()
        pen=ImageDraw.Draw(image)
        w,h=image.size
        pen.rectangle((int(w*.2),int(h*.93),int(w*.34),int(h*.956)),
                      fill=(255,255,255))
        self.assertIsNone(phase4_decline_point(png(image)))


if __name__=="__main__":
    unittest.main()
