#!/usr/bin/env python3
"""Pure local tests for original Phase4 RIGHT「同意」; no ADB/account."""
import io
import unittest
from PIL import Image, ImageDraw

from home41_phase4_agree_once import verified_phase4_agree_point


def png(im):
    out=io.BytesIO()
    im.save(out,format="PNG")
    return out.getvalue()


def verified_original_phase4_sample():
    w,h=1080,2340
    im=Image.new("RGB",(w,h),(181,240,185))
    samples=(
        (.50,.14,(38,179,151)),
        (.50,.16,(38,179,151)),
        (.50,.20,(207,247,166)),
        (.50,.68,(158,239,203)),
        (.25,.925,(247,251,247)),
        (.75,.925,(247,251,247)),
        (.25,.955,(247,251,247)),
        (.75,.955,(247,251,247)),
        (.50,.930,(163,245,220)),
    )
    for x,y,c in samples:
        im.putpixel((int(w*x),int(h*y)),c)
    p=ImageDraw.Draw(im)
    p.rectangle((int(w*.223),int(h*.935),
                 int(w*.293),int(h*.943)),fill=(150,150,150))
    p.rectangle((int(w*.702),int(h*.935),
                 int(w*.776),int(h*.942)),fill=(150,150,150))
    return im


class Phase4AgreeTests(unittest.TestCase):
    def test_original_page_click_is_only_right_agree(self):
        self.assertEqual(verified_phase4_agree_point(
            png(verified_original_phase4_sample())),(810,2199))

    def test_original_page_left_button_not_target(self):
        x,y=verified_phase4_agree_point(png(verified_original_phase4_sample()))
        self.assertGreater(x,540)
        self.assertGreater(y,2000)

    def test_modal_or_wrong_screen_refuses_all_actions(self):
        for x,y in ((.50,.14),(.25,.925),(.75,.925),(.50,.930)):
            with self.subTest(sample=(x,y)):
                im=verified_original_phase4_sample()
                im.putpixel((int(im.width*x),int(im.height*y)),(0,0,0))
                self.assertIsNone(verified_phase4_agree_point(png(im)))
        self.assertIsNone(verified_phase4_agree_point(b"not png"))
        self.assertIsNone(verified_phase4_agree_point(
            png(verified_original_phase4_sample().resize((720,1560)))))

    def test_missing_button_caption_is_not_original_page(self):
        im=verified_original_phase4_sample()
        p=ImageDraw.Draw(im)
        p.rectangle((int(im.width*.67),int(im.height*.93),
                     int(im.width*.83),int(im.height*.956)),
                    fill=(247,251,247))
        self.assertIsNone(verified_phase4_agree_point(png(im)))


if __name__=="__main__":
    unittest.main()
