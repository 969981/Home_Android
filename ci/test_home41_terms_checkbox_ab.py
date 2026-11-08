#!/usr/bin/env python3
"""Pure local tests: no ADB, UI input, consent or real accounts."""
import io
import unittest
from PIL import Image, ImageDraw

from home41_terms_checkbox_ab import terms_ui_signature, roi_change_counts


def png(image):
    stream=io.BytesIO()
    image.save(stream,format="PNG")
    return stream.getvalue()


def sample_terms_screen():
    w,h=1080,2340
    im=Image.new("RGB",(w,h),(175,240,182))
    markers=[
        ((.5,.14),(38,179,151)),
        ((.5,.2),(207,247,166)),
        ((.8,.30),(240,246,237)),
        ((.8,.38),(240,246,237)),
        ((.65,.64),(255,173,4)),
        ((.135,.46),(247,251,247)),
        ((.135,.514),(247,251,247)),
    ]
    for (x,y),color in markers:
        im.putpixel((int(w*x),int(h*y)),color)
    return im


class TermsCheckboxABTests(unittest.TestCase):
    def test_verified_original_terms_signature_has_first_checkbox_point(self):
        img=sample_terms_screen()
        self.assertEqual(terms_ui_signature(png(img),True),(145,1076))

    def test_unknown_screen_and_wrong_checkbox_refused(self):
        img=sample_terms_screen()
        img.putpixel((int(1080*.65),int(2340*.64)),(0,0,0))
        self.assertIsNone(terms_ui_signature(png(img),True))
        img=sample_terms_screen()
        img.putpixel((int(1080*.135),int(2340*.514)),(0,0,0))
        self.assertIsNone(terms_ui_signature(png(img),True))
        self.assertIsNone(terms_ui_signature(b"bad png",True))

    def test_visual_ab_accepts_only_first_checkbox_changed(self):
        before=sample_terms_screen()
        after=before.copy()
        d=ImageDraw.Draw(after)
        w,h=after.size
        d.rectangle((int(w*.115),int(h*.448),int(w*.157),int(h*.475)),
                    fill=(20,110,100))
        changed=roi_change_counts(png(before),png(after))
        self.assertIsNotNone(changed)
        self.assertGreater(changed[0],90)
        self.assertEqual(changed[1],0)

    def test_visual_ab_is_not_rigged_for_other_checkbox(self):
        before=sample_terms_screen()
        after=before.copy()
        d=ImageDraw.Draw(after)
        w,h=after.size
        d.rectangle((int(w*.115),int(h*.500),int(w*.157),int(h*.530)),
                    fill=(20,110,100))
        changed=roi_change_counts(png(before),png(after))
        self.assertEqual(changed[0],0)
        self.assertGreater(changed[1],90)
        self.assertIsNone(roi_change_counts(b"not png",png(after)))


if __name__=="__main__":
    unittest.main()
