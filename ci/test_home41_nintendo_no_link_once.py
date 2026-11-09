#!/usr/bin/env python3
"""Offline synthetic tests: never interact with HOME or create accounts."""
import io
import unittest
from PIL import Image, ImageDraw

from home41_nintendo_no_link_once import verified_no_link_point


def png(im):
    output=io.BytesIO()
    im.save(output,format="PNG")
    return output.getvalue()


def original_style_choice():
    w,h=1080,2340
    im=Image.new("RGB",(w,h),(166,249,216))
    draw=ImageDraw.Draw(im)
    # Actual immutable color landmarks from original screenshot #42542835109.
    draw.rectangle((0,int(h*.27),w,int(h*.60)),fill=(18,166,168))
    draw.rectangle((int(w*.02),int(h*.64),
                    int(w*.98),int(h*.83)),outline=(235,94,65),width=5)
    draw.rectangle((int(w*.05),int(h*.855),
                    int(w*.95),int(h*.90)),fill=(248,170,4))
    draw.rectangle((int(w*.05),int(h*.927),
                    int(w*.95),int(h*.971)),fill=(240,246,236))
    for x,y,rgb in (
        (.5,.15,(38,179,151)),
        (.5,.18,(200,242,160)),
        (.5,.28,(18,166,168)),
        (.5,.50,(18,166,168)),
        (.04,.70,(235,94,65)),
        (.96,.70,(235,94,65)),
        (.5,.86,(248,170,4)),
        (.5,.88,(248,170,4)),
        (.2,.94,(240,246,236)),
        (.8,.94,(240,246,236)),
        (.2,.955,(240,246,236)),
        (.8,.955,(240,246,236)),
    ):
        im.putpixel((int(w*x),int(h*y)),rgb)
    # Visible gray 「不关联」 caption cluster, ~800 dark pixels.
    draw.rectangle((int(w*.44),int(h*.95),
                    int(w*.495),int(h*.955)),fill=(141,141,141))
    return im


class NoLinkOriginalUiTests(unittest.TestCase):
    def test_only_lower_gray_no_link_button_is_target(self):
        result=verified_no_link_point(png(original_style_choice()))
        self.assertEqual(result,(540,2235))
        self.assertGreater(result[1],int(2340*.92))

    def test_reject_malformed_png_and_wrong_dimensions(self):
        self.assertIsNone(verified_no_link_point(b"invalid"))
        self.assertIsNone(verified_no_link_point(
            png(original_style_choice().resize((720,1560)))))

    def test_reject_unknown_page_or_missing_warning(self):
        for x,y in ((.5,.15),(.5,.28),(.5,.5),(.04,.70),(.96,.70),
                    (.5,.86),(.5,.88),(.2,.94),(.8,.955)):
            with self.subTest(pixel=(x,y)):
                im=original_style_choice()
                im.putpixel((int(im.width*x),int(im.height*y)),(0,0,0))
                self.assertIsNone(verified_no_link_point(png(im)))

    def test_reject_when_lower_button_caption_absent(self):
        im=original_style_choice()
        draw=ImageDraw.Draw(im)
        w,h=im.size
        draw.rectangle((int(w*.38),int(h*.947),
                        int(w*.62),int(h*.958)),fill=(240,246,236))
        self.assertIsNone(verified_no_link_point(png(im)))


if __name__=="__main__":
    unittest.main()
