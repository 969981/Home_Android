#!/usr/bin/env python3
"""Offline synthetic original modal gate tests. Never touches real accounts."""
import io
import unittest
from PIL import Image, ImageDraw

from home41_guest_second_confirm_once import final_guest_start_point


def png(image):
    output=io.BytesIO()
    image.save(output,format="PNG")
    return output.getvalue()


def original_modal_synthetic():
    w,h=1080,2340
    frame=Image.new("RGB",(w,h),(52,70,51))
    pen=ImageDraw.Draw(frame)
    pen.rectangle((int(w*.03),int(h*.265),
                   int(w*.97),int(h*.746)),fill=(247,251,247))
    pen.rectangle((int(w*.55),int(h*.69),
                   int(w*.90),int(h*.735)),fill=(255,173,4))
    # The real right label is white and left label gray; require both.
    pen.rectangle((int(w*.665),int(h*.698),
                   int(w*.795),int(h*.712)),fill=(250,254,255))
    pen.rectangle((int(w*.215),int(h*.698),
                   int(w*.279),int(h*.713)),fill=(167,168,167))
    landmarks=(
        (.50,.15,(11,53,44)),(.50,.17,(11,53,44)),
        (.50,.30,(247,250,246)),(.50,.36,(247,251,247)),
        (.50,.46,(241,164,146)),(.50,.60,(243,251,247)),
        (.50,.63,(243,251,247)),(.50,.675,(247,251,247)),
        (.25,.695,(247,251,247)),(.25,.72,(247,251,247)),
        (.62,.695,(255,173,4)),(.76,.718,(255,173,4)),
        (.76,.725,(255,173,4)),(.85,.72,(255,173,4)),
        (.93,.70,(247,251,247)),(.50,.80,(73,74,72)),
    )
    for x,y,c in landmarks:
        frame.putpixel((int(w*x),int(h*y)),c)
    return frame


class ExactFinalGuestConfirmationTests(unittest.TestCase):
    def test_only_orange_right_start_is_selected(self):
        self.assertEqual(
            final_guest_start_point(png(original_modal_synthetic())),
            (int(1080*.76),int(2340*.72)))

    def test_invalid_images_and_dimensions_fail_closed(self):
        self.assertIsNone(final_guest_start_point(b"invalid"))
        self.assertIsNone(final_guest_start_point(
            png(original_modal_synthetic().resize((720,1560)))))

    def test_change_required_independent_landmark_refuses_action(self):
        for x,y in ((.50,.15),(.50,.30),(.50,.46),(.25,.695),
                    (.62,.695),(.76,.718),(.76,.725),(.50,.80)):
            with self.subTest(sample=(x,y)):
                frame=original_modal_synthetic()
                frame.putpixel((int(1080*x),int(2340*y)),(0,0,0))
                self.assertIsNone(final_guest_start_point(png(frame)))

    def test_missing_left_or_right_caption_refused(self):
        for left in (True,False):
            with self.subTest(left=left):
                frame=original_modal_synthetic()
                d=ImageDraw.Draw(frame)
                w,h=frame.size
                rect=((int(w*.215),int(h*.698),
                       int(w*.279),int(h*.713)) if left else
                      (int(w*.665),int(h*.698),
                       int(w*.795),int(h*.712)))
                d.rectangle(rect,fill=(247,251,247) if left
                            else (255,173,4))
                self.assertIsNone(final_guest_start_point(png(frame)))


if __name__=="__main__":
    unittest.main()
