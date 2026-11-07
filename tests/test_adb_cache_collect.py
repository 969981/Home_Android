import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from adb_cache_collect import REMOTE_ROOT, safe_remote_path

class AdbCacheTest(unittest.TestCase):
    def test_recognize_accessible_candidates(self):
        self.assertEqual(safe_remote_path(REMOTE_ROOT+"/a/123/__data"),Path("a/123/__data"))
        self.assertEqual(safe_remote_path(REMOTE_ROOT+"/models/pm0025.bundle"),Path("models/pm0025.bundle"))
        self.assertIsNone(safe_remote_path(REMOTE_ROOT+"/token/session.bundle"))
        self.assertIsNone(safe_remote_path(REMOTE_ROOT+"/../outside.bundle"))
        self.assertIsNone(safe_remote_path("/data/user/0/jp.pokemon.pokemonhome/cache/foo.bundle"))
        self.assertIsNone(safe_remote_path(REMOTE_ROOT+"/user_settings.json"))

if __name__=="__main__":
    unittest.main()
