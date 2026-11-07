import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from runtime_cache_inventory import detect,run as inventory
from pokemon_cache_scan import species_from_name,run as pokemon_scan
from il2cpp_loader_hints import run as il2cpp_hints

class RuntimeCacheTest(unittest.TestCase):
    def test_magic_and_species(self):
        self.assertEqual(detect(b"UnityFS"+bytes(58)),"unity_bundle")
        self.assertEqual(detect(bytes.fromhex("89504e470d0a1a0a")+bytes(56)),"image_png")
        self.assertEqual(detect(b"private token="+bytes(50)),"unrecognized")
        self.assertEqual(species_from_name("pm0025_f01_idle"),(25,1))
        self.assertEqual(species_from_name("pokemon0150"),(150,None))
        self.assertIsNone(species_from_name("BG_HomeCube_0025"))
        self.assertIsNone(species_from_name("pika"))
    def test_safe_cache_copy_and_no_cache(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            source=d/"cache"; source.mkdir()
            (source/"bundle_pm0025").write_bytes(b"UnityFS"+bytes(70))
            (source/"ui.png").write_bytes(bytes.fromhex("89504e470d0a1a0a")+bytes(50))
            (source/"random.bin").write_bytes(b"plain text token data"+bytes(40))
            (source/"tokens").mkdir()
            (source/"tokens"/"secret.bundle").write_bytes(b"UnityFS"+bytes(50))
            report=d/"report";output=d/"output"
            result=inventory("4.1.0",source,report,output)
            self.assertEqual(result["eligible_files"],2)
            self.assertEqual(result["copied_files"],2)
            self.assertEqual(result["excluded_sensitive_path"],1)
            self.assertEqual(result["unrecognized"],1)
            self.assertTrue((output/"unity_bundle").is_dir())
            empty_report=d/"no_cache"
            self.assertEqual(inventory("4.1.0",None,empty_report)["status"],"runtime_cache_not_supplied")
            self.assertEqual(pokemon_scan("4.1.0",output,empty_report)["status"],"no_cached_unity_assets")
    def test_il2cpp_name_hints(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            script=d/"script.json"
            script.write_text(json.dumps({"ScriptMethod":[
               {"Name":"PokemonModel.LoadAssetAsync","Address":4096},
               {"Name":"A.B","Address":1024}]}),encoding="utf-8")
            result=il2cpp_hints(script,d/"report")
            self.assertEqual(result["hits"],1)
            with (d/"report"/"il2cpp_loader_hints.csv").open() as f:
                rows=list(csv.DictReader(f))
            self.assertEqual(rows[0]["method_address"],"4096")

if __name__=="__main__":
    unittest.main()
