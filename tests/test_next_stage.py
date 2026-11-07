import importlib.util
import tempfile
import unittest
from pathlib import Path

TOOLS=Path(__file__).resolve().parents[1]/"tools"

def load(name):
    import sys
    sys.path.insert(0,str(TOOLS))
    spec=importlib.util.spec_from_file_location(name,TOOLS/(name+".py"))
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class TestNextStage(unittest.TestCase):
    def test_entropy(self):
        probe=load("aba_probe")
        self.assertEqual(probe.entropy(bytes(1024)),0)
        self.assertEqual(probe.entropy(bytes(range(256))),8)
    def test_reference_fileid(self):
        links=load("unity_references")
        tree={"m_Materials":[{"m_FileID":0,"m_PathID":10},
                             {"m_FileID":1,"m_PathID":11}],
              "empty":{"m_FileID":0,"m_PathID":0}}
        self.assertEqual(list(links.gather(tree)),
                         [("$.m_Materials[0]",0,10),("$.m_Materials[1]",1,11)])
    def test_no_cache(self):
        import csv
        diff=load("cache_diff")
        with tempfile.TemporaryDirectory() as temp:
            r=Path(temp)
            (r/"apk_entries.csv").write_text("path,size\nassets/a,22\n",encoding="utf-8")
            result=diff.run("test",r,None)
            self.assertEqual(result["status"],"no_runtime_cache_input")

if __name__=="__main__":
    unittest.main()
