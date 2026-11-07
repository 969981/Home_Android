import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS=Path(__file__).resolve().parents[1]/"tools"

class TestReassembly(unittest.TestCase):
    def test_numeric_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            input=root/"raw"/"assets"/"bin"/"Data"
            input.mkdir(parents=True)
            # Intentionally write split10 ahead of split2; integer order is required.
            for i in range(12):
                (input / f"sharedassets0.assets.split{i}").write_bytes(bytes([i]))
            cmd=[sys.executable,str(TOOLS/"reassemble_splits.py"),"--version","fixture",
                 "--input",str(root/"raw"),"--out",str(root/"out"),"--report",str(root/"reports")]
            p=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual((root/"out"/"assets/bin/Data/sharedassets0.assets").read_bytes(),bytes(range(12)))
            result=json.loads((root/"reports/reassembly_summary.json").read_text())
            self.assertEqual(result["reassembled"],1)
            self.assertEqual(result["split_files"],12)

if __name__=="__main__":
    unittest.main()
