import importlib.util, tempfile, unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('privacy_check',Path(__file__).parents[1]/'scripts/privacy_check.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class PrivacyCheckTests(unittest.TestCase):
    def test_rejects_manuscript(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'draft.docx'; p.write_bytes(b'x')
            self.assertTrue(m.scan([p]))
    def test_accepts_safe_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'README.md'; p.write_text('safe research summary')
            self.assertFalse(m.scan([p]))

if __name__=='__main__': unittest.main()

