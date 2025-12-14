import hashlib
import importlib.util
import tempfile
from pathlib import Path
import unittest


# ``varux.py`` isimli kök dosya, dizindeki ``varux`` klasörünün paket olarak
# otomatik keşfedilmesini engellediği için modülü güvenli bir şekilde manuel
# yüklüyoruz. Böylece testler gerçek dosya yolunu kullanarak yardımcıların
# çalıştığını doğrulayabiliyor.
REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_PATH = REPO_ROOT / "varux" / "core" / "utils.py"

spec = importlib.util.spec_from_file_location("varux.core.utils", UTILS_PATH)
assert spec and spec.loader, "utils modülü için spec oluşturulamadı"
utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utils)


class HashFileTests(unittest.TestCase):
    def test_hash_file_returns_expected_digest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "sample.txt"
            file_path.write_text("varux-elite", encoding="utf-8")

            expected = hashlib.sha256(b"varux-elite").hexdigest()
            self.assertEqual(utils.hash_file(file_path), expected)

    def test_hash_file_raises_for_missing_file(self):
        missing = Path("/tmp/non-existent-varux-file")
        with self.assertRaises(FileNotFoundError):
            utils.hash_file(missing)

    def test_hash_file_raises_for_unknown_algorithm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "sample.txt"
            file_path.write_text("content", encoding="utf-8")

            with self.assertRaises(ValueError):
                utils.hash_file(file_path, algorithm="unknown-hash")


if __name__ == "__main__":
    unittest.main()
