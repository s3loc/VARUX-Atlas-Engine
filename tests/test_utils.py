import tempfile
import unittest
from pathlib import Path

from varux.core import utils


class UtilsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_load_json_handles_invalid_content_gracefully(self) -> None:
        bad_json = self.temp_path / "broken.json"
        bad_json.write_text("{invalid json", encoding="utf-8")

        result = utils.load_json(bad_json)

        self.assertEqual(result, {})

    def test_load_yaml_handles_invalid_content_gracefully(self) -> None:
        bad_yaml = self.temp_path / "broken.yaml"
        bad_yaml.write_text("foo: : bar", encoding="utf-8")

        result = utils.load_yaml(bad_yaml)

        self.assertEqual(result, {})

    def test_save_and_load_roundtrip_json(self) -> None:
        payload = {"key": "value", "items": [1, 2, 3]}
        target = self.temp_path / "data" / "sample.json"

        utils.save_json(target, payload)
        loaded = utils.load_json(target)

        self.assertEqual(payload, loaded)


if __name__ == "__main__":
    unittest.main()
