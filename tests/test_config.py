import json
import os
import tempfile
import unittest
from pathlib import Path

from varux.core.config import ConfigManager


class ConfigManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.tempdir.name)
        self.original_env = os.environ.get(ConfigManager.ENV_CONFIG_PATH)

    def tearDown(self) -> None:
        if self.original_env is None:
            os.environ.pop(ConfigManager.ENV_CONFIG_PATH, None)
        else:
            os.environ[ConfigManager.ENV_CONFIG_PATH] = self.original_env
        self.tempdir.cleanup()

    def test_respects_environment_config_path(self) -> None:
        config_file = self.temp_path / "custom.json"
        config_file.write_text(
            json.dumps({"global": {"log_level": "DEBUG"}}), encoding="utf-8"
        )
        os.environ[ConfigManager.ENV_CONFIG_PATH] = str(config_file)

        manager = ConfigManager()

        self.assertEqual(manager.config_path, config_file)
        self.assertEqual(manager.get("global.log_level"), "DEBUG")
        # Missing keys should remain from defaults
        self.assertIsNotNone(manager.get("ai.model"))

    def test_save_and_reload_roundtrip(self) -> None:
        config_file = self.temp_path / "config.json"
        os.environ[ConfigManager.ENV_CONFIG_PATH] = str(config_file)
        manager = ConfigManager()

        manager.set("ai.model", "gpt-elite")
        manager.set("scan.rate_limit.requests_per_second", 42)
        self.assertTrue(manager.save())

        # Reload using a fresh instance to ensure persistence works
        reloaded = ConfigManager()
        self.assertEqual(reloaded.get("ai.model"), "gpt-elite")
        self.assertEqual(
            reloaded.get("scan.rate_limit.requests_per_second"), 42
        )


if __name__ == "__main__":
    unittest.main()
