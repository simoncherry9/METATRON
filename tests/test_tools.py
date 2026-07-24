import unittest
from unittest.mock import patch

import tools


class ToolInventoryTests(unittest.TestCase):
    @patch("tools.shutil.which", return_value=None)
    def test_native_fallbacks_are_reported_as_operational(self, _which):
        inventory = tools.get_tool_inventory()
        by_id = {item["id"]: item for item in inventory["tools"]}

        self.assertEqual(by_id["nmap"]["mode"], "fallback")
        self.assertTrue(by_id["nmap"]["operational"])
        self.assertEqual(by_id["whatweb"]["mode"], "fallback")
        self.assertEqual(by_id["msfconsole"]["mode"], "unavailable")
        self.assertGreater(inventory["operational"], 0)


if __name__ == "__main__":
    unittest.main()
