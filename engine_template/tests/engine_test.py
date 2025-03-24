import unittest
import unittest.mock

from base_engine.test_case import TestEngine


class TestEngine(TestEngine):
    def test(self):
        options = {"example_option": False}

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["info"], 1)
        self.assertEqual(results[1]["result"]["info"], 2)


if __name__ == "__main__":
    unittest.main()
