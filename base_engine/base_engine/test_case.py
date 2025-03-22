import unittest
import json

from engine import engine

class TestEngine(unittest.TestCase):
    def setUp(self):
        with open("metadatas.json", "r", encoding="utf-8") as f:
            self.metadatas = json.load(f)
        self.engine = engine

    def start_scan(self, options):
        return self.engine.test_scan(options, self.metadatas)