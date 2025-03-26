import unittest

from engine import engine  # type: ignore


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.engine = engine

    def start_scan(self, options):
        return self.engine.test_scan(options)
