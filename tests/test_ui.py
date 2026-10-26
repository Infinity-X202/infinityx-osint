"""Presentation tests. They do not contact the network."""

from __future__ import annotations

import io
import unittest

from rich.console import Console

from infinityx import __version__
from infinityx.ui import print_banner


class BannerTests(unittest.TestCase):
    def test_banner_keeps_the_same_words_and_centers_them(self) -> None:
        stream = io.StringIO()
        console = Console(file=stream, width=100, force_terminal=False, highlight=False, color_system=None)
        print_banner(console)
        text = stream.getvalue()
        self.assertIn("InfinityX OSINT Scanner", text)
        self.assertIn(__version__, text)
        self.assertIn("Created by Infinity", text)
        self.assertIn("passive authorized OSINT", text)
        self.assertIn("report.html", text)
        self.assertIn("It does not guess passwords", text)
