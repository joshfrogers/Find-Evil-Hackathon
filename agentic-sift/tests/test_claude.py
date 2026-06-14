"""Tests for the Claude Messages-API interface (stdlib HTTPS transport)."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.claude import _parse_json_response, call_claude, ClaudeError


class ParseJsonResponseTest(unittest.TestCase):
    """The LLM (Opus) is chatty: it prepends prose and sometimes emits MORE THAN
    ONE top-level JSON object. The parser must recover the FIRST valid object
    rather than spanning first-brace-to-last-brace (which concatenates the
    objects into invalid JSON and drops the whole turn — observed live as
    repeated 'json parse failed', producing 0 commands for that sub-agent turn)."""

    def test_clean_object(self):
        self.assertEqual(_parse_json_response('{"commands": []}'), {"commands": []})

    def test_object_after_prose(self):
        text = 'I will investigate.\n\n{"commands": [{"tool_path": "/bin/ls"}]}'
        self.assertEqual(
            _parse_json_response(text), {"commands": [{"tool_path": "/bin/ls"}]}
        )

    def test_two_top_level_objects_returns_first(self):
        # The exact shape seen in the live run: prose + the same block twice.
        text = (
            "I'll investigate systematically.\n\n"
            '{"commands": [{"tool_path": "/usr/bin/find", "args": ["/mnt"]}]}\n\n'
            '{"commands": [{"tool_path": "/usr/bin/find", "args": ["/mnt"]}]}'
        )
        self.assertEqual(
            _parse_json_response(text),
            {"commands": [{"tool_path": "/usr/bin/find", "args": ["/mnt"]}]},
        )

    def test_braces_inside_string_values_do_not_truncate(self):
        # A '}' inside a quoted value must not end the object early.
        text = 'note\n{"args": ["a}b{c"], "x": "y"}\ntrailing'
        self.assertEqual(_parse_json_response(text), {"args": ["a}b{c"], "x": "y"})

    def test_fenced_block_still_works(self):
        text = 'Here:\n```json\n{"findings": [1, 2]}\n```\nthanks'
        self.assertEqual(_parse_json_response(text), {"findings": [1, 2]})

    def test_array_after_prose(self):
        # The hypotheses path parses a top-level JSON array.
        text = 'Hypotheses:\n[{"id": "H1"}, {"id": "H2"}]\nend'
        self.assertEqual(
            _parse_json_response(text), [{"id": "H1"}, {"id": "H2"}]
        )

    def test_no_json_returns_none(self):
        self.assertIsNone(_parse_json_response("no json here at all"))


class CallClaudeErrorSurfacingTest(unittest.TestCase):
    @patch("agents.claude.time.sleep")
    @patch("agents.claude._request_target")
    @patch("agents.claude.http.client.HTTPSConnection")
    def test_api_error_surfaces_body_text(self, mock_cls, mock_target, _sleep):
        """A non-200 API response must put the real error text (from the JSON
        body) into the ClaudeError, not just a bare status code."""
        mock_target.return_value = ("host", {"content-type": "application/json"}, None)
        resp = MagicMock(status=400)
        resp.read.return_value = (
            b'{"error":{"message":"prompt is too long (210000 tokens > 200000)"}}'
        )
        resp.getheader.return_value = None
        conn = MagicMock()
        conn.getresponse.return_value = resp
        mock_cls.return_value = conn

        with self.assertRaises(ClaudeError) as ctx:
            call_claude("hi", timeout=1)
        self.assertIn("prompt is too long", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
