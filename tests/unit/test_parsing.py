"""
Tests for the tolerant LLM-JSON extractor.

Every agent routes its model output through ``parse_json_response``. When it fails,
the agent silently records its fallback verdict — a critical threat becomes
"unknown/medium" — so the failure is invisible in production. These cases are the
shapes Gemini actually emits.
"""
import pytest

from core.parsing import parse_json_response


class TestCleanPayloads:
    def test_plain_object(self):
        assert parse_json_response('{"severity": "critical"}') == {"severity": "critical"}

    def test_dict_passes_through_untouched(self):
        payload = {"severity": "high"}
        assert parse_json_response(payload) is payload

    def test_bare_array_is_wrapped_as_items(self):
        assert parse_json_response('[1, 2]') == {"items": [1, 2]}

    def test_nested_object_survives(self):
        out = parse_json_response('{"a": {"b": [1, {"c": 2}]}}')
        assert out == {"a": {"b": [1, {"c": 2}]}}


class TestFences:
    @pytest.mark.parametrize("fence", ["```json", "```JSON", "```"])
    def test_fenced_object(self, fence):
        assert parse_json_response(f'{fence}\n{{"severity": "low"}}\n```') == {"severity": "low"}

    def test_fence_with_surrounding_whitespace(self):
        assert parse_json_response('  ```json\n{"a": 1}\n```  \n') == {"a": 1}


class TestProsePreamble:
    """
    The regression this module exists for: an unrelated bracket ahead of the payload.

    Anchoring on the first bracket in the text made "Analysis [step 1]: {...}" parse
    as the *step marker* rather than the assessment, so the agent dropped a
    correctly-classified critical threat.
    """

    def test_square_bracket_in_preamble_does_not_shadow_the_object(self):
        text = 'Analysis [step 1]: {"threat_type": "port_scan", "severity": "critical"}'
        assert parse_json_response(text) == {
            "threat_type": "port_scan", "severity": "critical",
        }

    def test_curly_brace_in_preamble_does_not_shadow_the_object(self):
        text = 'Remember to use {curly} braces. {"a": 1}'
        assert parse_json_response(text) == {"a": 1}

    def test_sentence_before_object(self):
        assert parse_json_response('Here is the result:\n{"a": 1}') == {"a": 1}

    def test_trailing_commentary_after_object(self):
        assert parse_json_response('{"a": 1}\nHope that helps!') == {"a": 1}

    def test_object_preferred_over_an_earlier_valid_array(self):
        text = 'Steps: [1, 2, 3]\nVerdict: {"severity": "high"}'
        assert parse_json_response(text) == {"severity": "high"}

    def test_array_still_returned_when_no_object_follows(self):
        assert parse_json_response('Findings: ["a", "b"] — that is all') == {"items": ["a", "b"]}


class TestBracketsInsideStrings:
    def test_closing_brace_inside_a_string_value(self):
        out = parse_json_response('{"reasoning": "} is not the end", "severity": "low"}')
        assert out == {"reasoning": "} is not the end", "severity": "low"}

    def test_escaped_quote_inside_a_string_value(self):
        out = parse_json_response(r'{"reasoning": "he said \"stop\"", "n": 1}')
        assert out == {"reasoning": 'he said "stop"', "n": 1}

    def test_bracket_only_inside_a_string_is_not_a_candidate(self):
        out = parse_json_response('prefix "[not json]" {"a": 1}')
        assert out == {"a": 1}


class TestFailureModes:
    @pytest.mark.parametrize("text", ["", "   ", "no json at all", "{unterminated", "[1, 2"])
    def test_unparseable_returns_default(self, text):
        assert parse_json_response(text) is None
        assert parse_json_response(text, {"fallback": True}) == {"fallback": True}

    def test_none_returns_default(self):
        assert parse_json_response(None) is None
        assert parse_json_response(None, {"d": 1}) == {"d": 1}

    def test_scalar_json_is_not_accepted_as_a_mapping(self):
        # A model that answers "42" must not become {"items": ...} or a truthy dict.
        assert parse_json_response("42") is None
        assert parse_json_response('"critical"') is None

    def test_non_string_content_is_stringified(self):
        class Weird:
            def __str__(self):
                return '{"a": 1}'

        assert parse_json_response(Weird()) == {"a": 1}


class TestScale:
    def test_long_prose_preamble_does_not_hang(self):
        text = "blah {ignore} " * 2000 + '{"a": 1}'
        assert parse_json_response(text) == {"a": 1}

    def test_unicode_survives_round_trip(self):
        out = parse_json_response('{"summary": "перехват — 攻撃 detected \\u2014 ok"}')
        assert out["summary"].startswith("перехват")
