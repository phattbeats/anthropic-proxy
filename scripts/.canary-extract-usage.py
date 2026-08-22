#!/usr/bin/env python3
"""Extract cache_creation_input_tokens / cache_read_input_tokens from a response."""
import json
import sys


def usage_from_file(path: str) -> dict:
    with open(path) as f:
        d = json.load(f)
    u = d.get("usage", {}) or {}
    return {
        "input_tokens": u.get("input_tokens", 0),
        "cache_creation_input_tokens": u.get("cache_creation_input_tokens", 0),
        "cache_read_input_tokens": u.get("cache_read_input_tokens", 0),
        "output_tokens": u.get("output_tokens", 0),
    }


if __name__ == "__main__":
    print(json.dumps(usage_from_file(sys.argv[1])))
