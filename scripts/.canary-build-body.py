#!/usr/bin/env python3
"""Build the ST-shaped /v1/messages body for the PHA-2134 cache canary."""
import json
import sys

def build(turn: int, user_text: str, sys_text: str, model: str) -> dict:
    history = []
    for i in range(1, turn):
        history.append({"role": "user", "content": f"prior user turn {i}"})
        history.append({"role": "assistant", "content": f"prior assistant reply {i}"})
    history.append({"role": "user", "content": user_text})
    return {
        "model": model,
        "max_tokens": 8,
        "system": [
            {"type": "text", "text": sys_text, "cache_control": {"type": "ephemeral"}}
        ],
        "messages": history,
    }


if __name__ == "__main__":
    turn = int(sys.argv[1])
    user_text = sys.argv[2]
    sys_text = sys.argv[3]
    model = sys.argv[4]
    print(json.dumps(build(turn, user_text, sys_text, model)))
