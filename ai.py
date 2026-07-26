import os
import json

# Agar OpenAI use karna ho
from openai import OpenAI


class AIPlanner:
    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )

    def plan(self, transcript, allowed_root_causes):
        """
        Returns:
        {
            "rootCause": "...",
            "evidence": ["ev_1","ev_5"]
        }
        """

        prompt = f"""
You are an incident response planner.

Choose ONLY ONE root cause from this list:

{json.dumps(allowed_root_causes)}

Return ONLY JSON.

Format:

{{
    "rootCause":"...",
    "evidence":["ev_1","ev_2"]
}}

Rules:

1. Choose exactly one allowed root cause.
2. Evidence must contain 2-4 evidence IDs.
3. Do not explain anything.
4. Output JSON only.

Transcript:

{transcript}
"""

        response = self.client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0
        )

        content = response.choices[0].message.content

        return json.loads(content)
