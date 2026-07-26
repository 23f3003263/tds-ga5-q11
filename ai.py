import os
import json
from openai import OpenAI


class AIPlanner:
    def __init__(self):
        api_key = os.getenv("AIPIPE_API_KEY")

        if not api_key:
            raise Exception("AIPIPE_API_KEY not found")

        self.client = OpenAI(
            api_key=api_key,
            base_url="https://aipipe.org/openai/v1"
        )

    def plan(
        self,
        transcript,
        allowed_root_causes,
        tool_catalog,
        maximum_diagnostics
    ):
        """
        AI decides:
        1. Root Cause
        2. Evidence IDs
        3. Minimum diagnostic tool calls
        """

        prompt = f"""
You are an expert AI Incident Response Planner.

Your task is to analyze the incident transcript and decide:

1. Choose EXACTLY ONE root cause.
2. Root cause MUST be selected ONLY from the provided allowedRootCauses.
3. Choose ONLY the minimum diagnostic tools needed.
4. Never exceed {maximum_diagnostics} diagnostics.
5. Evidence must contain 2 to 4 evidence IDs exactly as they appear.
6. Never invent evidence IDs.
7. Return ONLY valid JSON.
8. Do not include markdown.
9. Do not explain anything.

Allowed Root Causes:

{json.dumps(allowed_root_causes, indent=2)}

Available Tool Catalog:

{json.dumps(tool_catalog, indent=2)}

Incident Transcript:

{transcript}

Return JSON in exactly this format:

{{
    "rootCause":"...",
    "evidence":[
        "ev_1",
        "ev_2"
    ],
    "diagnostics":[
        {{
            "tool":"tool_name",
            "arguments":{{}}
        }}
    ]
}}
"""

        response = self.client.chat.completions.create(
            model="gpt-4.1-mini",
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert incident-response planner. "
                        "Always return valid JSON only."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )

        try:
            content = response.choices[0].message.content
            return json.loads(content)

        except Exception as e:
            raise Exception(f"Failed to parse AI response: {e}")
