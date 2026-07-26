import os
import json
from openai import OpenAI


class AIPlanner:

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise Exception("OPENAI_API_KEY not found")

        self.client = OpenAI(api_key=api_key)

    def plan(
        self,
        transcript,
        allowed_root_causes,
        tool_catalog,
        maximum_diagnostics
    ):

        prompt = f"""
You are an incident response planner.

You must solve ONE incident.

Choose exactly ONE root cause.

Choose ONLY the minimum number of diagnostic tools required.

Never exceed {maximum_diagnostics} diagnostics.

Return ONLY valid JSON.

Allowed Root Causes:

{json.dumps(allowed_root_causes, indent=2)}

Available Tools:

{json.dumps(tool_catalog, indent=2)}

Transcript:

{transcript}

Output Format:

{{
    "rootCause":"...",
    "evidence":[
        "ev_x",
        "ev_y"
    ],
    "diagnostics":[
        {{
            "tool":"query_metrics",
            "arguments":{{}}
        }}
    ]
}}
"""

        response = self.client.chat.completions.create(

            model="gpt-4.1-mini",

            temperature=0,

            response_format={
                "type": "json_object"
            },

            messages=[
                {
                    "role": "system",
                    "content":
                    "You are a precise incident-response planner. Return JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        result = response.choices[0].message.content

        return json.loads(result)
