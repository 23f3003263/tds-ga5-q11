import json
import os
from typing import Dict, Any

from utils import content_hash


STATE_FILE = "runs.json"


class StateManager:

    def __init__(self):
        if not os.path.exists(STATE_FILE):
            with open(STATE_FILE, "w") as f:
                json.dump({}, f)

    def load(self):

        with open(STATE_FILE, "r") as f:
            try:
                return json.load(f)
            except:
                return {}

    def save(self, data):

        with open(STATE_FILE, "w") as f:
            json.dump(
                data,
                f,
                indent=2
            )

    def exists(self, run_id):

        data = self.load()

        return run_id in data

    def get(self, run_id):

        data = self.load()

        return data.get(run_id)

    def create_run(
        self,
        run_id,
        request,
        response
    ):

        data = self.load()

        data[run_id] = {

            "request_hash": content_hash(request),

            "request": request,

            "response": response,

            "status": response["status"],

            "actionLog": [],

            "receiptLog": [],

            "dispatches": [],

            "approvals": []

        }

        self.save(data)

    def update_response(
        self,
        run_id,
        response
    ):

        data = self.load()

        data[run_id]["response"] = response

        data[run_id]["status"] = response["status"]

        self.save(data)

    def verify_replay(
        self,
        run_id,
        request
    ):

        data = self.load()

        if run_id not in data:
            return None

        if data[run_id]["request_hash"] != content_hash(request):
            return "conflict"

        return data[run_id]["response"]

    def add_dispatch(
        self,
        run_id,
        dispatch
    ):

        data = self.load()

        data[run_id]["dispatches"].append(dispatch)

        data[run_id]["actionLog"].append(dispatch)

        self.save(data)

    def add_receipt(
        self,
        run_id,
        receipt
    ):

        data = self.load()

        data[run_id]["receiptLog"].append(receipt)

        self.save(data)

    def set_completed(
        self,
        run_id,
        final_response
    ):

        data = self.load()

        data[run_id]["status"] = final_response["status"]

        data[run_id]["response"] = final_response

        self.save(data)
