"""Lightweight Flask API that fronts the Redis/RQ task queue.

Run with ``python -m varux.core.orchestrator_api`` or ``python
varux/core/orchestrator_api.py`` and keep at least one RQ worker alive
(`rq worker varux-tasks`).
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, request
from redis import Redis
from rq import Worker
from rq.job import Job

from .modules import MODULE_REGISTRY
from .task_queue import DEFAULT_REDIS_URL, get_queue, queue_health, run_module_task

app = Flask(__name__)
BASE_DIR = os.getenv("VARUX_BASE_DIR", os.getcwd())


def _serialize_job(job: Job) -> Dict[str, Any]:
    job.refresh()
    return {
        "id": job.get_id(),
        "status": job.meta.get("status", job.get_status().upper()),
        "enqueued_at": job.enqueued_at.isoformat() if job.enqueued_at else None,
        "started_at": job.meta.get("started_at"),
        "finished_at": job.meta.get("finished_at"),
        "result": job.return_value(),
        "meta": job.meta,
    }


@app.route("/api/tasks", methods=["POST"])
def enqueue_task():
    payload = request.get_json(force=True) if request.data else {}
    module_key = payload.get("module")
    if module_key not in MODULE_REGISTRY:
        return jsonify({"error": "Unknown module", "available": list(MODULE_REGISTRY.keys())}), 400

    task_payload = payload.get("payload", {})
    timeout = int(payload.get("timeout", 0) or 0) or None

    queue = get_queue(redis_url=payload.get("redis_url"))
    job = queue.enqueue(
        run_module_task,
        module_key,
        task_payload,
        BASE_DIR,
        timeout,
        meta={"status": "PENDING", "created_at": datetime.utcnow().isoformat()},
    )

    return jsonify({"job_id": job.get_id(), "status": "PENDING"}), 202


@app.route("/api/tasks/<job_id>", methods=["GET"])
def task_status(job_id: str):
    connection = Redis.from_url(DEFAULT_REDIS_URL)
    job = Job.fetch(job_id, connection=connection)
    return jsonify(_serialize_job(job))


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(queue_health())


@app.route("/api/health/workers", methods=["GET"])
def worker_health():
    connection = Redis.from_url(DEFAULT_REDIS_URL)
    workers = Worker.all(connection=connection)
    data = [
        {
            "name": worker.name,
            "state": worker.get_state(),
            "queues": [q.name for q in worker.queues],
            "birth_date": worker.birth_date.isoformat() if worker.birth_date else None,
        }
        for worker in workers
    ]
    return jsonify({"workers": data, "count": len(data)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("VARUX_ORCH_PORT", "5001")))
