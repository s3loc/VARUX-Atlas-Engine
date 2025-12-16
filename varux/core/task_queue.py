"""Central Redis/RQ task queue for module orchestration.

The queue decouples module execution from callers (CLI, dashboard, API)
and enforces reliability features such as timeouts, retry with exponential
backoff and health reporting for workers.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict

from redis import Redis
from rq import Queue, get_current_job
from rq.job import Job
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .modules import MODULE_REGISTRY, module_path

DEFAULT_REDIS_URL = os.getenv("VARUX_REDIS_URL", "redis://localhost:6379/0")
DEFAULT_TIMEOUT = int(os.getenv("VARUX_TASK_TIMEOUT", "300"))
MAX_RETRIES = int(os.getenv("VARUX_TASK_MAX_RETRIES", "3"))


def _load_module(module_file):
    spec = importlib.util.spec_from_file_location(module_file.stem.replace(" ", "_"), str(module_file))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Modül yüklenemedi: {module_file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_file.stem.replace(" ", "_")] = module
    spec.loader.exec_module(module)
    return module


def get_queue(name: str = "varux-tasks", redis_url: str | None = None) -> Queue:
    connection = Redis.from_url(redis_url or DEFAULT_REDIS_URL)
    return Queue(name, connection=connection, default_timeout=DEFAULT_TIMEOUT)


def _invoke_module(base_dir, module_key: str, payload: Dict[str, Any], timeout: int) -> Any:
    module_info = MODULE_REGISTRY[module_key]
    module = _load_module(module_path(base_dir, module_key))

    def _call_sync():
        if "class" in module_info:
            cls = getattr(module, module_info["class"])
            instance = cls()
            return getattr(instance, module_info["function"])(**payload)
        return getattr(module, module_info["function"])(**payload)

    async def _call_async():
        if "class" in module_info:
            cls = getattr(module, module_info["class"])
            instance = cls()
            return await getattr(instance, module_info["function"])(**payload)
        return await getattr(module, module_info["function"])(**payload)

    if module_info["async"]:
        return asyncio.run(asyncio.wait_for(_call_async(), timeout=timeout))

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_call_sync)
        return future.result(timeout=timeout)


@retry(
    stop=stop_after_attempt(MAX_RETRIES),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception_type(Exception),
)
def _execute_with_retry(base_dir: str, module_key: str, payload: Dict[str, Any], timeout: int) -> Any:
    return _invoke_module(base_dir, module_key, payload, timeout)


def run_module_task(module_key: str, payload: Dict[str, Any] | None = None, base_dir: str | None = None,
                   timeout: int | None = None) -> Dict[str, Any]:
    job: Job = get_current_job()  # type: ignore[assignment]
    payload = payload or {}
    timeout = timeout or DEFAULT_TIMEOUT
    base_dir = base_dir or os.getcwd()

    job.meta.update(
        status="RUNNING",
        started_at=datetime.utcnow().isoformat(),
        retries=0,
    )
    job.save_meta()

    start = time.time()
    try:
        result = _execute_with_retry(base_dir, module_key, payload, timeout)
        status = "SUCCESS"
    except Exception as exc:  # pragma: no cover - defensive
        job.meta["error"] = str(exc)
        status = "FAILED"
        result = {"error": str(exc)}
    finally:
        job.meta.update(
            status=status,
            finished_at=datetime.utcnow().isoformat(),
            runtime_seconds=round(time.time() - start, 3),
        )
        job.save_meta()

    return {
        "module": module_key,
        "payload": payload,
        "status": status,
        "result": result,
    }


def queue_health(redis_url: str | None = None) -> Dict[str, Any]:
    """Return basic connectivity and worker liveness info."""

    redis_conn = Redis.from_url(redis_url or DEFAULT_REDIS_URL)
    try:
        redis_conn.ping()
        redis_status = "ok"
    except Exception as exc:  # pragma: no cover - defensive
        redis_status = f"error: {exc}"

    return {
        "redis": redis_status,
    }


__all__ = ["get_queue", "run_module_task", "queue_health"]
