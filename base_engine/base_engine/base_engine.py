from typing import Any, Generator
from pydantic import BaseModel, Field
from abc import ABC, abstractmethod
import redis
import json
from datetime import datetime
import logging
import time


class BaseOptions(BaseModel):
    """Base scan options."""

    pass


class Issue(BaseModel):
    severity: str = "info"
    confidence: str = "certain"
    target: dict = Field(default_factory=dict)
    title: str
    description: str = "No description provided."
    solution: str = "No solution available."
    metadata: dict = Field(default_factory=dict)
    type: str
    raw: Any = Field(default_factory=dict)
    timestamp: int = Field(default_factory=lambda: int(time.time()))


class Engine(ABC):
    logger = logging.getLogger(__name__)

    def __init__(
        self,
        scan_option: type[BaseModel] = BaseOptions,
        metadatas: type[BaseModel] = BaseModel,
        metadata_path="metadatas.json",
    ):
        self.queue_key = f"queue:{self.__class__.__name__}"
        self.processing_key = f"processing:{self.__class__.__name__}"
        self.scan_options = scan_option
        self.metadatas = metadatas

        with open(metadata_path, "r", encoding="utf-8") as f:
            metadatas = json.load(f)
            self._validate_and_load_config(metadatas)

    def start(self):
        self.redis_client = redis.Redis(
            host="localhost", port=6379, db=0, decode_responses=True
        )
        self._get_and_process_task()

    def _get_and_process_task(self):
        task = self.redis_client.blpop(self.queue_key, timeout=2)
        if not task:
            self.logger.debug("No task found")
            time.sleep(10)
            return self._get_and_process_task()

        key, value = task
        self._process_task(value)

    def _validate_and_load_config(self, metadatas: dict):
        """Validate metadata and load configuration."""
        validated_metadatas = self.metadatas.model_validate(metadatas)
        self.load_config(validated_metadatas)

    def execute_scan(self, options):
        """Execute the scan and return results."""
        started_at = datetime.now().timestamp()
        results = []

        for issues in self.start_scan(options):
            issues_to_list = issues if isinstance(issues, list) else [issues]

            for issue in issues_to_list:
                results.append(
                    {
                        "result": dict(Issue.model_validate(issue)),
                        "finished_at": datetime.now().timestamp(),
                        "started_at": started_at,
                        "engine": self.__class__.__name__,
                    }
                )

        return results

    def test_scan(self, scan_option: dict, metadatas: dict):
        """Test scan using provided options and metadata."""
        self._validate_and_load_config(metadatas)
        options = self.scan_options.model_validate(scan_option)
        return self.execute_scan(options)

    def _process_task(self, value: str):
        """Processes a task from Redis queue."""
        try:
            task_data = json.loads(value)
            self.redis_client.rpush(self.processing_key, value)

            options = self.scan_options.model_validate(task_data)
            results = self.execute_scan(options)

            for result in results:
                print("Send to datalake:", result)

            self.redis_client.lrem(self.processing_key, 0, value)
            self._get_and_process_task()
        except Exception as e:
            self._handle_task_failure(value, task_data, e)

    def _handle_task_failure(self, value: str, task_data: dict, error: Exception):
        """Handles the failure of a task processing."""
        self.logger.error(f"Error processing task: {error}")
        self.redis_client.lrem(self.processing_key, 0, value)
        self.redis_client.rpush(self.queue_key, json.dumps(task_data))

    @abstractmethod
    def start_scan(
        self, options: BaseModel, metadatas: BaseModel
    ) -> Generator[dict | list[dict], Any, None]:
        pass

    def load_config(self, metadatas):
        pass
