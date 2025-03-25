from typing import Any, Generator
from pydantic import BaseModel, Field
from abc import ABC, abstractmethod
import pika
import json
from datetime import datetime
import time
from base_engine.custom_logger import logger
import os

RABBITMQ_ADDRESS = os.environ.get("RABBITMQ_ADDRESS", "localhost")


class BaseOptions(BaseModel):
    """Base scan options."""

    id: int = 0
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
    def __init__(
        self,
        scan_option: type[BaseModel] = BaseOptions,
        metadatas: type[BaseModel] = BaseModel,
        metadata_path="metadatas.json",
    ):
        self.task = None
        self.queue_key = f"engine-{self.__class__.__name__}"
        self.scan_options = scan_option
        self.metadatas = metadatas

        with open(metadata_path, "r", encoding="utf-8") as f:
            metadatas = json.load(f)
            self._validate_and_load_config(metadatas)

    def _validate_and_load_config(self, metadatas: dict):
        """Validate metadata and load configuration."""
        validated_metadatas = self.metadatas.model_validate(metadatas)
        self.load_config(validated_metadatas)

    ### DATABASES INTERACTIONS

    # TODO
    def query_issues(self, query):
        print(query)
        return []

    ### START & QUEUE PROCESS (Never called during unit testing)

    def start(self):
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(RABBITMQ_ADDRESS)
        )
        self.pika_channel = connection.channel()

        self._get_and_process_task()

    def _get_and_process_task(self):
        logger.debug(f"Listening for messages in queue {self.queue_key}")
        while not (self.task and self.task[0]):
            self.task = self.pika_channel.basic_get(self.queue_key)
            if not self.task[0]:
                time.sleep(1)

        if self._process_task():
            self.pika_channel.basic_ack(self.task[0].delivery_tag)
        else:
            self.pika_channel.basic_cancel(self.task[0].delivery_tag)

        self.task = None
        self._get_and_process_task()

    def _process_task(self):
        method_frame, properties, body = self.task
        """Processes a task from Redis queue."""
        logger.info("Start processing task")
        try:
            task_data = json.loads(body)
            print("task_data")
            print(task_data)

            options = self.scan_options.model_validate(task_data)
            results = self.execute_scan(options)

            for result in results:
                # TODO
                # print("Send to datalake:", result)
                pass

            return True
        except Exception as e:
            logger.error("Error processing task", e)
            return False

    ### UNIT TESTING PURPOSES

    def test_scan(self, scan_option: dict, metadatas: dict):
        """Test scan using provided options and metadata."""
        self._validate_and_load_config(metadatas)
        options = self.scan_options.model_validate(scan_option)
        return self.execute_scan(options)

    ### MAIN FUNCTION TO EXECUTE SCANS

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

    ### ABSTRACT METHODS

    @abstractmethod
    def start_scan(
        self, options: BaseModel, metadatas: BaseModel
    ) -> Generator[dict | list[dict], Any, None]:
        pass

    def load_config(self, metadatas):
        pass
