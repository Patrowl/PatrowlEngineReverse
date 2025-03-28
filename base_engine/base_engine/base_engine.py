from typing import Any, Generator, List, Dict
from pydantic import BaseModel
from abc import ABC, abstractmethod
import json
from datetime import datetime
import time
from base_engine.custom_logger import logger
from base_engine.utils import (
    push_issues_arsenal,
    set_started_db,
    set_finished_db,
    set_enqueued_db,
)


class BaseOptions(BaseModel):
    """Base scan options."""

    id: int = 0


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

        with open(metadata_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.metadatas = metadatas.model_validate(data)
            self.load_config(self.metadatas)

    ### UTILS

    def _format_scan_results(self, options: BaseOptions, issues) -> List[Dict]:
        """Format scan results into a standardized dictionary."""
        started_at = datetime.now().timestamp()
        issues_to_list = issues if isinstance(issues, list) else [issues]

        return [
            {
                "result": issue,
                "finished_at": datetime.now().timestamp(),
                "scan_id": options.id,
                "started_at": started_at,
                "engine": self.__class__.__name__,
            }
            for issue in issues_to_list
        ]

    ### DATABASES INTERACTIONS

    # TODO
    def query_issues(self, query):
        print(query)
        return []

    # TODO
    def _send_to_arsenal_db(self, data: list):
        logger.info(f"Sending {len(data)} issues to Arsenal")
        return push_issues_arsenal(data)

    def _send_to_nosql_db(self, data: list):
        logger.info(f"Sending {len(data)} issues to NoSQL db")

    ### START (Never called during unit testing)

    def start(self, data):
        logger.info("Start scan with data")
        logger.info(json.dumps(data))
        options = self.scan_options.model_validate(data)
        # Temporary? update status on arsenal
        set_started_db(options.id)
        issues = []

        batch = []
        batch_size = 50

        for result in self._execute_scan(options):
            batch.append(result)
            issues.append(result)
            if len(batch) >= batch_size:
                self._send_to_nosql_db(batch)
                batch.clear()
        if batch:
            self._send_to_nosql_db(batch)

        logger.info(f"Scan over. {len(issues)} issues found")
        # Temporary? update status on arsenal
        set_finished_db(options.id)

        # Temporary. Send issues also to arsenal
        if self._send_to_arsenal_db(issues):
            return len(issues)
        else:
            set_enqueued_db(options.id)
            raise Exception("Scan re-enqueued")

    ### MAIN FUNCTION TO EXECUTE SCANS (Never called during unit testing)

    def _execute_scan(self, options: BaseOptions) -> Generator[Dict, None, None]:
        """Execute the scan and yield results."""
        for issues in self.start_scan(options):
            yield from self._format_scan_results(options, issues)

    ### UNIT TESTING PURPOSES

    def test_scan(self, scan_option: dict):
        """Test scan using provided options and metadata."""
        options = self.scan_options.model_validate(scan_option)
        return self._execute_test_scan(options)

    def _execute_test_scan(self, options: BaseOptions) -> List[Dict]:
        """Execute the scan and return results as a list."""
        results = []
        for issues in self.start_scan(options):
            results.extend(self._format_scan_results(options, issues))
        return results

    ### ABSTRACT METHODS

    @abstractmethod
    def start_scan(
        self, options: BaseModel, metadatas: BaseModel
    ) -> Generator[dict | list[dict], Any, None]:
        pass

    def load_config(self, metadatas):
        pass
