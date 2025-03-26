from typing import Any, Generator, List, Dict
from pydantic import BaseModel
from abc import ABC, abstractmethod
import json
from datetime import datetime
import time
from base_engine.custom_logger import logger


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

    ### START (Never called during unit testing)

    def start(self, data):
        logger.info("Start scan with data", data)
        options = self.scan_options.model_validate(data)
        issues_count = 0

        for result in self._execute_scan(options):
            print(time.time())
            issues_count += 1
            # TODO
            # print("Send to datalake:", result)
            pass

        return issues_count

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
