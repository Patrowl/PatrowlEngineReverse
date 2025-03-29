import requests
import json
import psycopg2
from base_engine.custom_logger import logger
import time
import os

DB_CONFIG = {
    "database": os.environ.get("ARSENAL_DB_NAME", "patrowlarsenal_db"),
    "user": os.environ.get("ARSENAL_DB_USER", "PATROWLARSENAL_DBUSER"),
    "password": os.environ.get("ARSENAL_DB_PASSWORD", "PATROWLARSENAL_DBPASS"),
    "host": os.environ.get("ARSENAL_DB_HOST", "localhost"),
    "port": os.environ.get("ARSENAL_DB_PORT", 5432),
}

ARSENAL_URL = os.environ.get("ARSENAL_URL", "http://localhost:8004")
ARSENAL_TOKEN = os.environ.get(
    "ARSENAL_TOKEN", "5b3df5676cc24ecc4682297904033091fe0dd2a5"
)


def push_issues_arsenal(
    issues: list, max_retries: int = 5, sleep_time: int = 2
) -> bool:
    endpoint = f"{ARSENAL_URL}/findings/api/v1/raw/"
    headers = {"Authorization": f"Token {ARSENAL_TOKEN}"}

    payload = json.dumps(issues, default=str)

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                endpoint, json=json.loads(payload), headers=headers, timeout=10
            )
            response.raise_for_status()
            res_json = response.json()

            if res_json.get("success"):
                return True
            else:
                logger.error(f"Error pushing issues on Arsenal: {res_json}")
                return False
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(sleep_time)
            else:
                logger.error("Can't send issues to arsenal.")
                return False


def set_started_db(scan_id: str):
    conn = psycopg2.connect(**DB_CONFIG)

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH updated_job AS (
                        UPDATE scan_jobs
                        SET status = %s
                        WHERE id = %s
                        RETURNING scan_id
                    )
                    UPDATE scans
                    SET status = %s
                    WHERE id = (SELECT scan_id FROM updated_job);
                    """,
                    ("started", scan_id, "running"),
                )
                logger.info(f"Set scan_job {scan_id} status to 'started'.")
                logger.info("Set associated scan status to 'running'.")
    finally:
        conn.close()


def set_finished_db(scan_id: str):
    conn = psycopg2.connect(**DB_CONFIG)

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                        UPDATE scan_jobs
                        SET status = %s, finished_at = NOW()
                        WHERE id = %s
                    """,
                    ("finished", scan_id),
                )
                logger.info(f"Set scan_job {scan_id} status to 'finished'.")
    finally:
        conn.close()
