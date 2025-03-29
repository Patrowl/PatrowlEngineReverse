from engine import engine
from base_engine.custom_logger import logger
from base_engine.celery_app import app

app.conf.task_routes = {"execute_scan": {"queue": "engine-OwlDNS"}}


@app.task(bind=True, acks_late=True, name="execute_scan", max_retries=3)
def execute_scan(self, options_json):
    try:
        self.update_state(state="PROGRESS", meta={"current": 2, "total": 6})
        return engine.start(options_json)
    except Exception as e:
        logger.exception("Celery: Error during scan", exc_info=e)
        raise self.retry(exc=e, countdown=60)
