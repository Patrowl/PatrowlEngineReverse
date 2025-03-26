from engine import engine
from base_engine.custom_logger import logger
from base_engine.celery_app import app

app.conf.task_routes = {"execute_scan": {"queue": "engine-OwlDNS"}}


@app.task(name="execute_scan")
def execute_scan(options_json):
    try:
        return engine.start(options_json)
    except Exception as e:
        logger.exception("Celery: Error during scan", exc_info=e)
        raise e
