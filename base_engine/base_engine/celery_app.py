import os
from celery import Celery


RABBITMQ_ADDRESS = os.environ.get("RABBITMQ_ADDRESS", "localhost")

app = Celery("scans", broker=f"pyamqp://guest:guest@{RABBITMQ_ADDRESS}//")
app.conf.broker_connection_retry_on_startup = True
