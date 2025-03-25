# Engines

[DEVELOPMENT DOC](ENGINE_DEV.md)

Engine are listening a RabbitMQ queue `engine-EngineName` like `engine-OwlDNS`

They consume a task in queue (state Ready --> Unacked). At the end of the process, the task is Ack

Then, result is sent to a database

## Env vars

- RABBITMQ_ADDRESS=localhost
    - Address of rabbit MQ
- LOG_LEVEL=20
    - 10=DEBUG 20=INFO 30=WARNING 40=ERROR 50=CRITICAL
