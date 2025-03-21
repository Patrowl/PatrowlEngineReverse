import redis
import json

# Connexion à Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

def push_task(task_data, task_type):
    # Définir la clé de la file pour ce type de tâche
    queue_key = f"queue:{task_type}"
    # Convertir la tâche en JSON et l'ajouter à la file (ici, à droite)
    redis_client.rpush(queue_key, json.dumps(task_data))
    print(f"Tâche ajoutée dans {queue_key}")

# Exemple d'ajout de tâche
if __name__ == '__main__':
    task = {"id": 2, "assets": ["http://sutowl.fr"], "options": {"arg": "value1", "arg2": "value2"}}
    push_task(task, "OwlDNS")
