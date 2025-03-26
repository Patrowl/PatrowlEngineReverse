from celery import Celery

app = Celery("tasks", broker="pyamqp://guest:guest@localhost//")


def push_task(queue_name, task_data):
    app.send_task("execute_scan", args=[task_data], queue="engine-OwlDNS")
    print(f" [x] Sent task to {queue_name}: {task_data}")


def get_assets():
    return [{"datatype": "domain", "value": "yohangastoud.fr"}]


def get_options():
    return {
        # "create_new_assets": 1,
        "do_subdomain_enum": True,
        "do_subdomains_resolve": True,
        "do_dns_recursive": True,
        "subdomain_as_new_asset": True,
        "do_subdomain_bruteforce": True,
        "do_dns_transfer": True,
        "do_spf_check": True,
        "do_seg_check": True,
        "do_dmarc_check": True,
        "do_dkim_check": True,
        "do_whois": True,
        # "do_advanced_whois": True, # Not working on V1
    }


if __name__ == "__main__":
    options = {
        "assets": get_assets(),
        **get_options(),
    }
    task = options
    for i in range(150):
        push_task("engine-OwlDNS", task)
