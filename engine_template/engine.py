from base_engine.base_engine import Engine
from metadatas import Metadatas, Options
from typing import Any, Generator


class TemplateEngine(Engine):
    # def load_config(self, metadatas: Metadatas):
    #     pass

    def start_scan(self, options: Options) -> Generator[dict | list[dict], Any, None]:
        for i in [1, 2]:
            yield {"info": i, "example_option": options.example_option}


engine = TemplateEngine(Options, Metadatas)

if __name__ == "__main__":
    engine.start()
