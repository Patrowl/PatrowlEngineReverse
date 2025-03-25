from base_engine.base_engine import Engine
from metadatas import Metadatas, Options
from typing import Any, Generator
from base_engine.custom_logger import logger


class TemplateEngine(Engine):
    # def load_config(self, metadatas: Metadatas):
    #     pass

    def start_scan(self, options: Options) -> Generator[dict | list[dict], Any, None]:
        logger.info(f"Scan #{options.id} | Starting")

        for i in [1, 2]:
            yield {
                "info": i,
                "example_option": options.example_option,
            }

        logger.info(f"Scan #{options.id} | Over !")


engine = TemplateEngine(Options, Metadatas)

if __name__ == "__main__":
    engine.start()
