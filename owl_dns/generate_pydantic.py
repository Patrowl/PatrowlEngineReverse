import json
from typing import List, Any


def infer_type(value):
    if isinstance(value, str):
        return "str"
    elif isinstance(value, bool):
        return "bool"
    elif isinstance(value, int):
        return "int"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, list):
        if len(value) > 0:
            elem_type = infer_type(value[0])
            return f"List[{elem_type}]"
        else:
            return "List[Any]"
    elif isinstance(value, dict):
        return "dict"
    else:
        return "Any"


def generate_options_class(options_dict):
    lines = ["class Options(BaseOptions):"]
    for opt, details in options_dict.items():
        required = details.get("required", False)
        type_str = details.get("value", "string").lower()

        if type_str == "boolean":
            py_type = "bool"
            default_value = "False"
        elif type_str == "string":
            py_type = "str"
            default_value = '""'
        elif type_str == "integer":
            py_type = "int"
            default_value = "0"
        else:
            py_type = "Any"
            default_value = "None"

        if not required:
            line = f"    {opt}: {py_type} = {default_value}"
        else:
            line = f"    {opt}: {py_type}"
        lines.append(line)
    return "\n".join(lines)


def generate_metadatas_class(data):
    lines = ["class Metadatas(BaseModel):"]
    for key, value in data.items():
        if key != "options":
            type_annotation = infer_type(value)
            line = f"    {key}: {type_annotation}"
            lines.append(line)
    return "\n".join(lines)


def main():
    input_file = "metadatas.json.sample"
    output_file = "metadatas.py"

    with open(input_file, "r") as f:
        data = json.load(f)

    options_dict = data.get("options", {})

    result = [
        "from pydantic import BaseModel",
        "from typing import List, Any",
        "from base_engine.base_engine import BaseOptions",
        "",
    ]
    result.append(generate_options_class(options_dict))
    result.append("")
    result.append(generate_metadatas_class(data))

    with open(output_file, "w") as f:
        f.write("\n".join(result))

    print(f"Fichier {output_file} généré avec succès.")


if __name__ == "__main__":
    main()
