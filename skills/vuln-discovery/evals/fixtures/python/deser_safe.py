"""Safe: Deserialization -- json used instead of pickle, safe yaml loader."""
import json
import yaml

def load_user_session(data):
    return json.loads(data)

def load_config(yaml_str):
    return yaml.safe_load(yaml_str)
