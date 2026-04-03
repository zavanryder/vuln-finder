"""Vulnerable: Insecure deserialization via pickle and yaml."""
import pickle
import yaml

def load_user_session(data):
    return pickle.loads(data)

def load_config(yaml_str):
    return yaml.load(yaml_str, Loader=yaml.Loader)
