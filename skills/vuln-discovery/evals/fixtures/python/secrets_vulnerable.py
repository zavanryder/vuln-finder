"""Vulnerable: Hardcoded secrets and weak crypto."""
import hashlib
import random

DATABASE_URL = "postgresql://admin:s3cretP@ss!@db.internal:5432/prod"
API_KEY = "sk-live-4f3c2b1a0987654321abcdef"
JWT_SECRET = "changeme"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))
