import os


def get_env(name: str):
    """
    if name in os.environ:
        return os.environ[name]
    else:
        return default_value
    """
    return os.environ[name]

ANNOUNCE_DELAY = 1 * 60  # seconds
ANNOUNCE_URL = get_env("PUBLIC_RELAY_LIST") # "http://localhost:8080"
F_PACKET_SIZE = 4
RELAY_LISTENING_IP = '0.0.0.0'
