import sys
from pathlib import Path

from neo4j import GraphDatabase

# Path setup: make the repo root importable so `config` resolves regardless of cwd.
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD

# Constants
URI = NEO4J_URI
AUTH = (NEO4J_USERNAME, NEO4J_PASSWORD)


class Neo4jClient:
    def __init__(self, uri: str = URI, auth: tuple[str, str] = AUTH):
        self.driver = GraphDatabase.driver(uri, auth=auth)

    def verify(self):
        self.driver.verify_connectivity()

    def close(self):
        self.driver.close()
