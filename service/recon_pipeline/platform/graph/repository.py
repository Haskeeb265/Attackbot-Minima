import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from neo4j import exceptions

# Path setup: make the repo root and this package importable regardless of cwd.
_ROOT = Path(__file__).resolve().parents[3]
_GRAPH_DIR = Path(__file__).resolve().parent
for _path in (_ROOT, _GRAPH_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from client import Neo4jClient
from config import NEO4J_DATABASE

logger = logging.getLogger(__name__)


def _label_clause(labels: Sequence[str]) -> str:
    """Render a label list as a Cypher pattern suffix (e.g. `:Asset`:`Domain`).

    Every node the CRUD writes may carry several labels — always the base
    ``:Asset`` plus a typed label (schema.py multi-label design). Empty lists
    and bare strings are rejected up front (a bare string would otherwise be
    iterated character-by-character into garbage labels).

    NOTE — MERGE matches on the FULL label set. The same identity must always
    be written with the identical label set (e.g. always ``["Asset", "Domain"]``),
    otherwise idempotency breaks: a re-write with a different set will not
    merge and will trip the ``:Asset`` identity constraint instead.
    """
    if isinstance(labels, str):
        raise TypeError("labels must be a sequence of label strings, not a bare string")
    if not labels:
        raise ValueError("at least one label is required")
    return "".join(f":`{label}`" for label in labels)


class Neo4jRepository:

    def __init__(self, client: Neo4jClient, database: str = NEO4J_DATABASE):
        self.client = client
        self.database = database

    @property
    def driver(self):
        return self.client.driver

    # ------------------------------------------------------------------
    # 1. RUN QUERY
    # ------------------------------------------------------------------
    def run_query(
        self,
        query: str, 
        parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        try:
            records, _, _ = self.driver.execute_query(
                query,
                parameters or {},
                database_=self.database,
            )
            return [record.data() for record in records]
        except exceptions.Neo4jError as e:
            logger.error(f"Cypher execution failed: {e}")
            raise
        
        
    # ------------------------------------------------------------------
    # 2. MERGE NODE
    # ------------------------------------------------------------------
    def merge_node(
        self,
        labels: Sequence[str],
        identity_props: Dict[str, Any],
        additional_props: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not identity_props:
            raise ValueError("merge_node requires at least one identity property")
        all_props = {**identity_props, **(additional_props or {})}
        # Backtick the property keys AND use positional params: Cypher parameter
        # names cannot contain dots/hyphens, so keys like `scope.Identifier` or
        # `a-key` only work when the $name is generated (p0, p1, ...).
        match_keys = ", ".join([f"`{k}`: $p{i}" for i, k in enumerate(identity_props)])

        # `labels` is a list (e.g. ["Asset", "Domain"]) so nodes carry the
        # schema's base label AND its typed label — the :Asset identity
        # constraint is only exercised when writes include the :Asset label.
        # The same identity must ALWAYS be written with the same label set
        # (see _label_clause) or MERGE stops being idempotent.
        cypher = f"MERGE (n{_label_clause(labels)} {{{match_keys}}}) SET n += $all_props RETURN n"
        params = {f"p{i}": v for i, v in enumerate(identity_props.values())}
        params["all_props"] = all_props

        result = self.run_query(cypher, params)
        return result[0]["n"] if result else {}
    
    
    # ------------------------------------------------------------------
    # 3. GET NODE
    # ------------------------------------------------------------------
    def get_node(
        self,
        labels: Sequence[str],
        properties: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if not properties:
            raise ValueError("get_node requires at least one property to match on")
        where_clause = [f"n.`{k}` = $p{i}" for i, k in enumerate(properties)]
        where_str = " AND ".join(where_clause)

        cypher = f"MATCH (n{_label_clause(labels)}) WHERE {where_str} RETURN n LIMIT 1"
        params = {f"p{i}": v for i, v in enumerate(properties.values())}
        result = self.run_query(cypher, params)
        return result[0]["n"] if result else None
    
    
    # ------------------------------------------------------------------
    # 4. MERGE RELATIONSHIP
    # ------------------------------------------------------------------
    def merge_relation(
        self,
        from_labels: Sequence[str],
        from_key: Dict[str, Any],
        rel_type: str,
        to_labels: Sequence[str],
        to_key: Dict[str, Any],
        rel_props: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not from_key or not to_key:
            raise ValueError("merge_relation requires at least one property on both endpoints")
        from_matches = ", ".join([f"`{k}`: $from_{i}" for i, k in enumerate(from_key)])
        to_matches = ", ".join([f"`{k}`: $to_{i}" for i, k in enumerate(to_key)])

        cypher = (
            f"MATCH (a{_label_clause(from_labels)} {{{from_matches}}}) "
            f"MATCH (b{_label_clause(to_labels)} {{{to_matches}}}) "
            f"MERGE (a)-[r:`{rel_type}`]->(b) "
            f"SET r += $rel_props "
            f"RETURN r, a, b"
        )

        params = {f"from_{i}": v for i, v in enumerate(from_key.values())}
        params.update({f"to_{i}": v for i, v in enumerate(to_key.values())})
        params["rel_props"] = rel_props or {}

        result = self.run_query(cypher, params)
        return result[0] if result else {}
    
    
    # ------------------------------------------------------------------
    # 5. GET RELATIONSHIP
    # ------------------------------------------------------------------
    def get_relation(
        self,
        from_labels: Sequence[str],
        from_key: Dict[str, Any],
        rel_type: str,
        to_labels: Sequence[str],
        to_key: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if not from_key or not to_key:
            raise ValueError("get_relation requires at least one property on both endpoints")
        from_matches = ", ".join([f"`{k}`: $from_{i}" for i, k in enumerate(from_key)])
        to_matches = ", ".join([f"`{k}`: $to_{i}" for i, k in enumerate(to_key)])

        cypher = (
            f"MATCH (a{_label_clause(from_labels)} {{{from_matches}}})"
            f"-[r:`{rel_type}`]->"
            f"(b{_label_clause(to_labels)} {{{to_matches}}}) "
            f"RETURN r, a, b LIMIT 1"
        )

        params = {f"from_{i}": v for i, v in enumerate(from_key.values())}
        params.update({f"to_{i}": v for i, v in enumerate(to_key.values())})

        result = self.run_query(cypher, params)
        return result[0] if result else None