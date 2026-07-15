# memory/chromadb_manager.py
import chromadb
from chromadb.utils import embedding_functions
import config

# ── Client setup ────────────────────────────────────────────────────────────
# PersistentClient writes to disk (config.CHROMA_PERSIST_DIR) so incidents
# survive restarts — a fresh `python api/main.py` won't wipe your history.
_client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)

# Default embedding function — all-MiniLM-L6-v2, runs locally, no API cost.
# This is what turns your raw_log text into vectors ChromaDB can compare.
_embedder = embedding_functions.DefaultEmbeddingFunction()

_collection = _client.get_or_create_collection(
    name="soc_incidents",
    embedding_function=_embedder,
    metadata={"hnsw:space": "cosine"},  # cosine similarity — standard for text embeddings
)


def store_alert(alert: dict, pipeline_result: dict) -> None:
    """
    Called after an alert finishes the pipeline (or after analyst feedback).

    What gets embedded: raw_log — this is the actual text ChromaDB compares
    against future alerts. Everything else (severity, MITRE ID, verdict)
    goes into `metadata` — searchable/filterable but NOT embedded.

    Why not embed the whole alert dict? Embedding structured fields like
    "port: 22" adds noise — raw_log has the actual attack signature language.
    """
    _collection.add(
        ids=[alert["alert_id"]],
        documents=[alert["raw_log"]],
        metadatas=[{
            "event_type":       alert["event_type"],
            "severity":         alert["severity"],
            "hostname":         alert["hostname"],
            "source_ip":        alert["source_ip"],
            "attack_type":      pipeline_result.get("attack_type", "unknown"),
            "mitre_id":         pipeline_result.get("mitre_id", "unknown"),
            "false_positive":   pipeline_result.get("false_positive", False),
        }],
    )
    print(f"  💾 Stored alert {alert['alert_id'][:8]}... in ChromaDB")


def find_similar(raw_log: str, n_results: int = 3) -> list[dict]:
    """
    Called by the Memory agent for every incoming alert.

    Returns up to n_results past incidents, each with:
      - the original log text
      - metadata (severity, attack_type, mitre_id, false_positive flag)
      - distance (0.0 = identical, higher = less similar — cosine distance)

    Why n_results=3 default: enough context for the LLM to spot a pattern
    without flooding its prompt. Memory agent can override this if needed.

    Edge case handled: if the collection is empty (first-ever alert),
    ChromaDB's query() would error. We check count() first and return []
    instead of crashing — Memory agent should treat empty list as
    "no history yet" and say so in its reasoning.
    """
    if _collection.count() == 0:
        return []

    results = _collection.query(
        query_texts=[raw_log],
        n_results=min(n_results, _collection.count()),  # can't ask for more than exist
    )

    similar = []
    # ChromaDB returns parallel lists nested one level for batch queries —
    # since we only sent 1 query_text, everything is at index [0]
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        similar.append({
            "raw_log":       doc,
            "severity":      meta.get("severity"),
            "attack_type":   meta.get("attack_type"),
            "mitre_id":      meta.get("mitre_id"),
            "false_positive": meta.get("false_positive", False),
            "similarity":    round(1 - dist, 3),  # convert distance → similarity score (1.0 = identical)
        })

    return similar