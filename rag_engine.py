
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer


# Paths are relative to this Python file
BASE_DIR = Path(__file__).resolve().parent
KNOWLEDGE_DIR = BASE_DIR / "knowledge_base"
VECTOR_DB_DIR = BASE_DIR / "chroma_db"

# Local embedding model
MODEL_NAME = "all-MiniLM-L6-v2"

# Chunk settings
CHUNK_SIZE = 700
CHUNK_OVERLAP = 100

# Initialize model and vector database
embedding_model = SentenceTransformer(MODEL_NAME)

client = chromadb.PersistentClient(
    path=str(VECTOR_DB_DIR)
)

collection = client.get_or_create_collection(
    name="soc_knowledge",
    metadata={"hnsw:space": "cosine"}
)


def split_into_chunks(text):
    """Split document text into overlapping chunks."""
    text = " ".join(text.split())
    chunks = []

    start = 0
    while start < len(text):
        end = min(start + CHUNK_SIZE, len(text))
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        if end == len(text):
            break

        start = end - CHUNK_OVERLAP

    return chunks


def ingest_documents():
    """Read text files and store their embeddings in ChromaDB."""
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)

    documents = []
    ids = []
    metadatas = []

    for file_path in KNOWLEDGE_DIR.glob("*.txt"):
        text = file_path.read_text(encoding="utf-8")
        chunks = split_into_chunks(text)

        for index, chunk in enumerate(chunks):
            documents.append(chunk)
            ids.append(f"{file_path.stem}-{index}")
            metadatas.append({
                "source": file_path.name,
                "chunk": index
            })

    if not documents:
        print("No .txt knowledge documents found.")
        return 0

    embeddings = embedding_model.encode(
        documents,
        normalize_embeddings=True
    ).tolist()

    collection.upsert(
        ids=ids,
        documents=documents,
        metadatas=metadatas,
        embeddings=embeddings
    )

    print(f"Successfully indexed {len(documents)} chunks.")
    return len(documents)


def retrieve_knowledge(query, top_k=3):
    """Retrieve the most relevant knowledge chunks for a query."""
    query_embedding = embedding_model.encode(
        [query],
        normalize_embeddings=True
    ).tolist()

    results = collection.query(
        query_embeddings=query_embedding,
        n_results=min(top_k, collection.count())
    )

    retrieved = []

    if results["documents"] and results["documents"][0]:
        for i, document in enumerate(results["documents"][0]):
            retrieved.append({
                "text": document,
                "source": results["metadatas"][0][i]["source"],
                "distance": results["distances"][0][i]
            })

    return retrieved


if __name__ == "__main__":
    ingest_documents()

    print("\nTesting knowledge retrieval...")
    matches = retrieve_knowledge(
        "What should the SOC analyst do after multiple failed logins?"
    )

    for match in matches:
        print(f"\nSource: {match['source']}")
        print(f"Distance: {match['distance']:.4f}")
        print(match["text"])
