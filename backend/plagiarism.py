
# backend/plagiarism.py
from difflib import SequenceMatcher

def check_similarity_texts(a: str, b: str) -> float:
    a = a or ""
    b = b or ""
    return SequenceMatcher(None, a, b).ratio()
