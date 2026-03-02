import threading
import os
from urllib.parse import urlparse


class NeuralEngine:
    def __init__(self) -> None:
        self.vectorizer = None
        self.model = None
        self._ml_ready = False
        self.is_trained = False
        self._lock = threading.Lock()
        self._bad_tokens = set()
        self._good_tokens = set()
        self._use_sklearn = (os.getenv("CYPHERSCOUT_USE_SKLEARN", "false").strip().lower() == "true")

    def _tokenize(self, url: str) -> set[str]:
        parsed = urlparse(url if str(url).startswith(("http://", "https://")) else f"https://{url}")
        host = (parsed.netloc or "").lower().replace("www.", "")
        path = (parsed.path or "").lower()
        tokens = set()
        for chunk in (host + "/" + path).replace(".", "/").replace("-", "/").split("/"):
            chunk = chunk.strip()
            if len(chunk) >= 3:
                tokens.add(chunk)
        return tokens

    def train_from_db(self, db_path: str) -> None:
        import sqlite3

        with self._lock:
            try:
                conn = sqlite3.connect(db_path)
                rows = conn.execute("SELECT url, manual_status FROM feedback").fetchall()
                conn.close()
                if len(rows) < 2:
                    self.is_trained = False
                    return

                # Optional sklearn mode only when explicitly enabled.
                if self._use_sklearn:
                    try:
                        from sklearn.ensemble import RandomForestClassifier
                        from sklearn.feature_extraction.text import TfidfVectorizer

                        self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
                        self.model = RandomForestClassifier(n_estimators=120, random_state=42)
                        urls = [row[0] for row in rows]
                        labels = [1 if "MALICIOUS" in (row[1] or "").upper() or "SCAM" in (row[1] or "").upper() else 0 for row in rows]
                        vectors = self.vectorizer.fit_transform(urls)
                        self.model.fit(vectors, labels)
                        self._ml_ready = True
                        self.is_trained = True
                        return
                    except Exception:
                        self._ml_ready = False

                # Safe pure-Python fallback model.
                bad_tokens = set()
                good_tokens = set()
                for url, status in rows:
                    label = (status or "").upper()
                    tokens = self._tokenize(url or "")
                    if "MALICIOUS" in label or "SCAM" in label:
                        bad_tokens.update(tokens)
                    else:
                        good_tokens.update(tokens)
                self._bad_tokens = bad_tokens
                self._good_tokens = good_tokens
                self.is_trained = bool(self._bad_tokens or self._good_tokens)
            except Exception:
                self.is_trained = False

    def predict_malicious_prob(self, url: str) -> float:
        if not self.is_trained:
            return 0.5
        if self._ml_ready and self.model is not None and self.vectorizer is not None:
            try:
                return float(self.model.predict_proba(self.vectorizer.transform([url]))[0][1])
            except Exception:
                return 0.5
        tokens = self._tokenize(url)
        if not tokens:
            return 0.5
        bad_hits = len(tokens.intersection(self._bad_tokens))
        good_hits = len(tokens.intersection(self._good_tokens))
        total = bad_hits + good_hits
        if total == 0:
            return 0.5
        return max(0.0, min(1.0, bad_hits / float(total)))


neural_engine = NeuralEngine()
