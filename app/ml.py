import threading

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer


class NeuralEngine:
    def __init__(self) -> None:
        self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
        self.model = RandomForestClassifier(n_estimators=120, random_state=42)
        self.is_trained = False
        self._lock = threading.Lock()

    def train_from_db(self, db_path: str) -> None:
        import sqlite3

        with self._lock:
            try:
                conn = sqlite3.connect(db_path)
                rows = conn.execute("SELECT url, manual_status FROM feedback").fetchall()
                conn.close()
                if len(rows) < 2:
                    return
                urls = [row[0] for row in rows]
                labels = [1 if "MALICIOUS" in row[1] else 0 for row in rows]
                vectors = self.vectorizer.fit_transform(urls)
                self.model.fit(vectors, labels)
                self.is_trained = True
            except Exception:
                self.is_trained = False

    def predict_malicious_prob(self, url: str) -> float:
        if not self.is_trained:
            return 0.5
        try:
            return float(self.model.predict_proba(self.vectorizer.transform([url]))[0][1])
        except Exception:
            return 0.0


neural_engine = NeuralEngine()
