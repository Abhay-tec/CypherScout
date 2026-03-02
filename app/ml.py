import threading


class NeuralEngine:
    def __init__(self) -> None:
        self.vectorizer = None
        self.model = None
        self._ml_ready = False
        self.is_trained = False
        self._lock = threading.Lock()
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer

            self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
            self.model = RandomForestClassifier(n_estimators=120, random_state=42)
            self._ml_ready = True
        except Exception:
            self._ml_ready = False

    def train_from_db(self, db_path: str) -> None:
        import sqlite3

        with self._lock:
            if not self._ml_ready:
                self.is_trained = False
                return
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
        if not self._ml_ready or not self.is_trained:
            return 0.5
        try:
            return float(self.model.predict_proba(self.vectorizer.transform([url]))[0][1])
        except Exception:
            return 0.0


neural_engine = NeuralEngine()
