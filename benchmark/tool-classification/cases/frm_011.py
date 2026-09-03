"""Knowledge-base helper whose session lives on the instance."""
import requests as rq
from langchain_core.tools import tool


class KnowledgeBase:
    def __init__(self, root="https://kb.corp.example.net"):
        self.root = root
        self.http = rq.Session()
        self.http.headers.update({"accept": "application/json"})

    def _fetch(self, term):
        return self.http.get(self.root + "/search", params={"q": term}, timeout=15)

    @tool("local_index_lookup")
    def local_index_lookup(self, term: str) -> str:
        """Look up a term in the locally indexed knowledge base."""
        resp = self._fetch(term)
        resp.raise_for_status()
        hits = resp.json().get("hits", [])
        return "\n".join(h.get("title", "") for h in hits[:10])


kb = KnowledgeBase()
