class AnalysisContext:
    def __init__(self, process_tree):
        self.process_tree = process_tree
        self.findings = []
        # Trust Map: SeqID -> Score (0-100)
        self._trust_scores = defaultdict(lambda: 50) 

    def get_trust(self, seqid):
        return self._trust_scores[seqid]

    def lower_trust(self, seqid, amount):
        self._trust_scores[seqid] -= amount