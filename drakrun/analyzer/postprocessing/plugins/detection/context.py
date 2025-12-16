from typing import defaultdict

class AnalysisContext:
    def __init__(self, process_tree):
        self.process_tree = process_tree
        self.findings = []
        