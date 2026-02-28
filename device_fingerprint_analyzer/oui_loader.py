import csv
import os
import pickle


class OUILoader:
    def __init__(self, csv_path="./data/oui.csv", cache_file="./data/oui_cache.pkl"):
        self.csv_path = csv_path
        self.cache_file = cache_file
        self.oui_db = {}

    def load(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "rb") as f:
                self.oui_db = pickle.load(f)
            return self.oui_db

        with open(self.csv_path, newline='', encoding="utf-8", errors="ignore") as csvfile:
            reader = csv.reader(csvfile)
            
            next(reader)
            
            for row in reader:
                if len(row) < 3:
                    continue

                assignment = row[1].strip().upper()
                vendor = row[2].strip()

                if len(assignment) == 6:
                    prefix = ":".join([assignment[i:i+2] for i in range(0, 6, 2)])
                    self.oui_db[prefix] = vendor

        with open(self.cache_file, "wb") as f:
            pickle.dump(self.oui_db, f)

        return self.oui_db

    def lookup(self, mac):
        mac = mac.upper()
        prefix = mac[:8]
        return self.oui_db.get(prefix, "Unknown")