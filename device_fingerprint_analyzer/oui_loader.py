import csv
import os
import pickle


class OUILoader:
    def __init__(self, csv_path="oui.csv", cache_file="oui_cache.pkl"):
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
            for row in reader:
                if len(row) < 2:
                    continue

                prefix = row[0].strip().upper()
                vendor = row[1].strip()

                prefix = prefix.replace("-", ":")
                if len(prefix) == 6:
                    prefix = ":".join([prefix[i:i+2] for i in range(0, 6, 2)])

                self.oui_db[prefix] = vendor

        with open(self.cache_file, "wb") as f:
            pickle.dump(self.oui_db, f)

        return self.oui_db

    def lookup(self, mac):
        mac = mac.upper()
        prefix = mac[:8]
        return self.oui_db.get(prefix, "Unknown")