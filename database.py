import sqlite3


class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()

    def read_domains(self) -> dict:
        self.cursor.execute("SELECT project_id, name FROM domains")
        data = self.cursor.fetchall()
        result_dict = {}
        for project_id, name in data:
            if project_id in result_dict:
                result_dict[project_id].append(name)
            else:
                result_dict[project_id] = [name]

        return result_dict

    def write_rules(self, rules_dict: dict) -> bool:
        try:
            for project_id, reg_exp in rules_dict.items():
                self.cursor.execute("INSERT INTO rules (regexp, project_id) VALUES (?, ?)", (reg_exp, project_id))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

