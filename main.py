from collections import defaultdict, Counter
import math

from database import Database


class DomainGroup:
    def __init__(self, group_id, domains_list):
        self.id = group_id
        self.domains = set(domains_list)
        self.high_entropy_subdomains = []
        self.low_entropy_domains = []
        self.entropy_limit = 2.5  # Порог энтропии, можно корректировать
        self.regex = ''

    def entropy(self, s: str) -> float:
        p, lns = defaultdict(lambda: 0), float(len(s))
        for char in s:
            p[char] += 1
        return -sum(count / lns * math.log2(count / lns) for count in p.values())

    def cluster_domain(self):
        for domain in self.domains:
            parts = domain.split('.')
            if len(parts) > 2:  # Убедимся, что есть поддомен
                subdomain = parts[0]
                if not subdomain.replace('-', '').isalpha():
                    if self.entropy(subdomain) > self.entropy_limit:
                        self.high_entropy_subdomains.append(subdomain)
                    else:
                        self.low_entropy_domains.append(subdomain)
                else:
                    self.low_entropy_domains.append(subdomain)

    def analyze_subdomains(self) -> tuple[Counter, str]:
        subdomains = self.high_entropy_subdomains
        # 1. Частота длин строк
        lengths = [len(sub) for sub in subdomains]
        lengths_freq = Counter(lengths)

        # 2. Сортировка символов
        all_chars = set(''.join(subdomains))
        all_chars_sotred = ''.join(sorted(all_chars))

        return lengths_freq, all_chars_sotred

    def generate_regex(self, lengths: Counter, chars: str) -> str:
        # 1. Длина строки
        min_len, max_len = min(lengths), max(lengths)
        length_pattern = f"{{,{max_len}}}?" if min_len == 0 else f"{{{min_len},{max_len}}}"

        # 2. Символы
        has_dash = '-' in chars
        special_chars = set(chars) - set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        chars_set = set(chars) - special_chars

        sorted_chars = sorted(chars_set)
        optimized = []
        i = 0
        while i < len(sorted_chars):
            start_char = sorted_chars[i]
            end_char = start_char
            while i + 1 < len(sorted_chars) and ord(sorted_chars[i + 1]) - ord(end_char) == 1:
                end_char = sorted_chars[i + 1]
                i += 1
            if start_char == end_char:
                optimized.append(start_char)
            else:
                optimized.append(f"{start_char}-{end_char}")
            i += 1

        # Если был "-", вернем его в конец
        if has_dash:
            optimized.append('-')
        char_pattern = f'[{"".join(optimized)}]'
        self.regex = f"^{char_pattern}{length_pattern}\\."

        return self.regex

    def domain_profiler(self):
        self.cluster_domain()
        lengths_frequency, chars_string = self.analyze_subdomains()
        return self.generate_regex(lengths_frequency, chars_string)

    def filter_domians_by_regex(self):
        return [s for s in self.domains if re.match(self.regex, s)]


if __name__ == '__main__':

    db_path = "./domains.db"
    with Database(db_path) as db:
        domains = db.read_domains()

    domain_groups = [DomainGroup(*group) for group in domains.items()]

    for group in domain_groups:
        print(f"Анализ для id '{group.id}' запущен.")
        domains_group_regexp = {group.id: group.domain_profiler()}
        print(f"Регулярное выражение для id '{group.id}': '{group.regex}'")

        with Database(db_path) as db:
            send_to_db = db.write_rules(domains_group_regexp)
            if send_to_db:
                print(f"Результат успешно записан в БД!")
