import random
from collections import Counter

from typing import Dict, List, Iterator 


class _Balancer:
    def __init__(self):
        self.domains: List[str] = []
        self._dc_to_domain: Dict[int, str] = {}
    
    def update_domains_list(self, domains_list: List[str]) -> None:
        # Filter out dead / timing-out domains
        broken = {
            "lovetrue.co.uk",
            "pclead.co.uk",
            "pyatdesyatodin.co.uk",
            "onedaychamp.co.uk",
            "nothingthere.co.uk"
        }
        valid = [d for d in domains_list if d not in broken]
        if Counter(self.domains) == Counter(valid):
            return
        
        # Priority list of fast, verified responsive Cloudflare domains
        priority = [
            'offshor.co.uk',
            'noskomnadzor.co.uk',
            'cakeisalie.co.uk',
            'sorokdva.co.uk',
            'pyatdesyatdva.co.uk',
            'notelega.co.uk',
            'fixtelega.co.uk',
            'stopblocking.co.uk',
            'nebally.co.uk',
            'havegreatday.co.uk',
            'pomogite.co.uk',
            'sadnews.co.uk'
        ]
        ordered = [d for d in priority if d in valid]
        for d in valid:
            if d not in ordered:
                ordered.append(d)

        self.domains = ordered

        # Assign verified fast domains initially
        fast_pool = ordered[:4] if len(ordered) >= 4 else ordered
        self._dc_to_domain = {
            dc_id: fast_pool[i % len(fast_pool)]
            for i, dc_id in enumerate((1, 2, 3, 4, 5, 203))
        }

    def update_domain_for_dc(self, dc_id: int, domain: str) -> bool:
        if self._dc_to_domain.get(dc_id) == domain:
            return False
        
        self._dc_to_domain[dc_id] = domain
        return True

    def get_domains_for_dc(self, dc_id: int) -> Iterator[str]:
        current_domain = self._dc_to_domain.get(dc_id)
        if current_domain is not None:
            yield current_domain

        shuffled_domains = self.domains[:]
        random.shuffle(shuffled_domains)

        for domain in shuffled_domains:
            if domain != current_domain:
                yield domain


balancer = _Balancer()
