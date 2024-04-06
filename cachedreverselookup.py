import socket


class CachedReverseLookup:
    # Current results that have been tried
    cache = {}

    # Resolver tries this cycle
    resolver_count = 0

    def __init__(self) -> None:
        pass

    def reset_count(self) -> None:
        self.resolver_count = 0

    #
    # convert an IP address to a host by either using the cache or
    # doing a lookup and adding it to the cache
    def lookup(self, ip_address: str) -> str:
        if ip_address in self.cache:
            return self.cache[ip_address]
        if self.resolver_count < 10:
            self.resolver_count += 1
            try:
                host = socket.gethostbyaddr(ip_address)
                self.cache[ip_address] = host[0]
            except:
                self.cache[ip_address] = ip_address
            return self.cache[ip_address]
        else:
            return ip_address
