import re
from humanbytes import HumanBytes


class Rule:
    _rule_no = 0
    _packets = 0
    _bytes = 0
    _ttl = 0
    _protocol = ''
    _src_ip = 0
    _src_name = ''
    _src_port = 0
    _src_port_number = 0
    _dest_ip = 0
    _dest_name = ''
    _dest_port = 0
    _dest_port_number = 0
    _flow = ''
    _valid = False

    def __init__(self, line: str='') -> None:
        #
        # 16700      32     10211 (90s) STATE tcp 192.168.128.112 56187 <-> 192.40.81.4 443 :default
        #

        #
        # Start with only one space between each field
        self._line = re.sub("[\s]+", ' ', line.rstrip())
        self._valid = False

        if 'STATE' in self._line:
            packets = state = arrows = 0
            # state is a local variable because we don't need it
            self._rule_no, packets, rule_bytes, self._ttl, state, self._protocol, self._src_ip, self._src_port, arrows, self._dest_ip, self._dest_port, self._flow = self._line.split(' ')

            self._src_port_number = self._src_port
            self._dest_port_number = self._dest_port

            self._src_name = self._src_ip
            self._dest_name = self._dest_ip

            # clean up ttl to be ust a number
            self._ttl = re.sub('[s()]', '', self._ttl)

            self._packets = int(packets)
            self._bytes = int(rule_bytes)

            self._valid = True

    def get_readable_bytes(self) -> str:
        return HumanBytes.format(self._bytes, metric=True, precision=0)

    def get_limited_host_and_port(self, host: str, port: int, max_len: int=-1) -> str:
        # max_len of -1 is for no limit on the length
        if max_len == -1:
            return f'{host},{port}'
        else:
            full_result = f'{host},{port}'
            if len(full_result) <= max_len:
                # the result is already less then the max limit
                return full_result
            else:
                port_str = f',{port}'
                host_str = f'{host}'[0:1 + max_len - len(port_str)]
                return f'{host_str}{port_str}'
