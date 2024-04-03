import re
from typing import List


class Rules:
    '''
    Store all the elements of a reported dynamic ipfw rule with "ipfw -D show"
    '''
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
    METRIC_LABELS: List[str] = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']

    def __init__(self, line: str='') -> None:
        '''
        Intialize and parse a string into its parts
        
        Example string:
         16700      32     10211 (90s) STATE tcp 192.168.128.112 56187 <-> 192.40.81.4 443 :default
        '''

        #
        # Start with default of being not a valid rule
        self._valid = False

        #
        # Compress only one space between each field
        self._line = re.sub("[\s]+", ' ', line.rstrip())

        if 'STATE' in self._line:
            packets = state = arrows = 0

            #
            # state is a local variable because we don't need it
            self._rule_no, packets, rule_bytes, self._ttl, state, self._protocol, self._src_ip, self._src_port, arrows, self._dest_ip, self._dest_port, self._flow = self._line.split(' ')

            #
            # By default make the port number and name the same
            self._src_port_number = self._src_port
            self._dest_port_number = self._dest_port

            #
            # By default make the address number and host name the same
            self._src_name = self._src_ip
            self._dest_name = self._dest_ip

            #
            # Clean up ttl to be ust a number
            self._ttl = re.sub('[s()]', '', self._ttl)

            #
            # Convert to integers
            self._packets = int(packets)
            self._bytes = int(rule_bytes)

            #
            # And mark as valid
            self._valid = True

    def get_readable_bytes(self, max_len: int=-1) -> str:
        # Raw data in bytes
        result = f'{self._bytes}'
        if max_len == -1 or len(result) < max_len:
            return result
        divisions = 0
        num = self._bytes
        while divisions < len(Rules.METRIC_LABELS):
            num = int(num / 1024)
            divisions += 1
            result = f'{num}' + Rules.METRIC_LABELS[divisions]
            if len(result) <= max_len:
                return result
        return result

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
