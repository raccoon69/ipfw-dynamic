from humanbytes import HumanBytes
import re
from queue import Full

class Rule:
    rule_no = 0
    packets = 0
    bytes = 0
    ttl = 0
    protocol = ''
    src_ip = 0
    src_name = ''
    src_port = 0
    src_port_number = 0
    dest_ip = 0
    dest_name = ''
    dest_port = 0
    dest_port_number = 0
    flow = ''
    valid = False
    
    def __init__(self, line: str='') -> None:
        #
        # 16700      32     10211 (90s) STATE tcp 192.168.128.112 56187 <-> 192.40.81.4 443 :default
        #
        
        #
        # Start with only one space between each field
        self.line = re.sub("[\s]+", ' ', line.rstrip())
        self.valid = False
        
        if 'STATE' in self.line:
            # state is a local variable because we don't need it
            self.rule_no, packets, bytes, self.ttl, state, self.protocol, self.src_ip, self.src_port, arrows, self.dest_ip, self.dest_port, self.flow = self.line.split(' ')
            
            self.src_port_number = self.src_port
            self.dest_port_number = self.dest_port
            
            self.src_name = self.src_ip
            self.dest_name = self.dest_ip
            
            # clean up ttl to be ust a number
            self.ttl = re.sub('[s()]', '', self.ttl)
            
            self.packets = int(packets)
            self.bytes = int(bytes)
            
            self.valid = True
            
    def get_readable_bytes(self) -> str:
        return HumanBytes.format(self.bytes, metric=True, precision=0)

    def get_limited_host_and_port(self, host: str, port: int, max_len: int=-1) -> str:
        # max_len of -1 is for no limit on the length
        if max_len == -1:
            return '{},{}'.format(host, port)
        else:
            full_result = '{},{}'.format(host, port)
            if len(full_result) <= max_len:
                # the result is already less then the max limit
                return full_result
            else:
                host_str = '{}'.format(host)
                port_str = ',{}'.format(port)
                return '{}{}'.format(host_str[0:1+max_len-len(port_str)], port_str)