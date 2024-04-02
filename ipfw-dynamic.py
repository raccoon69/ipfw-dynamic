from rule import Rule
from cachedreverselookup import CachedReverseLookup
import socket
from _operator import attrgetter
import curses
from curses import wrapper
# from pip._vendor.rich import screen


def read_ipfw_state(file: str) -> list:
    results = []
    with open(file) as rules:
        for line in rules:
            r = Rule(line)
            if r.valid:
                results.append(r)
    return results


def main(stdscr, *args):
    cache = CachedReverseLookup()
    count = 1
    while True:
        filename = 'ipfw-show{}.txt'.format(count)
        results = read_ipfw_state(filename)

        # sort the results
        results.sort(key=attrgetter('bytes'), reverse=True)

        for result in results:
            try:
                result.src_port = socket.getservbyport(int(result.src_port_number), result.protocol)
            except:
                pass
            try:
                result.dest_port = socket.getservbyport(int(result.dest_port_number), result.protocol)
            except:
                pass
            result.src_name = cache.lookup(result.src_ip)
            result.dest_name = cache.lookup(result.dest_ip)

        results.sort(key=attrgetter('bytes'), reverse=True)

        stdscr.erase()
        divider = '=' * curses.COLS
        stdscr.addstr(1, 0, divider)

        ip_width = int((curses.COLS - 35) / 2)
        for screen_line in range(2, curses.LINES):
            stdscr.addstr(0, 0, 'Rule')
            stdscr.addstr(0, 8, 'Source')
            stdscr.addstr(0, ip_width + 1 + 8, 'Destination')
            stdscr.addstr(0, curses.COLS - 25, 'Protocol')
            stdscr.addstr(0, curses.COLS - 12, 'Size')
            result = results[screen_line - 2]
            stdscr.addstr(screen_line, 0, result.rule_no)
            stdscr.addstr(screen_line, 8, result.get_limited_host_and_port(result.src_name, result.src_port, ip_width))
            stdscr.addstr(screen_line, ip_width + 1 + 8, result.get_limited_host_and_port(result.dest_name, result.dest_port, ip_width))
            stdscr.addstr(screen_line, curses.COLS - 25, result.protocol)
            stdscr.addstr(screen_line, curses.COLS - 12, result.get_readable_bytes())
        stdscr.refresh()
        stdscr.getch()
        count += 1
        if count > 3:
            return


curses.wrapper(main)
