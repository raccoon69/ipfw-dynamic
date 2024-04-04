import subprocess
import time
import socket
import curses
from curses import wrapper
from _operator import attrgetter
from rules import Rules
from cachedreverselookup import CachedReverseLookup


def read_ipfw_state() -> list:
    results = []
    ipfw_out = subprocess.run(['/sbin/ipfw', '-D', 'show'], capture_output=True, text=True)
    for line in ipfw_out.stdout.splitlines():
        r = Rules(line)
        if r._valid:
            results.append(r)
    return results


def main(stdscr, *args):
    cache = CachedReverseLookup()
    stdscr.timeout(5)
    while True:
        results = read_ipfw_state()

        # sort the results
        results.sort(key=attrgetter('_bytes'), reverse=True)

        for result in results:
            try:
                result._src_port = socket.getservbyport(int(result._src_port_number), result._protocol)
            except:
                pass
            try:
                result._dest_port = socket.getservbyport(int(result._dest_port_number), result._protocol)
            except:
                pass
            result._src_name = cache.lookup(result._src_ip)
            result._dest_name = cache.lookup(result._dest_ip)

        stdscr.erase()

        ip_width = int((curses.COLS - 35) / 2)
        stdscr.addstr(0, 0, 'Rule')
        stdscr.addstr(0, 8, 'Source')
        stdscr.addstr(0, ip_width + 1 + 8, 'Destination')
        stdscr.addstr(0, curses.COLS - 25, 'Protocol')
        stdscr.addstr(0, curses.COLS - 12, 'Size')
        for screen_line in range(2, curses.LINES):
            if screen_line - 2 >= len(results):
                break
            result = results[screen_line - 2]
            stdscr.addstr(screen_line, 0, result._rule_no)
            stdscr.addstr(screen_line, 8, result.get_limited_host_and_port(result._src_name, result._src_port, ip_width))
            stdscr.addstr(screen_line, ip_width + 1 + 8, result.get_limited_host_and_port(result._dest_name, result._dest_port, ip_width))
            stdscr.addstr(screen_line, curses.COLS - 25, result._protocol)
            stdscr.addstr(screen_line, curses.COLS - 12, result.get_readable_bytes(6))
        stdscr.hline(1, 0, '=', curses.COLS)
        stdscr.refresh()
        for _ in range(0, 2000):
            time.sleep(0.0001)
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                return


curses.wrapper(main)
