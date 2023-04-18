import curses
import logging

from .global_state import GlobalState

l = logging.Logger(__name__)

def filln(msg, n):
    msg = str(msg)
    if len(msg) > n:
        return f" ... {msg[-(n - 6):]} "  
    else:
        return msg.center(n)

class UI:
    
    def __init__(self, global_state: GlobalState):
        self._global_state = global_state
        self._columns = []
        
        self.stdscr = curses.initscr()
        self.stdscr.keypad(True)
        curses.noecho()
        curses.cbreak()
        
        self._add_columns(("pid", 10),
                          ("input", 60),
                          ("time", 10, " s"),
                          ("misuses found", 15))
        
    def _add_line(self, line):
        self.stdscr.addstr(line + "\n")
        
    def _add_column(self, name, width, suffix=""):
        self._columns.append((name, width, suffix))
        
    def _add_columns(self, *columns):
        for column in columns:
            self._add_column(*column)
        
    def _add_row(self, *contents, use_suffix=True):
        assert len(self._columns) == len(contents)
        line = "|"
        for content, (name, width, suffix) in zip(contents, self._columns):
            line += f"{filln(str(content) + (suffix if use_suffix else ''), width)}|"
        self._add_line(line)
        
    def refresh(self):
        try:
            self.stdscr.clear()
            self._add_row(*(column[0] for column in self._columns), use_suffix=False)
            for pid in self._global_state.task_states:
                task_state = self._global_state.task_states[pid]
                self._add_row(pid, task_state.filename, task_state.running_time, 
                                task_state.report.num_misuses)
            self.stdscr.refresh()
        except curses.error:
            l.error("Something went wrong when refreshing terminal UI")
                
    def close(self):
        self.stdscr.keypad(False)
        curses.nocbreak()
        curses.echo()
        curses.endwin()