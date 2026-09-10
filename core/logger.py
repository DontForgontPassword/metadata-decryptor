from colorama import Fore, Style


class Log:
    def __init__(self, tag=None):
        self.tag = tag

    def _p(self, color, msg):
        if self.tag:
            msg = f"[{self.tag}] {msg}"

        print(f"{color}{msg}{Style.RESET_ALL}")

    def info(self, msg):
        self._p(Fore.CYAN, msg)

    def ok(self, msg):
        self._p(Fore.GREEN, msg)

    def warn(self, msg):
        self._p(Fore.YELLOW, msg)

    def highlight(self, msg):
        self._p(Fore.MAGENTA, msg)

    def error(self, msg):
        self._p(Fore.RED, msg)

    def debug(self, msg):
        self._p(Fore.LIGHTBLACK_EX, msg)
