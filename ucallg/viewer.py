from typing import Callable, TextIO


class CallStack:
    def __init__(self, dummy: str):
        self.stack: list[str] = []
        self.dummy: str = dummy

    def push(self, val: str):
        self.stack.append(val)

    def pop(self) -> str:
        if self.stack:
            return self.stack.pop(-1)
        else:
            return self.dummy

    def adjust(self, depth: int):
        while len(self.stack) < depth:
            self.push(self.dummy)

        while len(self.stack) > depth:
            self.pop()

    def call(self, name: str, depth: int):
        self.adjust(depth)
        self.push(name)

    def ret(self, depth: int) -> str:
        self.adjust(depth + 1)
        return self.pop()


class Viewer:
    def __init__(self, module: str):
        self.module: str = module

    def pid(self, pid: int):
        with open(f'/sys/kernel/debug/{self.module}/pid', 'w') as fd:
            fd.write(f'{pid}')

    def view(self, fds: list[TextIO],
             width: int, strip: Callable[[str], str], uniq: bool,
             color: Callable[[int], tuple[str, str]]):
        from contextlib import suppress
        from csv import reader

        with open(f'/sys/kernel/debug/{self.module}/log') as fd:
            with suppress(KeyboardInterrupt):
                cstks = {}
                callpass = {}
                retpass = {}

                for row in reader(fd):
                    match row:
                        case [pid, name, kind, depth, ip, *regs]:
                            pid = int(pid, 0)
                            kind = int(kind, 0)
                            depth = int(depth, 0)
                            assert (depth >= 0)
                            ip = int(ip, 0)
                            regs = [int(r, 0) for r in regs]

                            if pid not in cstks:
                                cstks[pid] = CallStack('')

                            if uniq:
                                if pid not in callpass:
                                    callpass[pid] = set()

                                if pid not in retpass:
                                    retpass[pid] = set()

                            begin, end = color(ip)
                            header = f'{pid} {begin}{ip:#018x}{end}|'
                            indent = ' ' * width * depth

                            match kind:
                                case 0:
                                    cstks[pid].call(name, depth)
                                    args = [(f'{r:#x}', *color(r))
                                            for r in regs]
                                    args = [f'{b}{r}{e}' for (r, b, e) in args]
                                    args = ','.join(args)
                                    name = strip(name)
                                    body = f'{name}({args}) {{'

                                case 1:
                                    ret = [(f'{r:#x}', *color(r))
                                           for r in regs]
                                    ret = [f'{b}{r}{e}' for (r, b, e) in ret]
                                    ret = ','.join(ret)

                                    if cstks[pid].ret(depth) == name:
                                        comment = ''
                                    else:
                                        name = strip(name)
                                        comment = f' // {name}'

                                    if ret:
                                        body = f'}} = {ret}{comment}'
                                    else:
                                        body = '}}{comment}'

                                case _:
                                    body = 'unknown format'

                            if uniq:
                                match kind:
                                    case 0:
                                        if ip in callpass[pid]:
                                            continue

                                        callpass[pid].add(ip)
                                    case 1:
                                        if ip in retpass[pid]:
                                            continue

                                        retpass[pid].add(ip)

                            line = f'{header} {indent}{body}'

                            for fd in fds:
                                print(line, file=fd)
