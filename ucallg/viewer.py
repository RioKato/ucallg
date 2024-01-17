from typing import Callable, Iterator


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

    def view(self, width: int, strip: Callable[[str], str],
             color: Callable[[int], tuple[str, str]]) -> Iterator[str]:
        from csv import reader

        with open(f'/sys/kernel/debug/{self.module}/log') as fd:
            cstks = {}

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
                                args = [(f'{r:#x}', *color(r))
                                        for r in regs]
                                args = [f'{b}{r}{e}' for (r, b, e) in args]
                                args = ','.join(args)
                                name = strip(name)
                                body = f'{name}({args});'

                            case 2:
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

                        yield f'{header} {indent}{body}'

    def dump(self) -> Iterator[str]:
        with open(f'/sys/kernel/debug/{self.module}/log') as fd:
            for line in fd:
                yield line.rstrip()

    def deprecated(self) -> Iterator[str]:
        with open(f'/sys/kernel/debug/{self.module}/deprecated') as fd:
            for line in fd:
                if line:
                    yield line.rstrip()


class ProcMaps:
    END = '\033[0m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'

    def __init__(self, pid: int):
        from re import compile

        maps = {}
        parser = compile(r'([a-f0-9]+)-([a-f0-9]+)' + r'\s+\S+'*4 + r'\s+(.+)')
        with open(f'/proc/{pid}/maps') as fd:
            for line in fd:
                if found := parser.match(line):
                    lower = found.group(1)
                    upper = found.group(2)
                    name = found.group(3)
                    lower = int(lower, 16)
                    upper = int(upper, 16)
                    assert (lower <= upper)

                    if name in maps:
                        lower = min(lower, maps[name][0])
                        upper = max(upper, maps[name][1])

                    maps[name] = (lower, upper)

        colors = []

        heap = '[heap]'
        if heap in maps:
            lower, upper = maps[heap]
            del maps[heap]
            colors.append((lower, upper, ProcMaps.YELLOW))

        stack = '[stack]'
        if stack in maps:
            lower, upper = maps[stack]
            del maps[stack]
            colors.append((lower, upper, ProcMaps.GREEN))

        target = min(maps.items(),
                     default=('', None),
                     key=lambda e: e[1][0])[0]

        if target:
            lower, upper = maps[target]
            del maps[target]
            colors.append((lower, upper, ProcMaps.PURPLE))

        for (lower, upper) in maps.values():
            colors.append((lower, upper, ProcMaps.CYAN))

        self.colors: list[tuple[int, int, str]] = colors

    def color(self, v: int):
        for (lower, upper, color_) in self.colors:
            if lower <= v < upper:
                return (color_, ProcMaps.END)

        return ('', '')
