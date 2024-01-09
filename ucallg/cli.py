from typing import BinaryIO, Callable, TextIO


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    subparser_src = subparsers.add_parser('src')
    subparser_src.add_argument('toml')

    subparser_conf = subparsers.add_parser('conf')
    subparser_conf.add_argument('toml')

    subparser_cno = subparsers.add_parser('cno')
    subparser_cno.add_argument('toml')

    subparser_make = subparsers.add_parser('make')
    subparser_make.add_argument('module')
    subparser_make.add_argument('target')

    subparser_n2t = subparsers.add_parser('n2t')
    subparser_n2t.add_argument('path')
    subparser_n2t.add_argument(
        '-w', '--weak',
        nargs=2, type=lambda s: int(s, 0),
        metavar=('OFFSET', 'SIZE'))

    subparser_view = subparsers.add_parser('view')
    subparser_view.add_argument('module')
    subparser_view.add_argument('-p', '--pid', type=int)
    subparser_view.add_argument('-l', '--load', action='store_true')
    subparser_view.add_argument('-o', '--output')
    subparser_view.add_argument('-w', '--width', type=int, default=2)
    subparser_view.add_argument('-s', '--strip', action='store_true')
    subparser_view.add_argument('-u', '--uniq', action='store_true')
    subparser_view.add_argument('-c', '--color', action='store_true')

    args = parser.parse_args()
    match args.command:
        case 'src':
            src(args.toml)

        case 'conf':
            conf(args.toml)

        case 'cno':
            cno(args.toml)

        case 'make':
            make(args.module, args.target)

        case 'n2t':
            args.weak = tuple(args.weak) if args.weak else None
            n2t(args.path, args.weak)

        case 'view':
            view(args.module,
                 args.pid, args.load,
                 args.output,
                 args.width, args.strip, args.uniq,
                 args.color)

        case _:
            parser.print_usage()


def src(mod_toml: str):
    from . import Tpl
    from pathlib import Path

    mod_c = Path(mod_toml).with_suffix('.c').name
    mod_h = Path(mod_toml).with_suffix('.h').name

    with open(mod_toml, 'rb') as fd:
        libs = toml2libs(fd)

    with open(mod_c, 'w') as fd:
        fd.write(Tpl().uprobe(libs, mod_h))


def conf(mod_toml: str):
    from . import Tpl
    from pathlib import Path

    mod_h = Path(mod_toml).with_suffix('.h').name

    with open(mod_toml, 'rb') as fd:
        libs = toml2libs(fd)

    with open(mod_h, 'w') as fd:
        fd.write(Tpl().conf(libs))


def cno(mod_toml: str):
    from pathlib import Path

    mod_cno = Path(mod_toml).with_suffix('.cno').name

    with open(mod_toml, 'rb') as fd:
        libs = toml2libs(fd)

    with open(mod_cno, 'w') as fd:
        fd.write(f'{len(libs)}')


def make(module: str, target: str):
    from . import Tpl

    with open('Makefile', 'w') as fd:
        fd.write(Tpl().makefile(module, target))


def n2t(path: str, text: tuple[int, int] | None):
    from sys import stdin, stdout

    def intext(offset: int):
        if text:
            return text[0] <= offset < text[0] + text[1]
        else:
            return False

    libs = nm2libs(stdin, path, intext)
    libs2toml(stdout, libs)


def view(module: str,
         pid: int, load: bool,
         output: str,
         width: int, strip: bool, uniq: bool,
         color: bool):
    from . import Viewer
    from atexit import register
    from sys import stdout
    from re import compile

    if load:
        insmod(module)
        register(rmmod, module)

    viewer = Viewer(module)

    if pid:
        viewer.pid(pid)

    def custom_strip(s: str) -> str:
        if strip:
            s = compile(r'\(.*\)').sub('', s)
            s = compile(r'<.*>').sub('', s)
            return s
        else:
            return s

    def custom_color(v: int) -> tuple[str, str]:
        if color:
            END = '\033[0m'
            RED = '\033[31m'
            PURPLE = '\033[35m'
            GREEN = '\033[32m'

            # 0x0000000000400000
            if (v >> 20) == 0x04:
                return (RED, END)

            # 0x00007f0000000000
            if (v >> 40) == 0x7f:
                return (GREEN, END)

            # 0x0000500000000000
            if (v >> 44) == 0x05:
                return (PURPLE, END)

        return ('', '')

    fds = [stdout]

    if output:
        fds.append(open(output, 'w'))

    try:
        viewer.view(fds, width, custom_strip, uniq, custom_color)
    finally:
        for fd in fds[1:]:
            fd.close()


def toml2libs(toml: BinaryIO) -> dict[str, dict[int, str]]:
    from tomllib import load

    libs = {}
    for path, funs in load(toml).items():
        libs[path] = {}

        for offset, name in funs.items():
            offset = int(offset, 0)
            libs[path][offset] = name

    return libs


def nm2libs(nm: TextIO, path: str, intext: Callable[[int], bool]) -> dict[str, dict[int, str]]:
    from re import compile

    libs = {}
    lib = {}
    libs[path] = lib

    sym = compile(r'([0-9a-f]+)\s+([tTvVwW])\s+(.+)')

    for line in nm:
        if found := sym.match(line):
            offset, kind, name = found.groups()
            offset = int(offset, 16)

            if kind in 'vVwW':
                if not intext(offset):
                    continue

            if offset not in lib or len(lib[offset]) > len(name):
                lib[offset] = name
    return libs


def libs2toml(toml: TextIO, libs: dict[str, dict[int, str]]):
    def sanitize(s: str) -> str:
        table = {
            '\\': '\\\\',
            '"': '\\"',
            '\b': '\\b',
            '\t': '\\t',
            '\n': '\\n',
            '\f': '\\f',
            '\r': '\\r',
        }

        table = str.maketrans(table)
        return s.translate(table)

    for path, lib in libs.items():
        path = sanitize(path)
        print(f'["{path}"]', file=toml)

        for offset, name in lib.items():
            name = sanitize(name)
            print(f'{offset:#x} = "{name}"', file=toml)

        print('', file=toml)


def insmod(module: str):
    from subprocess import run
    run(['insmod', f'{module}.ko'])


def rmmod(module: str):
    from subprocess import run
    run(['rmmod', module])


if __name__ == '__main__':
    main()
