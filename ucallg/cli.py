from typing import BinaryIO, Callable, TextIO


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    subparser_src = subparsers.add_parser('src')
    subparser_src.add_argument('toml')

    subparser_config = subparsers.add_parser('config')
    subparser_config.add_argument('toml')

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
    subparser_view.add_argument('-c', '--color', action='store_true')
    subparser_view.add_argument('-a', '--autoconfig', action='store_true')
    subparser_view.add_argument('-d', '--dump', action='store_true')

    args = parser.parse_args()
    match args.command:
        case 'src':
            src(args.toml)

        case 'config':
            config(args.toml)

        case 'make':
            make(args.module, args.target)

        case 'n2t':
            args.weak = tuple(args.weak) if args.weak else None
            n2t(args.path, args.weak)

        case 'view':
            view(args.module,
                 args.pid, args.load,
                 args.output,
                 args.width, args.strip,
                 args.color,
                 args.autoconfig,
                 args.dump)

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


def config(mod_toml: str):
    from . import Tpl
    from pathlib import Path

    mod_h = Path(mod_toml).with_suffix('.h').name
    mod_ac = Path(mod_toml).with_suffix('.ac').name

    with open(mod_toml, 'rb') as fd:
        libs = toml2libs(fd)

    with open(mod_h, 'w') as fd:
        fd.write(Tpl().config(libs, mod_ac))


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
         width: int, strip: bool,
         color: bool,
         autoconfig: bool,
         dump: bool):
    from . import Viewer, ProcMaps
    from contextlib import suppress
    from atexit import register
    from re import compile

    if load:
        insmod(module)
        register(rmmod, module)

    viewer = Viewer(module)

    maps = None
    if pid:
        viewer.pid(pid)

        if color:
            maps = ProcMaps(pid)

    def custom_strip(s: str) -> str:
        if strip:
            s = compile(r'\(.*\)').sub('', s)
            s = compile(r'<.*>').sub('', s)
            return s
        else:
            return s

    def custom_color(v: int) -> tuple[str, str]:
        if maps:
            return maps.color(v)
        else:
            return ('', '')

    file = None

    if output:
        file = open(output, 'w')

    try:
        with suppress(KeyboardInterrupt):
            if dump:
                lines = viewer.dump()
            else:
                lines = viewer.view(width, custom_strip, custom_color)

            for line in lines:
                print(line)
                if file:
                    print(line, file=file)
    finally:
        if file:
            file.close()

    if autoconfig:
        with open(f'{module}.ac', 'w') as fd:
            for alias in viewer.deprecated():
                fd.write(f'#define URETPROBE_DISABLE_{alias}\n')


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
