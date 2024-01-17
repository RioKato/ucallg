from typing import Self


class Tpl:
    def __init__(self):
        from jinja2 import Environment, FileSystemLoader
        from pathlib import Path
        from random import randint

        loader = FileSystemLoader(Path(__file__).parent)
        env = Environment(loader=loader)
        env.lstrip_blocks = True
        env.trim_blocks = True
        env.globals.update({'rand': randint})

        self.env: Environment = env

    def uprobe(self, libs: dict[str, dict[int, str]], config: str) -> str:
        from re import compile, MULTILINE

        comment = compile(r'^//.*$\n?', MULTILINE)
        tpl = self.env.get_template('uprobe.tpl')
        src = tpl.render(libs=Name.map(libs), config=config)
        src = comment.sub('', src)
        return src

    def config(self, libs: dict[str, dict[int, str]], autoconfig: str) -> str:
        tpl = self.env.get_template('config.tpl')
        return tpl.render(libs=Name.map(libs), autoconfig=autoconfig)

    def makefile(self, module: str, target: str) -> str:
        tpl = self.env.get_template('Makefile.tpl')
        return tpl.render(module=module, target=target)


class Name:
    @classmethod
    def map(cls, src: dict[str, dict[int, str]]) -> dict[str, dict[int, Self]]:
        dst = {}
        for path, funs in src.items():
            if path not in dst:
                dst[path] = {}

            for offset, name in funs.items():
                dst[path][offset] = cls(path, offset, name)

        return dst

    def __init__(self, path: str, offset: int, name: str):
        from hashlib import md5

        data = b''
        data += f'{path}'.encode()
        data += b'\x00'
        data += offset.to_bytes(4)
        alias = md5(data).hexdigest()

        self.real: str = name
        self.alias: str = alias
