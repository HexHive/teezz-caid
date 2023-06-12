from dataclasses import dataclass
import subprocess


@dataclass
class Executable:
    full_name: str
    name: str
    path: str

    def contains_string(self, path, s):
        """Returns `True` if file `path` contains string `s`,
        `False` otherwise."""
        cmd = "strings {} | grep {}".format(path, s)
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        if out:
            return True
        return False


@dataclass
class Elf(Executable):

    @staticmethod
    def parse_elf(path: str):
        full_name = path
        name = full_name.split("/")[-1]
        path = path
        return Elf(full_name, name, path)

    def get_needed_libraries(self, elf_dir: str):
        deps = []
        cmd = 'readelf -d {} | grep "(NEEDED)"'.format(elf_dir +
                                                       self.full_name)
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        out = out.decode().splitlines()
        deps = list(map(lambda d: d[d.find("[") + 1: d.find("]")], out))
        return deps

    def contains_dynamic_symbol(self, elf_dir: str, symbol_name: str):
        """Returns `True` if `symbol_name` is part of the `.dynsym` symbol
        table of `ELF` file under `path`,  `False` otherwise."""
        elf_dir = elf_dir if elf_dir[-1] == "/" else elf_dir + "/"
        cmd = f'readelf --dyn-syms {elf_dir + self.full_name} | grep "{symbol_name}"'
        # if `grep` matches anything, the symbol is present
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        if out.decode():
            return True
        return False


@dataclass
class Vdex(Executable):
    @staticmethod
    def parse_from_string(string: str):
        full_name = string
        name = full_name.split("/")[-1]
        path = "/".join(full_name.split("/")[:-1])
        return Vdex(full_name, name, path)
