import logging
import multiprocessing
import os
import subprocess
from enum import Enum
from dataclasses import dataclass
from functools import reduce

################################################################################
# LOCAL MODULES
################################################################################

from adb import adb
from . import ExecutableInterface
from .ExecutableInterface import Elf
from .ExecutableInterface import Vdex

################################################################################
# GLOBALS
################################################################################

class NodeType(Enum):
    DIRECTORY = 0
    FILE = 1


Executable = ExecutableInterface.Executable
NodeType = NodeType

# use multiple processes
MP = True

SKIP_DIRS = ["sys", "proc", "dev", "sdcard", "storage", "cache", ".magisk"]
FILTERS = [
    "/data/local/tmp",
    "/sbin/.magisk",
    "/data/dalvik-cache",
]

################################################################################
# TYPING
################################################################################

from typing import List, Sequence

################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

################################################################################
# CODE
################################################################################

@dataclass
class FileExtractor:
    work_dir: str
    device_id: str
    new_elfs_dir: str

    NCORES = multiprocessing.cpu_count()

    def collect_vdex_files(self):
        log.info("Collecting VDEX files")

        directories = self.list_nodes("/", self.device_id)

        with multiprocessing.Pool(FileExtractor.NCORES) as p:
            new_vdexs = p.map(
                self._collect_vdex_files_in_directory, directories)
        return reduce(lambda a, b: a + b, new_vdexs)

    def collect_elf_files(self):
        """Crawl file system and return list of all ELF binaries."""
        log.info("Collecting ELF files")
        directories = self.list_nodes("/", self.device_id)
        start_value: list[Elf] = []
        new_elfs = []
        if MP:
            with multiprocessing.Pool(FileExtractor.NCORES) as p:
                new_elfs = list(
                    p.map(self._collect_elf_files_in_directory, directories))
        else:
            for d in directories:
                __elfs = self._collect_elf_files_in_directory(d)
                new_elfs.extend(__elfs)
                log.debug(f"dir {__elfs}")
        return reduce(lambda a, b: a + b, new_elfs, start_value)

    def _collect_vdex_files_in_directory(self, directory: str) -> List[Vdex]:
        def check_filter(vdex: Vdex):
            for fp in FILTERS:
                if fp in vdex.full_name:
                    return False
            return True

        if directory.replace("/", "") in SKIP_DIRS:
            log.debug(f"Skipping {directory}")
            return []
        node = self.get_node_type(directory, self.device_id)
        if node != NodeType.DIRECTORY:
            return []
        res = self.get_vdex_in_directory(directory, self.device_id)
        res = list(filter(check_filter, res))
        log.debug(f"Got {len(res)} vdexs from {directory}")
        if len(res) > 0:
            self.pull_files(res)
            log.debug(f"Finished pulling from {directory}")
        return res

    def collect_vdex_files_local(self):
        log.debug("Collecting Vdex files locally")
        print(self.new_elfs_dir)
        p = subprocess.Popen(
            f"find {self.new_elfs_dir} -type f -iname '*.vdex'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate()
        if stderr != b"":
            log.error("Collecting VDEX files failed:\n{}".format(stderr))
            return None
        strings = map(lambda e: e.replace(self.new_elfs_dir, ""),
                      stdout.decode().splitlines())
        elf_files = list(
            map(lambda e: Vdex.parse_from_string(e), strings))
        log.debug("Found {} Vdexs".format(len(elf_files)))
        return elf_files

    def collect_elf_files_local(self):
        """Collect ELFs from a directory on this machine."""

        log.debug("Collecting ELF files locally")
        p = subprocess.Popen(
            f"find {self.new_elfs_dir} -type f -exec file {{}} \; | grep 'ELF'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate()
        if stderr != b"":
            log.error("Collecting ELF files failed:\n{}".format(stderr))
            return None
        strings = map(lambda e: e.replace(self.new_elfs_dir, ""),
                      stdout.decode().splitlines())
        elf_files = list(
            map(lambda e: Elf.parse_elf(e.split(":")[0]), strings))
        log.debug("Found {} ELFs".format(len(elf_files)))
        return elf_files

    def _collect_elf_files_in_directory(self, directory: str):
        log.debug(f"dir {directory}")

        if directory.replace("/", "") in SKIP_DIRS:
            log.debug(f"Skipping {directory}")
            return []

        node = self.get_node_type(directory, self.device_id)
        if node != NodeType.DIRECTORY:
            log.debug(f"Not a dir: {directory}")
            return []

        res = self.get_elf_in_directory(directory, self.device_id)
        log.debug(f"Got {len(res)} elfs from {directory}")
        if len(res) > 0:
            self.pull_files(res)
            log.debug(f"Finished pulling from {directory}")
        return res

    def _pull_files_helper(self, file: Executable):
        """adb.pull `elf` from target to `dir_` on host.
        keep directory layout from target and just use `dir_` as root."""
        # elf path is absolute path -> don't need additional '/'
        if file.full_name.startswith("/"):
            # handle absolute paths
            path = os.path.join(self.new_elfs_dir, file.full_name[1:])
        else:
            # handle relative paths
            path = os.path.join(self.new_elfs_dir, file.full_name)
        # skip pulling if it already exists
        if not os.path.exists(path):
            os.system("mkdir -p {}".format(os.path.dirname(path)))
            adb.pull_privileged(file.full_name, path, self.device_id)

    def pull_files(self, files: Sequence[Executable]):
        """Pull all files from phone to local machine for dependency checks."""
        if not os.path.exists(self.new_elfs_dir):
            os.system(f"mkdir -p {self.new_elfs_dir}")
        for file in files:
            self._pull_files_helper(file)

    @staticmethod
    def get_node_type(path, device_id) -> NodeType:
        command = f"stat {path}"
        out, err = adb.execute_privileged_command(command, device_id)
        out = out.split(b"\n")
        if len(out) > 2:
            if b"directory" in out[1]:
                return NodeType.DIRECTORY
            else:
                return NodeType.FILE
        assert False, f"Error: `stat` returned {out} and {err}"

    @staticmethod
    def list_nodes(path, device_id) -> List[str]:
        dirs, _ = adb.execute_privileged_command(
            f"ls {path}", device_id)
        new_path = path + "/" if path[-1] != "/" else path
        return list(map(lambda d: f"{new_path}{d}", dirs.decode().split()))

    @staticmethod
    def get_elf_in_directory(path, device_id) -> List[Elf]:
        cmd = f"for node in `find {path} -type f`; do echo -n \"$node: \"; dd if=$node bs=1 count=4 2>/dev/null | grep -q 'ELF'; echo $?; done"
        files, _ = adb.execute_privileged_command(cmd, device_id)
        elf_paths = [f.split(b": ")[0].decode() for f in files.splitlines() if b": " in f and f.split(b": ")[1] == b"0"]
        elf_paths = [elf_path for elf_path in elf_paths if ".magisk" not in elf_path]
        return list(map(lambda l: Elf.parse_elf(l), elf_paths))

    @staticmethod
    def get_vdex_in_directory(path, device_id) -> List[Vdex]:
        cmd = f'find {path} -type f -iname "*.?dex"'
        out, _ = adb.execute_privileged_command(cmd, device_id)
        return list(map(lambda l: Vdex.parse_from_string(l), out.decode().splitlines()))


