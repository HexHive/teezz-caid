"""Crawl whole file system and build dependency tree for given library. """
import subprocess
import logging
import os
import json
import tempfile
import multiprocessing
from dataclasses import dataclass
from enum import Enum

################################################################################
# LOCAL MODULES
################################################################################

from adb import adb
from . import FileExtractor as fe
from .ExecutableInterface import Elf
from .ExecutableInterface import Vdex

################################################################################
# TYPING
################################################################################

from typing import List, Dict, Tuple, Optional

################################################################################
# GLOBALS
################################################################################

ELF_JSON_FNAME = "elfs.json"
VDEX_JSON_FNAME = "vdexs.json"
NCORES = multiprocessing.cpu_count()

FileExtractor = fe.FileExtractor

################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

################################################################################
# CODE
################################################################################

class Tools(Enum):
    GREP = 0
    GREP_R = 1
    READELF = 2


@dataclass
class DependencyFinder:
    target_lib: str
    device_id: str
    work_dir: str
    elf_dir: str
    elf_json: Optional[str]
    source_dir: str
    platform: str
    vdex_json: str

    def _get_find_dep_command(self, tool: Tools, path, dep):
        if tool == Tools.GREP:
            return 'grep -a "{}" {}'.format(dep, path)
        elif tool == Tools.GREP_R:
            return 'grep -r "{}" {}'.format(dep, path)
        elif tool == Tools.READELF:
            return "readelf --dyn-syms -W {} | grep {}".format(path, dep)
        assert False, "Your soul is lost."

    @staticmethod
    def _execute_command(cmd: str):
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        return out.decode()

    @staticmethod
    def _execute_command_binary(cmd: str) -> bytes:
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        return out

    def _build_dependency_graph_helper_elf(self, elf: Elf, elf_files: List[Elf]):
        """Return list of ELF binaries needed by the given ELF."""
        deps = elf.get_needed_libraries(self.elf_dir)
        hw_get_mod = elf.contains_dynamic_symbol(self.elf_dir, "hw_get_module")
        dlopen = elf.contains_dynamic_symbol(self.elf_dir, "dlopen@LIBC (3)")

        to_check = list(
            filter(lambda d: d.name not in deps and d.name != elf.name, elf_files)
        )
        if dlopen or hw_get_mod:
            for file in to_check:
                names = []
                if hw_get_mod:
                    if f".{self.platform}.so" in file.full_name:
                        names.append(file.name)
                if dlopen:
                    if file.name.endswith(".so"):
                        names.append(file.name)
                for n in names:
                    if elf.contains_string(self.elf_dir, n):
                        deps.append(n)

        path = self.elf_dir + elf.full_name
        cmd = self._get_find_dep_command(Tools.READELF, path, "getService")
        out = DependencyFinder._execute_command(cmd).splitlines()

        mangled_names = []
        for mangled_name in out:
            if " UND " in mangled_name:
                mangled_name = mangled_name.split("UND ")[1][:-1]
                mangled_names.append(mangled_name)

        for mangled_name in mangled_names:
            cmd = "c++filt -n {}".format(mangled_name)
            l = self._execute_command(cmd)
            if len(l) == 0:
                continue
            else:
                demangled = l
                if demangled == mangled_name:
                    log.info("Demangling {} unsuccessful".format(demangled))
                else:
                    # find version and name of the service
                    splitted = demangled.split("::")
                    base_name = None
                    version = None
                    for i in range(len(splitted)):
                        if splitted[i].startswith("I"):
                            (base_name, version) = splitted[i - 2: i]
                            break
                    if version is None or base_name is None:
                        continue
                    version = version[1:].replace("_", ".")
                    ver_string = version + "-impl.so"
                    # some services have '-service' and '-impl.so',
                    # others only have '.so'
                    candidates = [
                        c for c in elf_files if base_name in c.full_name]
                    candidates_imp = [
                        c for c in candidates if ver_string in c.full_name
                    ]
                    if len(candidates_imp) == 0:
                        ver_string = version + ".so"
                        candidates = [
                            c for c in candidates if ver_string in c.full_name
                        ]
                    else:
                        candidates = candidates_imp
                    if len(candidates) > 1:
                        # distinguish between 32 and 64 bit elfs
                        cmd = "file {}/{}".format(self.elf_dir, elf.full_name)
                        out = self._execute_command(cmd)
                        if not out:
                            log.error(
                                f"file failed, cannot determine arch {cmd}")
                            return deps
                        else:
                            l = out
                            if "64-bit" in l:
                                candidates = [
                                    c
                                    for c in candidates
                                    if "64" in os.path.split(c.full_name)[0]
                                ]
                            else:
                                candidates = [
                                    c
                                    for c in candidates
                                    if not "64" in os.path.split(c.full_name)[0]
                                ]
                            if len(candidates) > 1:
                                candidates_tmp = [
                                    c
                                    for c in candidates
                                    if c.full_name.startswith("/system")
                                ]
                                if len(candidates_tmp) == 0:
                                    candidates = candidates[:1]
                                else:
                                    candidates = candidates_tmp
                    elif len(candidates) == 0:
                        continue
                    if len(candidates) == 1:
                        deps.append(candidates[0].full_name)
        return deps

    def _build_dependency_graph_helper_vdex(
        self, vdex: Vdex, elf_files: List[Elf]
    ) -> List[str]:
        """Return list of ELF binaries needed by the given VDEX."""

        if vdex.full_name.endswith(".vdex"):
            vdex_path = "{}{}".format(self.elf_dir, vdex.full_name)
            vdex_path = vdex_path.replace("//", "/")
            # extract dex file
            vdex_dir = os.path.split(vdex_path)[0]
            dex_name = os.path.basename(vdex.full_name)[:-5] + "_classes.dex"
            dex_path = os.path.join(vdex_dir, dex_name)
            if not os.path.exists(dex_path):
                extract_dex = f"vdexExtractor --input={vdex_path}"
                extract_dex += f" --output={vdex_dir} --deps --dis"
                out = self._execute_command_binary(extract_dex)
                error = False
                for l in out.splitlines():
                    if l.startswith(b"[ERROR]"):
                        if not error:
                            log.error(f"Extraction of dex for {vdex_path} failed")
                            log.error(f"{extract_dex} \n {l}")
                        error = True
                if error:
                    return []
        else:
            dex_path = vdex.full_name
        # decompile dex file
        output_path = os.path.join(self.source_dir, vdex.full_name[1:])
        # assume, decompilation has already been performed, if directory exists
        if not os.path.exists(output_path):
            os.system("mkdir -p {}".format(output_path))
            decomp = f"jadx --fs-case-sensitive -d {output_path} {dex_path}"
            _ = self._execute_command(decomp)

        # check java source files for getHw...Service()
        deps = []
        services = [s for s in elf_files if s.full_name.endswith("-service")]
        cmd_dep = self._get_find_dep_command(
            Tools.GREP_R, output_path, "HwServiceFactory.getHw"
        )

        # java -jar baksmali-2.5.2.jar deodex -b /inout/boot.oat /inout/jadx-source/system/priv-app/Settings/oat/arm64/Settings.odex/Settings.odex -o out/Settings

        out = self._execute_command_binary(cmd_dep)
        for l in out.splitlines():
            if b"HwServiceFactory.getHw" in l:
                sp = l.split(b"HwServiceFactory.getHw")
                for s in sp:
                    if b"Service()" in s:
                        base = s.split(b"Service()")[0].lower()
                        candidates = [
                            c for c in services if base.decode() in c.full_name]
                        if len(candidates) == 1:
                            deps.append(candidates[0].full_name)


        # check java source files for System.loadLibrary()
        cmd_dep = self._get_find_dep_command(
            Tools.GREP_R, output_path, "System.loadLibrary("
        )
        jni_libs = [l for l in elf_files if l.full_name.endswith(".so")]
        out = self._execute_command(cmd_dep)
        for l in out.splitlines():
            if 'System.loadLibrary("' in l:
                sp = l.split('System.loadLibrary("')
                sp = sp[1].split('")')[0]
                cand = [c for c in jni_libs if sp in c.full_name]
                if len(cand) > 1:
                    if "arm64" in vdex.full_name:
                        cand = [c for c in cand if "64" in c.full_name]
                    else:
                        cand = [c for c in cand if not "64" in c.full_name]
                    if len(cand) > 1:
                        cand_tmp = [
                            c for c in cand if c.full_name.startswith("/system")
                        ]
                        if len(cand_tmp) > 1:
                            cand = cand_tmp[:1]
                        elif len(cand_tmp) == 0:
                            cand = cand[:1]
                        else:
                            cand = cand_tmp
                    if len(cand) > 0:
                        deps.append(cand[0].full_name)
                elif len(cand) == 1:
                    deps.append(cand[0].full_name)
        return deps

    def _collect_elf_dependencies(self, elf_files: List[Elf]) -> List[Tuple[str, List[str]]]:
        pool = multiprocessing.Pool(NCORES)

        results = []
        for elf in elf_files:
            res = pool.apply_async(
                self._build_dependency_graph_helper_elf,
                (
                    elf,
                    elf_files,
                ),
            )
            results.append((elf, res))
        return [(elf.full_name, res.get()) for elf, res in results]

    def _collect_vdex_dependencies(self, vdex_files: List[Vdex]) -> List[Tuple[str, List[str]]]:
        pool = multiprocessing.Pool(NCORES)

        results = []
        for vdex in vdex_files:
            res = pool.apply_async(
                self._build_dependency_graph_helper_vdex,
                (
                    vdex,
                    vdex_files,
                ),
            )
            results.append((vdex, res))
        return [(vdex.full_name, res.get()) for vdex, res in results]

    def build_dependency_graph(
        self, elf_files: List[Elf], vdex_files: List[Vdex], dep_root: str
    ) -> Dict[str, List[str]]:
        """Collect dependencies for `dep_root`.

        `dep_root` is the index to the `Elf` in `elf_files` we want to collect
        all dependencies for. This function generates a tree-like structure
        containing all `Elf`s and `Vdex`s `dep_root` (potentially) transitively
        needs.

        The result is a dict. `libA.so` and `libB.so` are dependant on
        `libC.so`:

            { "libC.so" : ["libA.so", "libB.so"]}

        Args:
            elf_files (List[Elf]): all `Elf`s considered.
            vdex_files (List[Vdex]): all `Vdex`s considered.
            dep_root (str): index to `elf_files` used as root.

        Returns:
            Dict[str, List[str]]: key is the `Elf`/`Vdex` string representation,
            value is a list of `Elf`/`Vdex` dependent on the key.
        """

        log.info("Building dependency graph")

        dependencies_full = {}

        log.info("ELF dep graph")
        elf_results = self._collect_elf_dependencies(elf_files)

        log.info("VDEX dep graph")
        vdex_results = self._collect_vdex_dependencies(vdex_files)

        results = elf_results + vdex_results

        log.info("Accumulating results 1")
        for elf, deps in results:

            # add `Elf` if it does not exist yet
            if not elf in dependencies_full.keys():
                dependencies_full[elf] = {"to": [], "from": []}


            for dep in deps:
                # find lib in elf_files
                candidates = [c for c in elf_files if dep in c.full_name]

                if len(candidates) == 0:
                    continue

                elif len(candidates) > 1:
                    # distinguish between 32 and 64 bit elfs
                    path = "{}{}".format(self.elf_dir, elf)
                    path = path.replace("//","/")
                    output = subprocess.check_output(["file", path]).decode()

                    if "64-bit" in output:
                        candidates = [
                            c
                            for c in candidates
                            if "64" in os.path.split(c.full_name)[0]
                        ]
                    else:
                        candidates = [
                            c
                            for c in candidates
                            if not "64" in os.path.split(c.full_name)[0]
                        ]

                    candidates_tmp = [
                        c for c in candidates if c.full_name.startswith("/system")
                    ]

                    if len(candidates_tmp) == 0:
                        candidates = candidates[:1]
                    else:
                        candidates = candidates_tmp

                dep_path = candidates[0].full_name

                # add dep in both entries
                dependencies_full[elf]["to"].append(dep_path)
                if dep_path not in dependencies_full.keys():
                    dependencies_full[dep_path] = {"to": [], "from": []}
                dependencies_full[dep_path]["from"].append(elf)

        log.info(f"Accumulting results 2 {len(dependencies_full)}")
        dependencies = {}
        queue = [dep_root]

        log.info(f"len of queue={len(queue)}")
        while len(queue) > 0:
            cur_node = queue.pop(0)
            if "libc.so" in cur_node:
                log.debug("found libc...NOPE")
                continue
            """
            note: not all dependencies in the to-list have to be
            a key in dependencies after this loop!
            """
            dependencies[cur_node] = dependencies_full[cur_node]
            for neighbor in dependencies[cur_node]["from"]:
                if neighbor not in dependencies.keys():
                    queue.append(neighbor)

        log.info("cleanup refs")
        # cleanup to references
        for key in dependencies.keys():
            to_remove = []
            for dep in dependencies[key]["to"]:
                if dep not in dependencies.keys():
                    to_remove.append(dep)
            for rem in to_remove:
                dependencies[key]["to"].remove(rem)

        # visualization only needs from
        deps_for_vis = {}
        for key in dependencies.keys():
            deps_for_vis[key] = dependencies[key]["from"]
        return deps_for_vis

    def create_visualization(self, out_dir: str, dependencies):
        """Create a visualization of the dependency graph."""

        log.info("Creating human readable output")
        out = "digraph DependencyTree {\n"
        for key in dependencies:
            for dep in dependencies[key]:
                out += '  "{}" -> "{}";\n'.format(dep, key)
        out += "}"


        deps_dot = os.path.join(out_dir, "deps.dot")
        with open(deps_dot, "w+") as f:
            f.write(out)

        deps_flat_dot = os.path.join(out_dir, "deps_flat.dot")
        unflatten = subprocess.Popen(
            f"unflatten -l 30 -f -o {deps_flat_dot} {deps_dot}",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )

        deps_png = os.path.join(out_dir, "deps.png")
        stdout, stderr = unflatten.communicate()
        dot = subprocess.Popen(
            ["dot", "-Tpng", deps_flat_dot, f"-o{deps_png}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = dot.communicate()
        dot.wait()
        if stdout != b"" or stderr != b"":
            log.debug("Creating graph failed:\n{}\n{}".format(stdout, stderr))

    def main(self):

        if self.work_dir is None:
            self.work_dir = tempfile.mkdtemp(prefix="teezz_")

        if self.elf_dir is None:
            self.new_elfs_dir = os.path.join(self.work_dir, "elfs")

        if self.source_dir is None:
            self.source_dir = os.path.join(self.work_dir, "jadx-source")

        log.info(f"Working directory is {self.work_dir}")

        if self.platform is None:
            self.platform = adb.execute_command("getprop ro.product.platform", self.device_id)

        target = self.elf_dir if self.elf_dir else self.new_elfs_dir
        file_extractor = FileExtractor(self.work_dir, self.device_id, target)

        vdex_files = None
        elf_files = None

        if self.elf_dir is not None:
            elf_files = file_extractor.collect_elf_files_local()
            vdex_files = file_extractor.collect_vdex_files_local()
        else:
            dest = os.path.join(self.work_dir, ELF_JSON_FNAME)
            if not self.elf_json:
                elf_files = file_extractor.collect_elf_files()
                with open(dest, "w") as f:
                    json.dump(elf_files, f, default=lambda x: x.__dict__)
            else:
                with open(dest, "r") as f:
                    elf_files = json.load(f, object_hook=lambda e: Elf(**e))
                    log.debug(f"Loaded {len(elf_files)} files")

        vdex_files = None
        if vdex_files is None:
            dest = os.path.join(self.work_dir, VDEX_JSON_FNAME)
            if not self.vdex_json:
                vdex_files = file_extractor.collect_vdex_files()
                with open(dest, "w") as f:
                    json.dump(vdex_files, f, default=lambda x: x.__dict__)
            else:
                with open(dest, "r") as f:
                    vdex_files = json.load(f, object_hook=lambda v: Vdex(**v))
        self.elf_dir = self.new_elfs_dir if self.elf_dir is None else self.elf_dir
        self.elf_dir = self.elf_dir if self.elf_dir[-1] == "/" else self.elf_dir + "/"

        for idx in range(len(elf_files)-1, 0, -1):
            if ".magisk" in elf_files[idx].full_name:
                del elf_files[idx]

        if elf_files:
            dependencies = self.build_dependency_graph(
                elf_files,
                vdex_files,
                self.target_lib,
            )
            self.create_visualization(self.work_dir, dependencies)
