#!/usr/bin/env python3

import hashlib
import re
import glob
import os
import shutil
import subprocess
import sys
from argparse import ArgumentParser
from pathlib import Path as P

PARSER = ArgumentParser()
PARSER.add_argument('command', choices=['build', 'test'])
PARSER.add_argument('build_dir', type=P)
PARSER.add_argument('src_dir', type=P)
PARSER.add_argument('root_dir', type=P)
PARSER.add_argument('target', choices=['release', 'debug'])
PARSER.add_argument('include')
PARSER.add_argument('extra_env')
PARSER.add_argument('prefix', type=P)
PARSER.add_argument('libdir', type=P)
PARSER.add_argument('--version', default=None)
PARSER.add_argument('--exts', nargs="+", default=[])
PARSER.add_argument('--depfile')


def generate_depfile_for(libfile):
    file_stem = libfile.parent / libfile.stem
    depfile_content = ""
    with open(f"{file_stem}.d", 'r') as depfile:
        for l in depfile.readlines():
            if l.startswith(str(file_stem)):
                output, srcs = l.split(":", maxsplit=2)
                output = re.sub(f"^{file_stem}",
                                f"{opts.build_dir / libfile.stem}", f)

                all_deps = []
                for src in srcs.split(" "):
                    all_deps.append(src)
                    src = P(src)
                    if src.name == 'lib.rs':
                        # `rustc` doesn't take `Cargo.toml` into account
                        # but we need to
                        cargo_toml = src.parent.parent / 'Cargo.toml'
                        if cargo_toml.exists():
                            all_deps.append(str(cargo_toml))

                depfile_content += f"{output}: {' '.join(all_deps)}\n"

    return depfile_content


if __name__ == "__main__":
    opts = PARSER.parse_args()

    logfile = open(opts.root_dir / 'meson-logs' /
                   f'{opts.src_dir.name}-cargo-wrapper.log', 'w')

    print(opts, file=logfile)
    cargo_target_dir = opts.build_dir / 'target'

    env = os.environ.copy()
    env['CARGO_TARGET_DIR'] = str(cargo_target_dir)

    pkg_config_path = env.get('PKG_CONFIG_PATH', '').split(':')
    pkg_config_path.append(str(opts.root_dir / 'meson-uninstalled'))
    env['PKG_CONFIG_PATH'] = ':'.join(pkg_config_path)

    if opts.extra_env:
        for e in opts.extra_env.split(','):
            k, v = e.split(':')
            env[k] = v

    if opts.command == 'build':
        cargo_cmd = ['cargo', 'cbuild']
        if opts.target == 'release':
            cargo_cmd.append('--release')
    elif opts.command == 'test':
        # cargo test
        cargo_cmd = ['cargo', 'ctest', '--no-fail-fast', '--color=always']
    else:
        print("Unknown command:", opts.command, file=logfile)
        sys.exit(1)

    cargo_cmd.extend(['--manifest-path', opts.src_dir / 'Cargo.toml'])
    cargo_cmd.extend(['--prefix', opts.prefix, '--libdir',
                     opts.prefix / opts.libdir])

    def run(cargo_cmd, env):
        try:
            subprocess.run(cargo_cmd, env=env, check=True)
        except subprocess.SubprocessError:
            sys.exit(1)

    for p in opts.include.split(','):
        cargo_cmd.extend(['-p', p])
    run(cargo_cmd, env)

    if opts.command == 'build':
        target_dir = cargo_target_dir / '**' / opts.target

        # Copy so files to build dir
        depfile_content = ""
        for ext in opts.exts:
            for f in glob.glob(str(target_dir / f'*.{ext}'), recursive=True):
                libfile = P(f)

                depfile_content += generate_depfile_for(libfile)

                copied_file = (opts.build_dir / libfile.name)
                try:
                    if copied_file.stat().st_mtime == libfile.stat().st_mtime:
                        print(f"{copied_file} has not changed.", file=logfile)
                        continue
                except FileNotFoundError:
                    pass

                print(f"Copying {copied_file}", file=logfile)
                shutil.copy2(f, opts.build_dir)

        with open(opts.depfile, 'w') as depfile:
            depfile.write(depfile_content)

        # Copy generated pkg-config files
        for f in glob.glob(str(target_dir / '*.pc'), recursive=True):
            shutil.copy(f, opts.build_dir)

        # Move -uninstalled.pc to meson-uninstalled
        uninstalled = opts.build_dir / 'meson-uninstalled'
        os.makedirs(uninstalled, exist_ok=True)

        for f in opts.build_dir.glob('*-uninstalled.pc'):
            # move() does not allow us to update the file so remove it if it already exists
            dest = uninstalled / P(f).name
            if dest.exists():
                dest.unlink()
            shutil.move(f, uninstalled)
