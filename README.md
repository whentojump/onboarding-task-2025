> [!CAUTION]
>
> For students working on their onboarding task: this document is outdated.
> You are safe to go when this message is gone. If you've reached this step
> and are still seeing this message, please email Wentao. Sorry for the
> inconvenience!

Tested with a clean Debian bookworm 64-bit VM.

One notable requirement is Python needs to be relatively new so that it
supports `match` statement, composite type hints etc. Python 3.10.12 is known
to work.

## User space

Install dependencies

```shell
sudo apt update
sudo apt install git build-essential ninja-build pkg-config libglib2.0-dev \
libpixman-1-dev libcap-ng-dev python3-pip python3-venv
sudo apt install llvm clang
```

Set up environment variables (1): you may modify them to your preferred locations

```shell
export Q_BUILD_DIR=$HOME/qemu-6.2.0-objcov
export SCRIPT_REPO=$HOME/object-coverage
export PYTHON_VENV=$HOME/.venv-objcov
export KERNEL_DIR=$HOME/linux-6.11.7
```

Set up environment variables (2): automatically calculated, do not modify

```shell
export Q_SRC=$Q_BUILD_DIR/src
export Q_PREFIX=$Q_BUILD_DIR/install
export Q_PLUGIN=$Q_SRC/contrib/plugins/libtbexec.so
export Q_SYSTEM_FLAGS=(
    -display none
    -nodefaults
    -M q35
    -d unimp,guest_errors
    -append 'console=ttyS0 earlycon=uart8250,io,0x3f8 nokaslr'
    -kernel $KERNEL_DIR/arch/x86/boot/bzImage
    -initrd $KERNEL_DIR/rootfs.cpio
    -cpu max
    -m 8G
    -smp 1 `# FIXME`
    -serial mon:stdio
)
```

Build QEMU and TCG plugin

```shell
mkdir -p $Q_BUILD_DIR

cd /tmp/
git clone git@gitlab.com:whentojump/qemu-play.git --branch tcg-plugin-v6.2.0
mv qemu-play $Q_SRC
cd $Q_SRC

./configure --enable-plugins \
--enable-virtfs `# For 9P` \
--disable-capstone \
--disable-werror \
--target-list="x86_64-linux-user x86_64-softmmu" \
--prefix=$Q_PREFIX

make -j$(nproc)
make -j$(nproc) install
pushd contrib/plugins
make -j10
popd
```

Run tests

```shell
git clone git@github.com:whentojump/onboarding-task-2025.git $SCRIPT_REPO

# Make sure the environment variables are correctly set, qemu binary and plugin can be found
ls $Q_PREFIX/bin/qemu-x86_64
ls $Q_PLUGIN

python3 -m venv $PYTHON_VENV
source $PYTHON_VENV/bin/activate
pip install colorama

cd $SCRIPT_REPO
./tests/test-all.sh
```

**(Experimental)** binary-encoded trace

```shell
export TRACE_ENCODING=binary
export BRANCH_COVERAGE=0
export DEBUG=1

./tests/test-all.sh

export TRACE_ENCODING=binary2

./tests/test-all.sh
```

## Kernel

Install kernel-specific dependencies:

```shell
sudo apt install flex bison libelf-dev bc libssl-dev curl zstd time
```

Build Linux

```shell
cd /tmp/
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.11.7.tar.xz
tar Jxvf linux-6.11.7.tar.xz
rm linux-6.11.7.tar.xz
mkdir -p $KERNEL_DIR
rm -r $KERNEL_DIR
mv linux-6.11.7 $KERNEL_DIR

cd $KERNEL_DIR
make defconfig
./scripts/config -d CONFIG_WERROR
make olddefconfig
make -j$(nproc)

objdump -d $KERNEL_DIR/vmlinux > $KERNEL_DIR/vmlinux.disassembly.txt
du -sh $KERNEL_DIR/vmlinux.disassembly.txt # ~430M
```

Prepare the initial RAM disk

```shell
curl -LSs https://github.com/ClangBuiltLinux/boot-utils/releases/download/20230707-182910/x86_64-rootfs.cpio.zst | zstd -d > rootfs.cpio
```

(Baseline) Boot Linux and do *not* trace

```shell
/usr/bin/time -v $Q_PREFIX/bin/qemu-system-x86_64 \
"${Q_SYSTEM_FLAGS[@]}"
```

> [!NOTE]
>
> On a CloudLab c6420: peak memory 479MB; run time 0:09.61

Boot Linux and collect trace

> [!WARNING]
>
> Memory-intensive. Typically ~50G.

```shell
/usr/bin/time -v $Q_PREFIX/bin/qemu-system-x86_64 \
"${Q_SYSTEM_FLAGS[@]}" \
-d plugin \
-plugin $Q_PLUGIN,kernel=on,addr_lo="0xffffffff81000000",addr_hi="0xffffffff83500000",log_mode=2,buffer_dump_file="$KERNEL_DIR/vmlinux.trace.txt"

du -sh $KERNEL_DIR/vmlinux.trace.txt
```

> [!NOTE]
>
> On a CloudLab c6420: peak memory 51.68GB; run time 3:32.01; trace size 49G

**(Experimental)** binary-encoded trace

Option differences:

- `log_mode`: `LOG_MODE_BUFFER_IN_MEMORY` -> `LOG_MODE_BUFFER_IN_MEMORY | LOG_MODE_BINARY`
- Output filename: extension `.txt` -> `.bin`

```shell
/usr/bin/time -v $Q_PREFIX/bin/qemu-system-x86_64 \
"${Q_SYSTEM_FLAGS[@]}" \
-d plugin \
-plugin $Q_PLUGIN,kernel=on,addr_lo="0xffffffff81000000",addr_hi="0xffffffff83500000",log_mode=6,buffer_dump_file="$KERNEL_DIR/vmlinux.trace.bin"

du -sh $KERNEL_DIR/vmlinux.trace.bin

/usr/bin/time -v $Q_PREFIX/bin/qemu-system-x86_64 \
"${Q_SYSTEM_FLAGS[@]}" \
-d plugin \
-plugin $Q_PLUGIN,kernel=on,addr_lo="0xffffffff81000000",addr_hi="0xffffffff83500000",log_mode=10,buffer_dump_file="$KERNEL_DIR/vmlinux.trace.bin2"

du -sh $KERNEL_DIR/vmlinux.trace.bin2
```

> [!NOTE]
>
> On a CloudLab c6420:
>
> - Binary encoding scheme 1: peak memory 7.42GB; run time 0:34.84; trace size 6.6G.
> - Binary encoding scheme 2: peak memory 3.11GB; run time 0:27.25; trace size 2.5G.
>
> Compared to text-based trace: the first and last TB are exactly the same; but
> the number of TBs differs, presumably due to kernel nondeterminism.

Post-process trace (WIP)

```shell
n=1000000; < $KERNEL_DIR/vmlinux.trace.txt head -n $n > $KERNEL_DIR/vmlinux-$n.trace.txt

min_address="ffffffff81000000"
max_address=`tail -n1 $KERNEL_DIR/vmlinux.disassembly.txt | cut -d : -f 1`

/usr/bin/time -v \
$SCRIPT_REPO/objcov-kernel.py \
--min-address=$min_address \
--max-address=$max_address \
--output-filename=$KERNEL_DIR/vmlinux-$n.report.txt \
$KERNEL_DIR/vmlinux-$n.trace.txt \
$KERNEL_DIR/vmlinux.disassembly.txt |& tee $KERNEL_DIR/log-$n.txt

less $KERNEL_DIR/vmlinux-$n.report.txt
```
