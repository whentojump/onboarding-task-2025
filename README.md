# Subtask: measure object coverage of Linux kernel

The following steps have been tested with (1) a clean Debian bookworm 64-bit VM
(2) a clean CloudLab c6320 instance.

In principle, the distro, its version, using a physical or virtual machine
should not make too much difference.
One notable requirement though is Python needs to be relatively new so that it
supports `match` statement, composite type hints etc. Python 3.10.12 is known
to work.

## 1. Prepare QEMU and test in user space

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
    -smp 1
    -serial mon:stdio
)
```

Build QEMU and TCG plugin

```shell
mkdir -p $Q_BUILD_DIR

cd /tmp/
git clone https://gitlab.com/whentojump/qemu-play.git --branch tcg-plugin-v6.2.0
mv qemu-play $Q_SRC
cd $Q_SRC

./configure --enable-plugins \
--enable-virtfs \
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
git clone https://github.com/whentojump/onboarding-task-2025.git $SCRIPT_REPO

# Make sure the environment variables are correctly set, qemu binary and plugin can be found
ls $Q_PREFIX/bin/qemu-x86_64
ls $Q_PLUGIN

python3 -m venv $PYTHON_VENV
source $PYTHON_VENV/bin/activate
pip install colorama

cd $SCRIPT_REPO
./tests/test-all.sh
```

## 2. Measure Linux kernel

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
du -sh $KERNEL_DIR/vmlinux.disassembly.txt
```

Prepare the initial RAM disk

```shell
curl -LSs https://github.com/ClangBuiltLinux/boot-utils/releases/download/20230707-182910/x86_64-rootfs.cpio.zst | zstd -d > rootfs.cpio
```

Boot Linux and collect trace

```shell
/usr/bin/time -v $Q_PREFIX/bin/qemu-system-x86_64 \
"${Q_SYSTEM_FLAGS[@]}" \
-d plugin \
-plugin $Q_PLUGIN,kernel=on,addr_lo="0xffffffff81000000",addr_hi="0xffffffff83500000",log_mode=10,buffer_dump_file="$KERNEL_DIR/vmlinux.trace.bin2"

du -sh $KERNEL_DIR/vmlinux.trace.bin2
```

Build the post processing program

```shell
g++ $SCRIPT_REPO/kernel-postprocess.cpp -o $SCRIPT_REPO/kernel-postprocess
```

Post-process and generate object coverage report

```shell
/usr/bin/time -v $SCRIPT_REPO/kernel-postprocess \
$KERNEL_DIR/vmlinux.trace.bin2 \
$KERNEL_DIR/vmlinux.disassembly.txt \
$KERNEL_DIR/vmlinux.report.txt
```

View the report

```shell
less $KERNEL_DIR/vmlinux.report.txt
```
