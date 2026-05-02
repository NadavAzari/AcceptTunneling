
## Usage
```
~/PortScanner/dist$ ./portstealer-x64 9998 127.0.0.1 9995
[*] target pid  : 216620
[*] target exe  : /usr/bin/socat
[*] GOT[accept] : 0x5f4b810ad8e0
[inject] real accept() @ 0x7c2e4ef10000
[inject] hook page @ 0x7c2e4eed6000
[inject] config @ 0x7c2e4eed6400  remote 127.0.0.1:9995
[inject] GOT[accept] patched → 0x7c2e4eed6000
[+] hook live — connections with magic \xde\xad\xbe\xef will be tunneled to 127.0.0.1:9995

python3 client.py 9994 127.0.0.1 9998

nc localhost 9994

```

## What is it?

Here is a situation from a Red teaming project i do for my mom's company!

Lets say you hacked something which is behind `NAT`, All u have is a forwarded port by the nat which something is already listening on it.
You dont have a route to the `WAN`.
also, netfilter is too old to do `DNAT` action.
This tool gives u simple traffic relay over a stolen session!
Which means u can tunnel over the only open port u have.
For now im supporting `ARM`, `x86` `x64`

## How does it work
I had a cool idea, so i did some micro management for claude and we did figure it out toogether!
First thing is the injector. we need to inject our payload somehow, so i asked for claude to do those next steps:
### Step by step
- First thing u wanna do, is to read from `/proc/net/tcp` to identify which pid is listening on this port?
- After having the PID and process name, lets identify where is the binary located on the filesystem.
- Parse the ELF and find the GOT address for `accept` libc function
- use ptrace to read the GOT address and have the real address of `accept`
- Injecting a `syscall` by overriding `EIP / PC` and calling `mmap` to allocate buffer and get the address of it
- Putting our payload in the returned buffer
- Overriding the `GOT` address of accept to our new payload!

After coding the injection method, we need a payload.
Claude is the real deal, and he coded the payload i asked for in **assembly**
We need something that reads 4 bytes from the socket, if its 
```
\xde\xad\xbe\xef
```
We are using `select()` to tunnel our self to the destination.
If not, we are just returning the `fd` to our caller.


