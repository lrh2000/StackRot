# Exploiting StackRot (CVE-2023-3269)

[![GitHub CI](https://github.com/lrh2000/StackRot/actions/workflows/ci.yml/badge.svg)][ci]

 [ci]: https://github.com/lrh2000/StackRot/actions

This contains a Proof of Concept (PoC) exploit for the StackRot bug. For a
detailed explanation of the vulnerability and a walkthrough of how this exploit
was developed, please refer to [this](/).

The exploit specifically targets Linux kernel version 6.1.25. It is primarily
used to acquire root privileges and escape sandboxes in the Google kCTF VRP
challenge. The kernel image and the kernel configuration can be found
[here](/env).

The successful execution of the exploit, resulting in the acquisition of root
privileges, is verified by the [GitHub CI][ci], which runs the exploit within
QEMU using the specified kernel images.

## Building and running the exploit

To build the exploit, execute the following command:
```
make
```

Given that QEMU is installed, the exploit can be tested with:
```
make run
```
If KVM is unavailable, substitute the previous command with:
```
make run KVM=
```

The most straightforward way to understand how this exploit operates without
having to set up a local environment is by reviewing the GitHub CI pass
procedure, which can be found [here][ci].

## Contributing

While it's unlikely that many will be interested in contributing code to a PoC
exploit, the contribution guidelines are still presented here.

Please ensure that the contributed code adheres to the proper formatting
standards. This can be achieved by executing:
```
make fmt
```

To verify that the code conforms to the specified formatting, execute:
```
make check
```

## Notes

Currently, the exploit implementation considers a two-CPU situation and
therefore assumes 16 as the number of maple nodes per slab, where the latter
value depends on the number of CPUs. This means that the exploit will not work
out of the box if the number of CPUs is not two. However, by adjusting a few
parameters, it should not be difficult to get the exploit to work on any number
of CPUs greater than one.
