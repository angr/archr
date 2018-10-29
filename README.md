# archr

Traditionally, binary analysis has been implicitly _program-centric_, meaning that the atomic unit of concern is the binary being analyzed.
This assumption is usually implicit: `angr.Project` is instantiated with the binary in question, `afl` launches the binary itself, generally hyper-modified to make it easier to fuzz, and so on.

However, outside of the CGC, programs do not exist in a vacuum.
Specific library versions, values in configuration files, environment variables, and a myriad other factors combine with the program binary itself to make a unique whilistic _target_, and in many cases, it is that target that needs to be analyzed, not just the program itself.
This is specifically true for analysis that need extreme accuracy, such as automatic exploit generation.

`archr` is an implementation of such a _target-centric_ analysis paradigm.
It consists of two main concepts: a `Target`, which describes the specification of the target itself, how it is configured, how it will be launched, and how it would be interacted with, and an `Bow`, which specializes this target for specific analysis actions, such as tracing, symbolic execution, and so on.
To accomplish their tasks, Bows might inject Arrows (i.e., the qemu or rr binaries) into the target.

The following `Target`s are planned:

* DockerImageTarget, which is a combination of (a) a docker image, (b) environment variables, (c) command to launch the target with, and (d) endpoint information (network port #, or stdin). Note that all this information can be generated from a dockerfile.
* LocalTarget, which just describes running the target in the local system
* (TODO) probably some qemu stuff

Bows would be able to request certain customizations of the target, such as disabling ASLR, relaxing security policies (for ptrace), etc.
The following Bows are planned:

- MemoryMapBow (will get a memory map, but we probably need more than ldd, because we also need stack and heap)
- AngrBow (can create an angr project with the right libs, and angr states with the right env, args, and fs)
- QEMUTraceBow (does qemu tracing of the target)
- (TODO) SyscallTraceBow (does rr tracing of the target)
- (TODO) AFLBow (launches AFL of the target)
- (TODO) GDBBow (will launch the target with gdbserver, and create an AvatarGDBConcreteTarget connected to it)
