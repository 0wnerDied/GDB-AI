# Provider Boundary

Built-in provider descriptors report generic GDB, Linux userland, remote,
userland security, and Linux kernel availability. Results name the provider,
version, mechanism, and limitations. Providers use canonical session methods;
they cannot write MI directly or own debugger state.

The trusted Python extension is not a provider runtime. It only fills narrow
GDB Python API gaps and is loaded from an absolute path after SHA-256
verification.
