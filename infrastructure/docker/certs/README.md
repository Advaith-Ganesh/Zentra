# Extra CA certificates

Drop any additional trusted root certificates here as `.crt` files (PEM
encoded). Both Docker images install everything in this directory into the
system trust store at build time and at runtime.

This exists for environments that terminate TLS on an inspecting proxy — common
in corporate networks and in some CI runners — where package installs and
outbound provider calls would otherwise fail certificate verification.

The directory is empty by default and the step is a no-op when nothing is here.
Never disable certificate verification instead of using this.
