# Known issues

Defects and rough edges that are understood but not yet fixed, with whatever
workaround there is. These are things that should eventually change, as
distinct from the deliberate design tradeoffs in
[known limitations](operations.md#known-limitations), which are not expected to.

## `config --init` cannot create a file named by `--config`

`cheesecloth config --init` creates `/etc/cheesecloth/config.yaml` when it is
not there, but fails if `--config` names a file that does not exist yet:

```
$ cheesecloth config --init --config /etc/cheesecloth/homelab.yaml
cheesecloth: error: open /etc/cheesecloth/homelab.yaml: no such file or directory
```

The configuration file is read while the command line is being parsed, long
before the command itself runs, and a file named explicitly is required to be
there while the default path is tolerated when absent. So the failure comes
from reading the file, not from writing it, and `--init` never gets the chance
to create the one it was asked for.

Create the file first, and `--init` will then write the section into it:

```
$ install -m 0644 /dev/null /etc/cheesecloth/homelab.yaml
$ cheesecloth config --init --config /etc/cheesecloth/homelab.yaml
```

Alternatively, `cheesecloth config` prints the same section it would have
written, so it can be redirected wherever it is wanted. Name the interface, so
that the settings on the command line are the ones printed:

```
$ cheesecloth config --interface wghomelab --overlay-net 10.42.0.0/24 > /etc/cheesecloth/homelab.yaml
```

Fixing this means reading the path in the command rather than leaving it to the
argument parser, which is worth doing but has not been done.
