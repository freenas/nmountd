nmountd
=======

** New NFS Mount Daemon for FreeBSD et al **

nmountd is mostly a rewrite of the existing mountd code.
It's considerably more verbose, not as efficient as the original version;
on the other hand, it's been modified with at least one feature the
old version did not have.

**FEATURES**

The main feature this has over the original code is the ability to specify
an alternate name for an export.  As an example

```
/tank/public=/public -maproot=nobody:nobody -network 192.168.0.0/24
/tank/src=/src -maproot=root:wheel -network 192.168.100.0/24
/tank/src=/src -maproot=nobody:nobody
```

exports `/tank/public` as `/public` (that is, one would use `mount
-t nfs server:/public /public`).  Similarly for `/tank/src`, which is
mounted differently for `192.168.100.0/24` than for every other address.

**BUGS**

Too many to really list.  This is not yet a complete implementation, it
is still under very active development, and the internal data structures or
even file formats may change at any time.
