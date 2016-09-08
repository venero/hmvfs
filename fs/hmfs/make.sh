#!/bin/bash
ln -fs Makefile.goku Makefile
make -C /usr/src/linux-headers-3.11.0-15-generic
ln -sf Makefile.kernel Makefile
