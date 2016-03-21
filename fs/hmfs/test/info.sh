#!/bin/bash

hmfs_debug_dir=/sys/kernel/debug/hmfs/1258291200/info
echo "$1" > ${hmfs_debug_dir} & cat ${hmfs_debug_dir}