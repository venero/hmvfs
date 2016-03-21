#!/usr/bin/python3
from os.path import expanduser


home = expanduser('~')
file_list = []
for i in range(2048):
    with open(home + "/mount_hmfs/orphan_{:d}.txt".format(i), 'w') as file:
        file_list.append(file)
        file.write("ssssssssssssssssssss")

#hold files
while True:
    pass
