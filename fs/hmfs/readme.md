<h2>Definiton of access, change and modify time in HMFS:</h2>
<ul>
	<li>access: read or write file</li>
	<li>modify: contents of file change</li>
	<li>change: status of file change, such as ino, i_size, etc</li>
</ul>
<h2>Arguments of grub for starting kernel:</h2>
adding 'memmap=2G$4G' to the kernel boot parameters will reserve 2G of memory, starting at 4G. (You may have to escape the $ so it isn't interpreted by GRUB 2, if you use that as your boot loader.)
<h2>Mount command:</h2>
<pre>mount -t hmfs -o physaddr=0x40000000,init=2G,gid=yourgid,uid=youruid none ~/mnt-hmfs</pre>
