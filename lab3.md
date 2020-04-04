## 2 Filesystem

### 9 Read up on EXT2 and its successor EXT4 Write a small paragraph of maximum 400 words answering the following questions

#### a What is ext4’s on-disk layout

#### b How does ext4 use of a log affect your work as a forensic investigator?

ext4 divides its underlying storage into regular sized blocks. These are then placed into groups to implement the filesystem. Each group consists of a superblock, group descriptors, GDT blocks, data bitmap block, inode bitmap block, inode table, and data blocks. These control structures have a redundant copy to recover from corruption. Files and directories are represented as inodes which contain their name, metadata, and pointers to the actual data blocks. ext4 additionally makes use of a journal which by default ensures that file metadata is saved and can be recovered from crashes and incomplete writes. The use of redundant file structures and a log mean more opportunities for recovering data or at least identifiying previously existing files from logs of transactions and metadata.

- https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout

### 10 Detect whether there is an encrypted container on the USB key. This can be done by calculating the entropy

offsets 8670208-49135616 suggest the possibility of a 40MB encrypted container (section with high entropy)

```
arccy@nevers» binwalk -E usbkey.raw

WARNING: Failed to import matplotlib module, visual entropy graphing will be disabled

DECIMAL       HEXADECIMAL     ENTROPY
--------------------------------------------------------------------------------
0             0x0             Falling entropy edge (0.025572)
8670208       0x844C00        Rising entropy edge (0.994581)
9549824       0x91B800        Rising entropy edge (0.996502)
12808192      0xC37000        Rising entropy edge (0.955464)
13033472      0xC6E000        Rising entropy edge (0.960487)
14025728      0xD60400        Rising entropy edge (0.993650)
16291840      0xF89800        Rising entropy edge (0.985669)
16686080      0xFE9C00        Rising entropy edge (0.997077)
25131008      0x17F7800       Falling entropy edge (0.818926)
25447424      0x1844C00       Rising entropy edge (0.995588)
31513600      0x1E0DC00       Rising entropy edge (0.995864)
33554432      0x2000000       Rising entropy edge (0.996959)
37748736      0x2400000       Rising entropy edge (0.995209)
41345024      0x276E000       Rising entropy edge (0.967035)
41682944      0x27C0800       Rising entropy edge (0.990215)
41795584      0x27DC000       Falling entropy edge (0.000000)
42224640      0x2844C00       Rising entropy edge (0.995003)
46137344      0x2C00000       Rising entropy edge (0.990564)
49135616      0x2EDC000       Falling entropy edge (0.477071)
```

### Correction

Compressed images (which this drive contains a lot of) are also sources of high entropy.
The size size of the high entropy block corresponds more or less with the combined size of all the images on disk.
Therefore it is ulikely that this disk contains a large encrypted block.

### 11 Try to find out if something else happened to the filesystem

fdisk / partx doesn't locate any partition tables, kpartx does manage to mount it as a loopback device

extracting with binwalk doesn't yield any extra files compared to mounting the device

- binwalk -e -M usbkey.raw
- `diff <(ls mount/| sort) <(ls _usbkey.raw-1.extracted/ext-root | sort)`

```
arccy@nevers» fdisk -lu usbkey.hdd
Disk usbkey.hdd: 110 MiB, 115343360 bytes, 225280 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

arccy@nevers» file usbkey.hdd
usbkey.hdd: Linux rev 1.0 ext4 filesystem data, UUID=df8d5c63-b78c-4237-b637-6a4f9957e1a7 (needs journal recovery) (extents) (large files) (huge files)

arccy@nevers» binwalk usbkey.hdd

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux EXT filesystem, blocks count: 112640, image size: 115343360, rev 1.0, ext4 filesystem data, UUID=df8d5c63-b78c-4237-b637-6a4f99579957
```

### 12 Write a small paragraph of maximum 200 words about your findings

The usb key (115M) contained an ext4 filesystem with a deleted / non-existent partition table.
The contents of the filesystem were a random collection of images (jpg), most with mangled filenames.
Scanning by entropy indicated the possibility of an encrypted / compressed volume within the usb key.
