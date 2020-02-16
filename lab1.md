# lab1

## Q1. Form a group of two and discuss how you can retrieve an image from an currently off-line hard disk in a forensically sound manner Create and describe this method

- Check chain of custody and add current step
- Boot forensic workstation
- Attach hard drive to workstation (should be mounted read-only)
- Obtain hash of hard drive contents
- create image hard drive contents
- remove hard drive
- verify image integrity by comparing hash of image to hash of hard drive

- [module 7](https://www.swgde.org/documents/Current%20Documents/SWGDE%20QAM%20and%20SOP%20Manuals/SWGDE%20Model%20SOP%20for%20Computer%20Forensics)

## Q2. Write a one-line description or note a useful feature for the following tools included in CAINE Guymager Disk Image Mounter dc3dd kpartx

- Guymager: forensic imager for media acquisition
- Disk Image Mounter: image mounter
- dc3dd: patched dd with on the fly hashing
- kpartx: partition mounter

- [guymanager](https://guymager.sourceforge.io/)
- [dc3dd](https://tools.kali.org/forensics/dc3dd)

## Q3. While taking extra care to check and maintain the chain of custody retrieve one of the evidence harddisks and SATA-to-USB interfaces from the lab teachers

- 2020-02-06 14:39:23 +0100 obtain hard disk

## Q4. Follow your method to retrieve the image Please use timestamps explain every tool and note down the version

- 2020-02-06 14:39:23 +0100 obtain hard disk
- 2020-02-06 14:44:13 +0100 start dc3dd if=/dev/sdb hof=/local/disk.img hash=md5 cnt=41943040
- 2020-02-06 14:50:55 +0100 dc3dd completes with matching hash=2112d743d86cc19a1037a48bfc6dbba8
- 2020-02-06 14:52:04 +0100 start psteal
- 2020-02-06 14:53:03 +0100 copy img to server, verify hash still matches
- 2020-02-06 15:54:00 +0100 psteal complete
- 2020-02-06 15:56:23 +0100 copy timeline to server

- dc3dd v=7.2.646
- dd v=8.28
- md5sum v=8..28
- psteal v=20190708

## Q5. Read about CAINE Linux and its features while waiting on the dump to finish

### a. Why would you use a Forensic distribution and what are the main differences between a regular distribution?

A forensic distribution includes commonly used tools in a known good configuration.
It also has default policies that are appropriate to forensic scenarios such as by default mounting all devices as read only.

- https://www.caine-live.net/

### b. When would you use a live environment and when would you use an installed environment?

- An installed environment can be used with a stable workstation to save data between sessions.
- A live environment can be used on a workstation to start from a clean state everytime,
- or when it is not possible to connect hardware to a workstation, a live environment can be run on the existing hardware.

### c. What are the policies of CAINE?

- mounting: by default read only with options: ro,noatime,noexec,nosuid,nodev,noload

- https://www.caine-live.net/page8/page8.html

## Q6. As soon as your dump finishes start a tool to create a timeline on the image You will need this timeline later in the assignment

- psteal --source /local/disk.img -o l2tcsv -w timeline.csv

## Q7. Create and describe a method that enables the verification of your method Write this down in steps that the other team can follow

- check chain of custody of hard drive
- obtain hash of image
- Attach hard drive to workstation (should be mounted read-only)
- Obtain hash of hard drive contents
- check hash of image against hash of hard drive

## Q8. Exchange HDDs and images with another team Verify the procedure that they used and the resulting image Write a small paragraph of max 200 words Write as if you were verifying the evidence gathering procedure for a court case

- 2020-02-06 15:40:05 received hard disk and verified chain of custody
- 2020-02-06 15:45:38 started hash verification dd if=/dev/sdb count=41943040 | sha256sum -b
- 2020-02-06 15:54:00 verified sha256sum=f252f689bd5aadc37ab6b76561dd3a1e84ec4449488ab45d21198e671a0c94d5

On handover for verification, the drive was inspected and matched the descriptions in the chain of of custody document. Following standard forensic procedures, the drive was attached to a forensic workstation and the hash (sha256) of the first 20GiB of the drive was taken. This was verified to match the stated hash of the image produced by the other team.

## Q9. What kind of things would be less important during live acquisition?

- physical verification would be less important as the system is already running
- hash verification in the future would be more difficult as the system is likely mounted read-write and may change

## Q10. What would be different in your method?

- the verification of the physical evidence and chain of custody would be different to accomodate the fact that it is an existing system that should not be interrupted
- connecting the drive to a workstation and physical write blocker and the subsequent mount as read only would not be possible
- instead the system should be remounted read only, a storage drive connected and the imaging run directly

## Q11. Describe the new method that you would use to gather data during live forensics Make sure to categorize by priority Technical analysis

high priority:

- securing the environment, ensuring nothing will disrupt the creation of the image
- ex: people, power, lockouts, kill switches
- remount the system read only

medium priority:

- hash existing disk state
- attach and mount a storage drive to store the resulting image
- clone and verify disk image with hash

## Q12. Mount your image and make sure that it is mounted as read-only

- find offset of partitions: fdisk -lu disk.img

```
Disk disk.img: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xead2b41c

Device     Boot    Start      End  Sectors  Size Id Type
disk.img1  *        2048 29503487 29501440 14.1G 83 Linux
disk.img2       29505534 31455231  1949698  952M  5 Extended
disk.img5       29505536 31455231  1949696  952M 82 Linux swap / Solaris
```

- mount -o loop,ro,offset=1048576 disk.img mount1

## Q13. Identify and write a small paragraph of max 200 words about what kind of image it is Don't go into file specific details just yet This includes but is not limited to

### a. What is the size of the image?

20 GiB

### b. What partition type(s) does this image have?

- 1 ext4 root partition, 14.1GiB
- 1 encrypted swap partition, 952 MiB

/etc/fstab

```
# / was on /dev/sda1 during installation
UUID=b3d19395-7218-4d72-ae5a-e48c2e1ccb1b /               ext4    errors=remount-ro 0       1
# swap was on /dev/sda5 during installation
#UUID=5c6b3c7e-5255-47ce-a64b-c41044d21275 none            swap    sw              0       0
/dev/mapper/cryptswap1 none swap sw 0 0
```

### c. Does it have an MBR/GPT?

MBR

### d. etc

Likely created using a Ubuntu 16.04 installation

ecryptfs in /home/dave

/etc/os-release

```
NAME="Ubuntu"
VERSION="16.04.1 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.1 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=xenial
```

This appears to be an Ubuntu 16.04 installation with 14.1G of hard disk space and 952M of swap. Both swap and the user's home are encrypted, the former with ecryptfs. The drive is partitioned with MBR and appears to originate from a laptop.

## Q14. Using the information from the timeline you create above write a small paragraph on what you think happened on this specific HDD device. Make it a maximum of 300 words and use timestamps

It appears that the current operating system was installed on 01/26/2017 with the sole user directory created at 10:11:59UTC. Some form of acticity was recorded until 02/03/2017,14:00:01,UTC. The system was booted but no other activity recorded on 12/12/2017,10:22:55,UTC. 06/16/2018,10:06:04,UTC the HDD was accessed from a different device with hostname "localhost Terminal" as opposed to the usual "davy" hostname.

- 01/26/2017,10:11:59,UTC: home directory /home/dave created and encrypted
- 01/26/2017,10:13:23,UTC: tor installed
- 01/26/2017,11:59:23,UTC: tor first run?
- 01/26/2017,13:31:53,UTC: luks encrypted partition first open (stor.enc)
- 01/30/2017,13:41:01,UTC: cronjob tested?: /home/dave/init.sh
- 02/03/2017,11:45:02,UTC: cronjob run every minute: /home/dave/init.sh
- 02/03/2017,13:35:09,UTC: password changed for dave
- 02/03/2017,13:50:27,UTC: password changed for dave
- 02/03/2017,14:00:01,UTC: last run of cronjob, last interaction with laptop?
- 12/12/2017,10:22:55,UTC: boot?
- 06/16/2018,10:06:04,UTC: localhost Terminal accessed?

* grep -o 'installed [a-z0-9\-]+' timeline0.csv | sort | uniq
* grep stor.enc timeline0.csv
* grep -o '[a-zA-Z0-9]+@[a-z0-9]+\.[a-z]+' timeline0.csv | sort | uniq
* dave_meknowswhat@protonmail.com, pass XKCDWindmillh@ck

https://help.ubuntu.com/community/EncryptedPrivateDirectory#Recovering%20Your%20Data%20Manually

## Q15. What would help to investigate this evidence further?

- Obtaining the passphrase to encrypted home folder and subsequent access to the encrypted luks partition inside would likely open the door to finding more interesting evidence.

## Q16. OPTIONAL There is much more to find on this HDD than you will have time for during the official lab hours You can turn finding all evidence into a competition with your fellow students or a joint effort where you collectively try to analyse the disk more thoroughly

from /root/.bash_history:

```
cd
ls
cryptsetup -h
passwd dave
cryptsetup luksOpen ~dave/stor.enc encrypted
XKCDWindmillh@ck
exit
```

- obtain password by getting colleague to annoy teacher to no end (I did think to try the password but apparently not with camel case, also not good with selecting wordlists for hashcat)
- sudo ecryptfs-recover-private mount/home/.ecryptfs/dave/.Private
- sudo cryptsetup luksOpen /tmp/ecryptfs.RkH59zR5/ecryptfs/stor.enc encrypted
- sudo mount /dev/mapper/encrypted luks
