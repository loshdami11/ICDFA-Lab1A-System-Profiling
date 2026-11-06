# ICDFA-Lab-System-Profiling

DIGITAL FORENSIC SYSTEM PROFILING AND DISK INSPECTION REPORT
Course Title: ICDFA Digital Forensics Fundamentals
Lab Assignment: Lab  system identification, partition inspection and  file system profiling
STUDENT INDENTIFICATION
FULL NAME : ADEOTI SULIAT ADEDAMOLA
REGISTRATION NUMBER : C11/26/FCDF/17179 


Part A - System Identification and Evidence Layer Mapping



A1. Capture basic system specification
![image](https://github.com/user-attachments/assets/e8ccadca-16b0-4060-8056-0452d2b40f73)






2. ![image](https://github.com/user-attachments/assets/6e16aeee-21e3-4d1d-8bfb-abb66b90ad92)



A2. Capture storage information


![image](https://github.com/user-attachments/assets/f3aae157-9de1-4d82-a718-78ddc6ec8a8f)




A3. Map evidence sources to system layers

### A3. Map Evidence Sources to System Layers

| Layer / Source | Example Evidence | Where It May Be Found | Why It Matters |
| :--- | :--- | :--- | :--- |
| **User Layer** | Recent files, searched terms, typed credentials, shell history | User profiles, browser profiles (`AppData`), bash history, recent shortcuts (`.lnk` files) | Directly links human intent and specific user actions to system execution. |
| **Application Layer** | Office document metadata, browser cache, chat logs, database files | `%AppData%`, `%LocalAppData%`, app databases (`SQLite`), application logs | Identifies specific software tools used to process, store, or transmit data. |
| **OS Layer** | Event logs, installed programs, user account activity, autorun keys | Windows Event Viewer (`.evtx`), Registry hives (`SYSTEM`, `SOFTWARE`, `SAM`), `/var/log` | Establishes execution timelines, service startup state, and user login/logoff events. |
| **Disk Layer** | Deleted files, file fragments, partition tables, unallocated space | MBR/GPT headers, Master File Table (`$MFT`), unallocated disk clusters, slack space | Enables data recovery, deleted artifact extraction, and volume structure reconstruction. |
| **Memory / Process Layer** | Running malware, process ID lists, active network sockets, injected code | Volatile RAM dumps, pagefile (`pagefile.sys`), hibernation files (`hiberfil.sys`) | Captures live system state, decrypted payload data, active network connections, and unbacked process memory. |



User Action (User Layer): A user downloads and opens a malicious executable via a web browser.


Application Processing (Application Layer): The web browser logs the URL download history and saves the file to disk.


OS Execution (OS Layer): Windows launches the executable under a specific process ID (PID) updates user registry artifacts  and generates process execution event logs (Event ID 4688).


Disk Modification (Disk Layer): The file system updates the Master File Table with file creation timestamps and attributes).


RAM Allocation (Memory Layer): The executable resides in volatile memory, maintaining active network connections to a command-and-control server.




Part B - Program, Process and Thread Investigation
B1. Process Observation and System Profiling 

### B1. Process Analysis Table

| Process Name | Process ID (PID) | User Name / Context | Likely Purpose & System Role |
| :--- | :--- | :--- | :--- |
| **`lsass.exe`** | **`1228`** | `NT AUTHORITY\SYSTEM` | **Local Security Authority Subsystem Service:** Manages security policy, handles user logins, processes password changes and creates access tokens. |
| **`services.exe`** | **`1176`** | `NT AUTHORITY\SYSTEM` | **Service Control Manager:** Starts, stops and manages background Windows services and drivers. |
| **`smss.exe`** | **`716`** | `NT AUTHORITY\SYSTEM` | **Session Manager Subsystem:** Creates user sessions, initializes environment variables, and launches core system processes |





Difference between program, Process and Thread
Program: A passive file stored on the hard drive containing software code (like a recipe written in a cookbook sitting on a shelf). It uses no memory or CPU power until you double click it.


Process: An active, running instance of a program loaded into computer memory (RAM) with its own unique Process ID (PID) and assigned system resources (like actually cooking the recipe in the kitchen). 


Thread: A small individual sub-task running inside a process (like individual cooks in the kitchen working on different parts of the meal simultaneously, such as chopping vegetables while boiling water). 


Why Process Information Matters in Malware Analysis and  Live Forensics
Catches Hidden/Disguised Malware: Attackers often mask malicious programs using real system names e.g naming a fake file svchost.exe  Checking the PID, file path and parent process reveals if a system process is legitimate


Spots Unauthorized Behavior (Process Lineage): Looking at which process launched another e.g a Word document or web browser suddenly spawning cmd.exe/ powershell.exe  alerts examiners to initial exploitation. 


Captures Volatile Live Data: Malware running only in RAM (fileless malware), dynamic encryption keys and active network connections to attacker servers vanish as soon as the computer shuts down. Inspecting running processes captures this evidence while the system is still live. 


### C2. Calculate Your Own Disk or Partition Size

#### Documented Partition Parameters (From Terminal Output)

| Parameter | Partition 1 (EFI / System) | Partition 3 (Main OS / C: Drive) |
| :--- | :--- | :--- |
| **Drive Letter** | None (Reserved) | **C:** |
| **Offset (Bytes)** | `1,048,576` | `122,683,392` |
| **Start Sector ($\text{Offset} \div 512$)** | **2,048** | **239,616** |
| **Size (Bytes)** | `104,857,600` | `510,698,455,040` |
| **Number of Sectors ($\text{Size} \div 512$)** | **204,800 sectors** | **997,457,920 sectors** |
| **Bytes per Sector** | **512 bytes** | **512 bytes** |




Step by step calculations

1. Partition 1 (System Reserved Partition)
Sector Count (N): 104,857,600512=204 800 sectors
Calculate Total Bytes:


TotalBytes = 204,800512=104,857,600bytes
Convert Bytes to Kilobytes (KB):



KB=104,857,6001,024=102,400KB


Convert Kilobytes to Megabytes (MB):


MB = 102,4001,024= 100MB
Convert Megabytes to Gigabytes (GB):


GB=1001,024=0.0977GB


2. Partition 3 (C: Drive Volume)

Sector Count (N): 510,698,455,040512 = 997,457,920sectors


Calculate Total Bytes:


TotalBytes = 997,457,920512=510,698,455,040bytes

Convert Bytes to Kilobytes (KB):


KB = 510,698,455,0401,024 = 498,728,960KB

Convert Kilobytes to Megabytes (MB):


MB = 498,728,9601,024=487,039.999MB 

Convert Megabytes to Gigabytes (GB):


GB = 487,039.9991,024 = 475.625GB





Part D - Safe Partition Table Inspection 

D1. Windows DiskPart Safe Inspection Log

1. Command Execution Log

   ![image](https://github.com/user-attachments/assets/27ec35b7-e2b0-46b5-979d-045e164895d2)



   







D2. Kali method - read-only inspection

  

 ![image](https://github.com/user-attachments/assets/1618a0f3-7cb4-4b28-945b-0bb9de1676a9)







Part E - MBR, GPT, and Boot Process Explanation


### E1. The PC Boot Process

| Stage Number & Name | What Happens | Forensic Relevance |
| :---: | :--- | :--- |
| **1. Power-On & POST** | Firmware performs hardware diagnostics and initializes RAM. | Hardware failure or physical tampering may affect evidence access. |
| **2. BIOS / UEFI Initialization** | Reads non-volatile configuration settings (NVRAM/CMOS) and determines boot device order. | Boot mode and drive order explain partition style and boot artifacts. |
| **3. MBR / GPT & EFI Boot Records Execution** | System accesses the partition layout and locates the EFI Boot Partition (ESP) or sector 0 boot code. | Boot records may contain evidence of hidden partitions or boot tampering. |
| **4. Boot Loader / Manager Execution** | `bootmgr` / `winload.efi` (Windows) or `GRUB` (Linux) runs, loading basic drivers and selecting the target OS. | May show multi-boot options, custom boot parameters, or hidden OS behavior. |
| **5. Kernel Loading & OS Handover** | Operating system kernel (`ntoskrnl.exe` or `vmlinuz`) takes control, initializes system services, and displays login prompt. | Marks the point where volatile RAM artifacts and system activity logs begin accumulating. |




E2. Comprehensive Comparison: MBR vs. GPT

### E2. Comprehensive Comparison: MBR vs. GPT

| Feature | Master Boot Record (MBR) | GUID Partition Table (GPT) |
| :--- | :--- | :--- |
| **Age & Architecture** | Legacy partitioning architecture developed in the early 1980s for IBM PC-DOS systems. | Modern partitioning standard introduced as part of the Unified Extensible Firmware Interface (UEFI) specification. |
| **Disk Size Limitation** | Limited to addressing 32-bit logical block addresses, restricting maximum disk size to 2 TB (with standard 512-byte sectors). | Uses 64-bit logical block addressing, supporting disk capacities up to 9.4 ZB (Zettabytes) or $9.4 \times 10^{21}$ bytes. |
| **Partition Table Storage** | Stored entirely within a single 512-byte sector at Sector 0 (LBA 0), along with initial executable bootstrap code. | Stored across multiple reserved sectors. Uses a Primary GPT Header at LBA 1 and partition array entries from LBA 2–33. |
| **Redundancy and Recovery** | **No redundancy.** Contains only a single copy of the partition table. Damage to Sector 0 renders the partition layout unreadable without manual structure rebuilding. | **Built-in redundancy.** Maintains a duplicate Backup GPT Header and partition entry array at the very end of the physical disk for validation and automated recovery. |
| **Partition Support** | Supports up to 4 Primary Partitions (or 3 Primary Partitions + 1 Extended Partition containing logical drives). | Standard Windows implementation supports up to 128 Primary Partitions natively without requiring extended partition structures. |
| **Integrity Verification** | Uses no internal integrity checks; corrupt entries are processed until execution fails. | Employs Cyclic Redundancy Check (CRC32) checksums within both primary and backup headers to detect metadata corruption immediately. |
| **Forensic Assessment** | Critical single point of failure in Sector 0; prone to overwrite by bootkit malware, destructive wipers or bad sectors. | Highly resilient. Forensic recovery tools can parse the secondary/backup header at the end of the disk if primary headers are destroyed or timestomped. |



Part F - File System Identification and Interpretation
F1. File System Identification Across Systems
Based on the forensic evidence collected during the Windows host inspection and the Kali Linux virtual machine analysis:
EFI System Partition (Partition 1): Uses FAT32. Formatted for universal compatibility with UEFI firmware to execute boot loaders.
Primary System Volume (C: Drive - Partition 3): Uses NTFS. Stores OS core files, user directories, and system metadata.
Recovery Partition (Partition 4): Uses NTFS. Contains Windows Recovery Environment (WinRE) compressed recovery images.
2. Target Machine 2: Kali Linux VM
Root Partition (/dev/sda1): Uses ext4. Standard Linux journaled file system storing system executables, /var/log system logs
and user home profiles.
Live Installation ISO (/dev/sr0): Uses iso9660. Read-only optical disk format for live boot images.

F2. Forensic Reference Guide for File Systems

### F2. Forensic Reference Guide for File Systems

| File System | Common OS / Usage | Architectural Features | Forensic Importance Value |
| :--- | :--- | :--- | :--- |
| **FAT / FAT32** | Removable media (USB drives, SD cards) and UEFI system partitions (`ESP`). | File Allocation Table structure; non-journaled; uses 8.3 short filename conventions alongside LFN (Long File Name) entries. | **Simple structure:** Lack of complex journaling makes recovery of unallocated slack space straightforward, but provides limited metadata |
| **NTFS** | Modern Windows operating system drives (volume). | Master File Table file journaling Alternate Data Streams Volume Shadow Copies | **Rich metadata source:** Stores complete MACB timestamps (Modified, Accessed, Created, MFT Changed), permission security identifiers (SIDs), transaction logs for timeline reconstruction historical shadow copies. |
| **ext Family (ext2/ext3/ext4)** | Linux distributions (Kali, Ubuntu, Debian, RHEL). | Inode table structures, indirect blocks/extents, system journaling superblock backup copies. | **Inode-based metadata:** Inodes maintain file ownership (UID/GID), file attributes, modification times, and data block pointers, providing structured artifact mapping for Linux timeline analysis. |
| **XFS / btrfs / JFS** | Enterprise Linux servers, NAS storage, advanced Linux work environments. | Copy-on-Write (CoW) allocation, integrated volume snapshots, dynamic inode creation. | **Advanced recovery dynamics:** Snapshot features preserve deleted data versions, but Copy-on-Write metadata allocation complicates traditional undelete operations and cluster carving. |
| **HFS+ / APFS** | macOS devices and Apple storage media. | Catalog File metadata, extended attributes Apple File System (APFS) space sharing and encryption. | **macOS investigations:** Essential for parsing Apple metadata structures extended attribute quarantine flags tracking internet downloads). |



F3. Forensic Importance of File Systems
File systems are critical in digital forensics because they define how an operating system organizes, names, stores, and retrieves data on physical disk clusters:
Metadata parsing and  evidence recovery: File systems maintain structural indexes e.g the NTFS  or Linux  that preserve critical evidence 
Metadata including file creation/modification dates, file ownership, file permissions, and physical cluster allocations.
Timeline Analysis: File system timestamps allow forensic examiners to reconstruct precise event sequences 
Data Recovery from Unallocated and  Slack Space: When a file is deleted, the file system marks its entries as unallocated without immediately wiping the underlying data blocks. Understanding file system allocation structures enables forensic tools to carve deleted files, recover directory entries and extract file fragments from RAM slack and file slack.


Part G - Final Practical Assignment

### G1. Main Assignment Task Table

| Task | Required Evidence | Student Notes / Answer |
| :--- | :--- | :--- |
| **1. Identify Partition 1** | Screenshot of partition table and command output | **Partition 1 (EFI System Partition)** identified via `Get-Partition` / `DiskPart` on Windows (Disk 0, Partition 1) and `/dev/sda1` on Linux. |
| **2. Record Partition 1 sector count** | Start sector, end sector or sector count | **Windows (Disk 0, Partition 1):**<br>• Start Sector: `2,048`<br>• Size in Bytes: `104,857,600`<br>• Total Sectors ($N$): `204,800 sectors`<br><br>**Linux (/dev/sda1):**<br>• Start Sector: `2,048`<br>• End Sector: `171,966,463`<br>• Total Sectors ($N$): `171,964,416 sectors` |
| **3. Calculate Partition 1 size** | Formula and result in GB | **Windows Partition 1:**<br>$$\text{Bytes} = 204,800 \times 512 = 104,857,600$$<br>$$\text{GB} = \frac{104,857,600}{1024^3} = \mathbf{0.0977 \text{ GB}} \text{ (100 MB)}$$<br><br>**Linux Partition 1 (/dev/sda1):**<br>$$\text{Bytes} = 171,964,416 \times 512 = 88,045,781,000$$<br>$$\text{GB} = \frac{88,045,781,000}{1024^3} = \mathbf{81.999 \text{ GB}} \text{ (82 GB)}$$ |
| **4. Identify Partition 2** | Screenshot of partition table and command output | **Windows Partition 2 (Microsoft Reserved / MSR)** identified via `Get-Partition` / `DiskPart` (Disk 0, Partition 2). |
| **5. Record Partition 2 sector count** | Start sector, end sector or sector count | **Windows (Disk 0, Partition 2):**<br>• Offset: `105,906,176 bytes`<br>• Size in Bytes: `16,777,216`<br>• Start Sector: $105,906,176 \div 512 = \mathbf{206,848}$<br>• Total Sectors ($N$): $16,777,216 \div 512 = \mathbf{32,768 \text{ sectors}}$ |
| **6. Calculate Partition 2 size** | Formula and result in GB | **Windows Partition 2 (MSR):**<br>$$\text{Bytes} = 32,768 \times 512 = 16,777,216$$<br>$$\text{KB} = 16,777,216 \div 1024 = 16,384 \text{ KB}$$<br>$$\text{MB} = 16,384 \div 1024 = 16 \text{ MB}$$<br>$$\text{GB} = 16 \div 1024 = \mathbf{0.0156 \text{ GB}} \text{ (16 MB)}$$ |
| **7. Compare with OS-reported size** | Disk Management, `Get-Volume`, `lsblk`, or `df` output | • **Partition 1 (Windows ESP):** OS reports 100 MB (0.0977 GB calculated vs 100 MB displayed).<br><br>• **Partition 2 (Windows MSR):** OS reports 16 MB (0.0156 GB calculated vs 16 MB displayed).<br><br>• **Linux /dev/sda1:** OS reports 82 GB in `fdisk`/`lsblk` and 81 GB in `df -h`. |
| **8. Explain difference if any** | Short explanation of rounding, reserved space, file system overhead, or GiB/GB differences | Discrepancies between calculated values and OS tools occur due to Decimal ($\text{GB} / 1000^3$) vs. Binary ($\text{GiB} / 1024^3$) unit conversions, file system overhead, and display rounding applied by Disk Management and `df -h`. |







