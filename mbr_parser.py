#  MBR Analyser, Volume and First Deleted File Information
#  Module: Computer Forensics (ET4027)
#  Author: Solon Yukio Shibata Meira
#  ID: 15047199
######

from _struct import unpack

#  ------------------- MBR Analyser Methods -------------------#

#  get_mbr(): Opens the file (disk image) given as argument. Reads and returns its first 512 bytes (MBR)
def get_mbr(file):
    with open(file, 'rb') as f:
        f = open(file, 'rb')
        contents = f.read(512)
        f.close()
        return contents

'''
get_pte: Receives the file (disk image) and the number of the desired partition table entry.
The partition table entry number is translated to its equivalent hexadecimal value.
So, the function seeks for such offset and gets the PTE.
'''


def get_pte(file, n_pte):
    offset = {1: "1BE", 2: "1CE", 3: "1DE", 4: "1EE"}
    with open(file, 'rb') as f:
        f.seek(int(offset[n_pte], 16))
        contents = f.readline(16)
        f.close()
    return contents

'''
print_info():
Prints all the required information:
        . Partition Type (see get_type function);
        . Initial Sector
        . Size of partition

    The "unpack" function is used to convert the byte string into a tuple,
according to the given format.
    This tuple is converted into a list, so it can be passed through the
get_type function.
    Both the initial sector and the size of partition, are acquired by using the
unpack function in a slice of the PTE, passed as an argument to the function.

    The size of the partition is given in sectors by the PTE and printed in bytes
(number of sectors * 512)

    The function returns the number of sectors, so it can be used to calculate
the number of partitions, since if the partition has zero sectors, it doesn't
exist.

get_type(): Receives an integer as argument, and, according to the dictionary structure 'type',
assigns this number to one of the partition types, returning it.
'''


def print_info(file_array):
    def get_type(num):
        type = {
            0: "Unknown or empty",
            1: "12-bit FAT",
            4: "16-bit FAT (<32MB)",
            5: "Extended MS-DOS Partition",
            6: "FAT-16 (32MB to 2GB)",
            7: "NTFS",
            11: "FAT-32 (CHS)",
            12: "FAT-32 (LBA)",
            14: "FAT-16 (LBA)"
        }
        type_conv = type[num]
        return type_conv

    tmp = unpack("<B", file_array[4])
    type = get_type(tmp[0])
    firstSectorAddress = unpack("<L", file_array[8:12])
    numSectors = unpack("<L", file_array[12:])

    print "Partition Type: \t", type
    print "Initial Sector: \t", firstSectorAddress[0]
    print "Size of partition: \t", 512*numSectors[0], "bytes"

    return numSectors[0]

''' 
get_first_sector_address(): Receives the same array as the print_info() function, and returns the
first sector address for the partition in question.  
'''


def get_first_sector_address(file_array):
    firstSectorAddress = unpack("<L", file_array[8:12])

    return firstSectorAddress[0]

#  -------------------- Volume Information Methods -------------------#

'''
volume_boot_sector(): Receives the partition initial sector (decimal) and the disk image as arguments.
                      It opens the disk image file and returns the VBS (First 512 bytes from the partition
                      offset.
'''


def volume_boot_sector(partition_offset, file):

    # Getting the Volume's Boot Sector
    with open(file, 'rb') as f:
        f.seek(partition_offset*512)  # Converting sectors to bytes
        vbs = f.readline(512)
        f.close()
    return vbs


#  get_n_sectors_per_cluster(): Receives the VBR as an string of bytes and returns the number of sectors per cluster.
def get_n_sectors_per_cluster(vbr):
    tmp = unpack("<B", vbr[13])
    return tmp[0]


#  get_size_reserved_area(): Receives the VBR and returns the size of the reserved area in sectors.
def get_size_reserved_area(vbr):
    tmp = unpack("<H", vbr[14:16])
    return tmp[0]


#  get_fat_area(): Receives the VBR and returns the size of the FAT area in sectors.
def get_fat_area(vbr):
    fat_copies = unpack("<B", vbr[16])
    fat_area = unpack("<H", vbr[22:24])
    return fat_area[0] * fat_copies[0]


#  get_size_root_dir(): Receives the VBR and returns the size of the Root Directory in sectors.
def get_size_root_dir(vbr):
    tmp = unpack("<H", vbr[17:19])
    return tmp[0]*32/512


'''
get_root_directory(): Receives the initial sector of the desired partition's root directory and the disk image file as
                      argument. Calculates the root directory offset (bytes) using the above declared functions, and
                      returning the root directory as an array of bytes.
'''


def get_root_directory(initial_sector, file):
    root_directory_offset = (get_size_reserved_area(volume_boot_sector(initial_sector, file)) +
                             get_fat_area(volume_boot_sector(initial_sector, file)) + initial_sector)*512
    with open(file, 'rb') as f:
        f.seek(root_directory_offset)  # Goes to the root directory sector
        root_dir_array = f.readline(get_size_root_dir(volume_boot_sector(initial_sector, file))*512)
        f.close()
        fmt = str(get_size_root_dir(volume_boot_sector(initial_sector,file))*512) + 's'
        tmp = unpack(fmt, root_dir_array)

    return tmp[0]


#  -------------------- Deleted File Information Methods -------------------#

'''
deleted_file_info(): Receives the root directory array and root directory size in sector as arguments, checks from the
                     very first each 32th byte if it is equal to "E5h"(229d), so such file have been deleted, then gets
                     its file name, initial cluster and file size.
                     Returns the initial cluster to be used in order to get the cluster sector address of the deleted
                     file.
'''


def deleted_file_info(root_directory, root_directory_size):
    index = 0
    file_name = []
    for i in range(0, root_directory_size):
        tmp = unpack("<B", root_directory[index])
        if tmp[0] == 229:
            file_name = unpack("<11s", root_directory[index:index+11])
            starting_cluster = unpack("<H", root_directory[(index + 26):(index + 28)])
            file_size = unpack("<I", root_directory[(index + 28):(index + 32)])

            print "File Name:\t\t", file_name[0]
            print "Size of the file: \t", file_size[0]
            print "Initial Cluster: \t", starting_cluster[0]

            return starting_cluster[0]

        else:
            index += 32

'''
get_cluster_sector_address(): Receives the starting sector of the partition, the disk image file and the file's
                                   cluster number. Calculates the cluster sector address using the above declared
                                   functions.
                                   Returns the cluster sector address in bytes.
'''


def get_cluster_sector_address(initial_sector, file, cluster_number):
    csa = initial_sector + get_size_reserved_area(volume_boot_sector(initial_sector, file)) + \
          get_fat_area(volume_boot_sector(initial_sector, file)) + \
          get_size_root_dir(volume_boot_sector(initial_sector, file)) + ((cluster_number - 2)*8)
    return csa*512


'''
deleted_content(): Receives the cluster sector address in bytes and the disk image file. Opens the file, reading
                   the 16 first bytes from the given cluster sector address, returning them as an array.
'''

def deleted_content(csa, file):
    with open(file, 'rb') as f:
        f.seek(csa)
        content_array = unpack("16s", f.read(16))  # Gets the first 16 bytes of content from the deleted file
        f.close()
    return content_array[0]


############################ Main code ##############################

print "----------------------Forensic Tool----------------------\n"
print "----------------------MBR Analyser-----------------------\n"

print"Type the disk image file address: \n"

# Receives the disk image address through the terminal
file = raw_input() 
print "\n\n"

# Initialize the number of partitions variable
num_partitions = 0

# This loop prints the information about all the existing partitions in the disk image.
# It also increments the variable num_partitions, used to show the number of partitions in the disk.
for i in range(1, 5):
    print "Partition #",i
    if print_info(get_pte(file, i)) > 0:
        num_partitions += 1
    print("\n")

print "Number of Partitions: \t",(num_partitions),".\n\n"

print "------------------------Volume Info------------------------\n"
print "-------------------(For the 1st Partition)-----------------\n\n"

#  Gets the first partition's first sector address in bytes
initial_sector = get_first_sector_address(get_pte(file, 1))


#  Printing volume information
print "No. of Sectors:\t\t\t",get_n_sectors_per_cluster(volume_boot_sector(initial_sector, file))
print "Size of the FAT Area:\t\t", get_fat_area(volume_boot_sector(initial_sector, file))
print "Size of the Root Directory:\t", get_size_root_dir(volume_boot_sector(initial_sector,file))
print "Sector Address of Cluster #2:\t", initial_sector + get_size_reserved_area(volume_boot_sector(initial_sector,file))\
                                         + get_size_root_dir(volume_boot_sector(initial_sector,file)) + \
                                         get_fat_area(volume_boot_sector(initial_sector,file))
print "\n\n"

print "----------------------Deleted File Info---------------------\n"
print "-------------------(For the 1st del. file)------------------\n\n"

#  Gets the size of the root directory and the cluster sector address in bytes, so it can be used to calculate the
#  starting cluster of the deleted file.
size_root_dir = get_size_root_dir(volume_boot_sector(initial_sector, file))
starting_cluster = deleted_file_info(get_root_directory(initial_sector,file),size_root_dir)
csa = get_cluster_sector_address(initial_sector, file, starting_cluster)

#  Prints the first 16 bytes of the deleted file
print "First 16 bytes of the deleted file:\t", "\n\"",deleted_content(csa, file),"\""
print("\n\n")


# Waits for an user command to exit the program
raw_input("Press 'Enter' to exit...")

