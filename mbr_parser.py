#MBR Analyser
#Module: Computer Forensics (ET4027)
#Author: Solon Yukio Shibata Meira
#ID: 15047199

from _struct import unpack

'''
get_mbr: Opens the file (disk image) given as argument.
		 Reads and returns its first 512 bytes (MBR)
'''

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
print_info: Prints all the required information:
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

get_type: Receives an integer as argument, and, according to the dictionary structure 'type',
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
            14: "fAT-16 (LBA)"
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

def vol_info(file):



############################ Main code ##############################

print "----------------------Forensic Tool----------------------\n"
print "----------------------MBR Analyser-----------------------\n\n"

print"Type the disk image file address: \n"

#Receives the disk image address through the terminal
file = raw_input() 
print "\n\n"

#Initialize the number of partitions variable
num_partitions = 0

#This loop prints the information about all the existing partitions in the disk image.
#It also increments the variable num_partitions, used to show the number of partitions in the disk.
for i in range(1, 5):
    print "Partition #",i
    if(print_info(get_pte(file, i)) > 0):
        num_partitions = num_partitions + 1
    print("\n")

print "Number of Partitions: \t",(num_partitions),"."

print "------------------------Volume Info-----------------------\n\n"
print "-------------------(For the 1st Partition)-----------------\n\n"



#Waits for an user command to exit the program
raw_input("Press 'Enter' to exit...")

