from _struct import unpack
file = "Sample_1.dd"
initial_sector = 63


def volume_boot_sector(partition_offset, file):

    # Getting the Volume's Boot Sector
    with open(file, 'rb') as f:
        f.seek(partition_offset*512)  # Converting sectors to bytes
        vbr = f.readline(512)
        f.close()
    return vbr


def get_n_clusters_per_sector(vbr):
    tmp = unpack("<B", vbr[13])
    return tmp[0]


def get_size_reserved_area(vbr):
    tmp = unpack("<H", vbr[14:16])
    return tmp[0]


def get_fat_area(vbr):
    fat_copies = unpack("<B", vbr[16])
    fat_area = unpack("<H", vbr[22:24])
    return fat_area[0] * fat_copies[0]


def get_size_root_dir(vbr):
    tmp = unpack("<H", vbr[17:19])
    return tmp[0]*32/512


def get_root_directory(partition_sector, file):
    root_directory_offset = (get_size_reserved_area(volume_boot_sector(partition_sector, file)) +
                             get_fat_area(volume_boot_sector(partition_sector, file)) + partition_sector)*512
    with open(file, 'rb') as f:
        f.seek(root_directory_offset)  # Goes to the root directory sector
        root_dir_array = f.readline(get_size_root_dir(volume_boot_sector(partition_sector, file))*512)
        f.close()
        fmt = str(get_size_root_dir(volume_boot_sector(initial_sector,file))*512) + 's'
        tmp = unpack(fmt, root_dir_array)

    return tmp[0]


def deleted_file_info(root_directory, root_directory_size):
    index = 0
    file_name = []
    for i in range(0, root_directory_size):
        tmp = unpack("<B", root_directory[index])
        if tmp[0] == 229:
            file_name = unpack("<11s", root_directory[index:index+11])
            starting_cluster = unpack("<H", root_directory[(index + 26):(index + 28)])
            file_size = unpack("<I", root_directory[(index + 28):(index + 32)])

            print "File Name:\t", file_name[0]
            print "Size of the file: \t", file_size[0]
            print "Initial Cluster: \t", starting_cluster[0]

            return starting_cluster[0]

        else:
            index += 32


def get_cluster_sector_address(partition_sector, file, cluster_number):
    csa = partition_sector + get_size_reserved_area(volume_boot_sector(partition_sector, file)) + get_fat_area(volume_boot_sector(partition_sector, file)) + get_size_root_dir(volume_boot_sector(partition_sector, file)) + ((cluster_number - 2)*8)
    return csa*512


def deleted_content(csa, file):
    with open(file, 'rb') as f:
        f.seek(csa)
        content_array = unpack("16s", f.read(16))  # Gets the first 16 bytes of content from the deleted file
        f.close()
    return content_array[0]




# print(get_n_clusters_per_sector(volume_boot_sector(initial_sector, file)))
#print(get_size_reserved_area(volume_boot_sector(initial_sector, file)))
#print(get_fat_area(volume_boot_sector(initial_sector, file)))
# print(get_root_directory(63, file))

size_root_dir = get_size_root_dir(volume_boot_sector(initial_sector, file))
starting_cluster = deleted_file_info(get_root_directory(initial_sector,file),size_root_dir)
csa = get_cluster_sector_address(initial_sector, file, starting_cluster)
print"CSA:", csa
print deleted_content(csa, file)



