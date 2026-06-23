#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

char debug_mode = 0;

int fileCount = 0;


char file_name1[128] = "";
char file_name2[128] = "";
void *addr2 = NULL;
void *addr1 = NULL;
size_t length1 = 0;
size_t length2 = 0;
int fd1 = -1;
int fd2 = -1;

unsigned char mem_buf[10000];

typedef struct option {
    char key;
    char* name;
    void (*func)(void);
}option;

void toggle_debug_mode();
void examine_elf_file();
void print_section_names();
void print_symbols();
void print_relocations();
void check_file_for_merge();
void merge_elf_files();
void quit();

option options[9] = {
    {'D', "Toggle <D>ebug Mode", toggle_debug_mode},
    {'F', "Examine ELF <F>ile", examine_elf_file},
    {'N', "Print Section <N>ames", print_section_names},
    {'S', "Print <S>ymbols", print_symbols},
    {'R', "Print <R>elocations", print_relocations},
    {'C', "<C>heck Files for Merge", check_file_for_merge},
    {'M', "<M>erge ELF Files", merge_elf_files},
    {'Q', "Quit", quit},
    {'\0', NULL, NULL}
};

int main(int argc, char* argv[]) {
    char input[100];
    char choice;

    while (1) {

        if (debug_mode == 1) {
            printf("\n\nfile_mane1: %s\nfile_name2: %s\n", file_name1, file_name2);
        }

        printf("\nChoose action:\nToggle <D>ebug Mode\nExamine ELF <F>ile\nPrint Section <N>ames\n");
        printf("Print <S>ymbols\nPrint <R>elocations\n<C>heck Files for Merge\n<M>erge ELF Files\n<Q>uit\n");
        
        if (fgets(input, sizeof(input), stdin) == NULL) 
            break;
        if (sscanf(input, "%c", &choice) != 1) 
            continue;
        
        int found = 0;
        for (int i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
            if (options[i].key == '\0') {
                break;
            }
            if (options[i].key == choice) {
                options[i].func();
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Invalid option\n");
        }
    }
    return 0;
}

void toggle_debug_mode() {
    if (debug_mode == 0) {
        debug_mode = 1;
        fprintf(stderr, "Debug flag now on\n");
    } else {
        debug_mode = 0;
        fprintf(stderr, "Debug flag now off\n");
    }    
}

void examine_elf_file() {
    if (fileCount >= 2) {
        printf("Error: already loaded 2 files\n");
        return;
    }
    char *file_name = (fileCount == 0) ? file_name1 : file_name2;
    int  *fdp       = (fileCount == 0) ? &fd1 : &fd2;
    void **addr     = (fileCount == 0) ? &addr1 : &addr2;
    size_t *length  = (fileCount == 0) ? &length1 : &length2;

    printf("Enter file name: ");
    if (fgets(file_name, 128, stdin) == NULL) {
        perror("fgets");
        return;
    }
    file_name[strcspn(file_name, "\n")] = '\0';
    if (debug_mode)
        fprintf(stderr, "Debug: file name set to %s\n", file_name);

    *fdp = open(file_name, O_RDONLY);
    if (*fdp < 0) {
        perror("open");
        *fdp = -1;
        return;
    }

    *length = lseek(*fdp, 0, SEEK_END);
    lseek(*fdp, 0, SEEK_SET);

    *addr = mmap(NULL, *length, PROT_READ, MAP_SHARED, *fdp, 0);
    if (*addr == MAP_FAILED) {
        perror("mmap");
        close(*fdp);
        *fdp = -1;
        *addr = NULL;
        return;
    }

    if (debug_mode)
        fprintf(stderr, "Debug: mmapped %s to address %p\n", file_name, *addr);

    Elf32_Ehdr *header = (Elf32_Ehdr *)*addr;

    if (header->e_ident[0] != 0x7f ||
        header->e_ident[1] != 'E'  ||
        header->e_ident[2] != 'L'  ||
        header->e_ident[3] != 'F') {
        printf("Error: not a valid ELF file\n");
        munmap(*addr, *length);
        close(*fdp);
        *addr = NULL;
        *fdp = -1;
        return;
    }

    fileCount++;

    char *encoding;
    switch (header->e_ident[EI_DATA]) {
        case ELFDATA2LSB: encoding = "2's complement, little endian"; break;
        case ELFDATA2MSB: encoding = "2's complement, big endian";    break;
        default:          encoding = "unknown";                        break;
    }

    printf("%-35s%c%c%c\n",            "Magic:",             header->e_ident[1], header->e_ident[2], header->e_ident[3]);
    printf("%-35s%s\n",                "Data:",              encoding);
    printf("%-35s0x%x\n",             "Entry point address:", header->e_entry);
    printf("%-35s%u (bytes into file)\n", "Start of section headers:", header->e_shoff);
    printf("%-35s%u\n",               "Number of section headers:", header->e_shnum);
    printf("%-35s%u (bytes)\n",       "Size of section headers:",   header->e_shentsize);
    printf("%-35s%u (bytes into file)\n", "Start of program headers:", header->e_phoff);
    printf("%-35s%u\n",               "Number of program headers:", header->e_phnum);
    printf("%-35s%u (bytes)\n",       "Size of program headers:",   header->e_phentsize);
}

void print_section_names() {
    //TODO
    printf("not inplemented yet");
}

void print_symbols(){
    //TODO
    printf("not inplemented yet");
}

void print_relocations() {
    //TODO
    printf("not inplemented yet");
}

void check_file_for_merge() {
    //TODO
    printf("not inplemented yet");
}

void merge_elf_files() {
    //TODO
    printf("not inplemented yet");
}

void quit() {
    if (addr1 && length1 > 0) munmap(addr1, length1);
    if (addr2 && length2 > 0) munmap(addr2, length2);
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);
    _exit(0);
}