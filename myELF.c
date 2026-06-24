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
int terminate = 0;


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
        if (terminate)
            return 0;

        if (debug_mode == 1) 
            printf("\n\nfile_mane1: %s\nfile_name2: %s\n", file_name1, file_name2);
        

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

//part 1
void print_section_names() {
    if (fileCount == 0) {
        printf("Error: No files are currently mapped.\n");
        return;
    }

    for (int f = 0; f < fileCount; f++) {
        void *current_addr = (f == 0) ? addr1 : addr2;
        char *current_name = (f == 0) ? file_name1 : file_name2;

        if (!current_addr) continue;

        Elf32_Ehdr *header = (Elf32_Ehdr *)current_addr;
        Elf32_Shdr *sec_headers = (Elf32_Shdr *)((char *)current_addr + header->e_shoff);
        char *sh_str_table = (char *)current_addr + sec_headers[header->e_shstrndx].sh_offset;

        if (debug_mode) {
            fprintf(stderr, "[DEBUG] shstrndx = %u, shstrtab offset = 0x%x\n",
                    header->e_shstrndx, sec_headers[header->e_shstrndx].sh_offset);
        }

        printf("File %s sections:\n", current_name);
        printf("[index] section_name         section_address section_offset section_size section_type\n");

        for (int i = 0; i < header->e_shnum; i++) {
            Elf32_Shdr *shdr = &sec_headers[i];
            char *sec_name = sh_str_table + shdr->sh_name;

            if (debug_mode) {
                fprintf(stderr, "[DEBUG] section[%d] sh_name offset = %u, name = '%s'\n",
                        i, shdr->sh_name, sec_name);
            }

            printf("[%2d] %-20s 0x%08x     0x%06x     %6u       %u\n",
                   i, sec_name, shdr->sh_addr, shdr->sh_offset,
                   shdr->sh_size, shdr->sh_type);
        }
        printf("\n");
    }
}

//part 2a
void print_symbols() {
    if (fileCount == 0) {
        printf("Error: No files are currently mapped.\n");
        return;
    }

    for (int f = 0; f < fileCount; f++) {
        void *current_addr = (f == 0) ? addr1 : addr2;
        char *current_name = (f == 0) ? file_name1 : file_name2;

        if (!current_addr) continue;

        Elf32_Ehdr *header   = (Elf32_Ehdr *)current_addr;
        Elf32_Shdr *sec_hdrs = (Elf32_Shdr *)((char *)current_addr + header->e_shoff);
        char *sh_str_table   = (char *)current_addr + sec_hdrs[header->e_shstrndx].sh_offset;

        Elf32_Sym *sym_table = NULL;
        char      *str_table = NULL;
        int        sym_count = 0;

        for (int i = 0; i < header->e_shnum; i++) {
            if (sec_hdrs[i].sh_type == SHT_SYMTAB) {
                sym_table = (Elf32_Sym *)((char *)current_addr + sec_hdrs[i].sh_offset);
                sym_count = sec_hdrs[i].sh_size / sizeof(Elf32_Sym);
                str_table = (char *)current_addr + sec_hdrs[sec_hdrs[i].sh_link].sh_offset;

                if (debug_mode) {
                    fprintf(stderr, "[DEBUG] Symbol table: section index=%d, size=%u bytes, "
                            "num_symbols=%d, strtab_link=%u\n",
                            i, sec_hdrs[i].sh_size, sym_count, sec_hdrs[i].sh_link);
                }
                break;
            }
        }

        if (!sym_table) {
            printf("Error: No symbol table found in %s\n", current_name);
            continue;
        }

        printf("File %s symbols:\n", current_name);
        printf("[index] value      section_index section_name         symbol_name\n");

        for (int i = 0; i < sym_count; i++) {
            Elf32_Sym *sym     = &sym_table[i];
            char      *sym_name = str_table + sym->st_name;
            char      *sec_name;
            char       sec_name_buf[32];

            if (sym->st_shndx == SHN_UNDEF) {
                sec_name = "UNDEF";
            } else if (sym->st_shndx == SHN_ABS) {
                sec_name = "ABS";
            } else if (sym->st_shndx == SHN_COMMON) {
                sec_name = "COMMON";
            } else if (sym->st_shndx < header->e_shnum) {
                sec_name = sh_str_table + sec_hdrs[sym->st_shndx].sh_name;
            } else {
                snprintf(sec_name_buf, sizeof(sec_name_buf), "RESERVED(%u)", sym->st_shndx);
                sec_name = sec_name_buf;
            }

            printf("[%2d]   0x%08x %5u         %-20s %s\n",
                   i, sym->st_value, sym->st_shndx, sec_name, sym_name);
        }
        printf("\n");
    }
}

//part 2b
void print_relocations() {
    if (fileCount == 0) {
        printf("Error: No files are currently mapped.\n");
        return;
    }

    for (int f = 0; f < fileCount; f++) {
        void *current_addr = (f == 0) ? addr1 : addr2;
        char *current_name = (f == 0) ? file_name1 : file_name2;

        if (!current_addr) continue;

        printf("File %s relocations:\n", current_name);
        printf("[index] location related_symbol_name type\n");

        Elf32_Ehdr *header = (Elf32_Ehdr *)current_addr;
        Elf32_Shdr *sec_headers = (Elf32_Shdr *)((char *)current_addr + header->e_shoff);
        char *sh_str_table = (char *)current_addr + sec_headers[header->e_shstrndx].sh_offset;

        int rel_section_found = 0;

        for (int i = 0; i < header->e_shnum; i++) {
            Elf32_Shdr *shdr = &sec_headers[i];

            if (shdr->sh_type == SHT_REL) {
                rel_section_found = 1;
                
                Elf32_Shdr *sym_shdr = &sec_headers[shdr->sh_link];
                Elf32_Sym *sym_tab = (Elf32_Sym *)((char *)current_addr + sym_shdr->sh_offset);
                
                Elf32_Shdr *str_shdr = &sec_headers[sym_shdr->sh_link];
                char *str_tab = (char *)current_addr + str_shdr->sh_offset;

                Elf32_Rel *rel_table = (Elf32_Rel *)((char *)current_addr + shdr->sh_offset);
                int rel_count = shdr->sh_size / sizeof(Elf32_Rel);

                if (debug_mode) {
                    fprintf(stderr, "[DEBUG] Found Relocation Section '%s' with %d entries\n", 
                           sh_str_table + shdr->sh_name, rel_count);
                }

                for (int j = 0; j < rel_count; j++) {
                    Elf32_Rel *rel = &rel_table[j];
                    
                    unsigned int sym_idx = ELF32_R_SYM(rel->r_info);
                    unsigned int rel_type = ELF32_R_TYPE(rel->r_info);

                    char *sym_name = "";
                    if (sym_idx < (sym_shdr->sh_size / sizeof(Elf32_Sym))) {
                        sym_name = str_tab + sym_tab[sym_idx].st_name;
                    }

                    printf("[%2d]   %08x %-20s %d\n", j, rel->r_offset, sym_name, rel_type);
                }
            }
        }

        if (!rel_section_found) {
            printf("No relocations\n");
        }
        printf("\n");
    }
}

// Helper function to find a symbol by its string name
Elf32_Sym* find_symbol_by_name(void *map_start, Elf32_Sym *sym_table, int sym_count, char *str_table, const char *name) {
    for (int i = 1; i < sym_count; i++) {
        char *curr_name = str_table + sym_table[i].st_name;
        if (strcmp(curr_name, name) == 0) {
            return &sym_table[i];
        }
    }
    return NULL;
}

//part 3.1
void check_file_for_merge() {
    if (fileCount < 2 || !addr1 || !addr2) {
        printf("Error: Two ELF files must be opened and mapped first.\n");
        return;
    }

    Elf32_Ehdr *hdrs[2] = {(Elf32_Ehdr *)addr1, (Elf32_Ehdr *)addr2};
    Elf32_Shdr *sec_hdrs[2] = {
        (Elf32_Shdr *)((char *)addr1 + hdrs[0]->e_shoff),
        (Elf32_Shdr *)((char *)addr2 + hdrs[1]->e_shoff)
    };
    
    Elf32_Sym *sym_tables[2] = {NULL, NULL};
    char *str_tables[2] = {NULL, NULL};
    int sym_counts[2] = {0, 0};

    // Extract symbol table details for both files
    for (int f = 0; f < 2; f++) {
        int sym_tab_count = 0;
        for (int i = 0; i < hdrs[f]->e_shnum; i++) {
            if (sec_hdrs[f][i].sh_type == SHT_SYMTAB) {
                sym_tab_count++;
                sym_tables[f] = (Elf32_Sym *)((char *)(f == 0 ? addr1 : addr2) + sec_hdrs[f][i].sh_offset);
                sym_counts[f] = sec_hdrs[f][i].sh_size / sizeof(Elf32_Sym);
                
                Elf32_Shdr *str_shdr = &sec_hdrs[f][sec_hdrs[f][i].sh_link];
                str_tables[f] = (char *)(f == 0 ? addr1 : addr2) + str_shdr->sh_offset;
            }
        }
        if (sym_tab_count != 1) {
            printf("feature not supported\n");
            return;
        }
    }

    for (int current = 0; current < 2; current++) {
        int other = 1 - current;

        for (int i = 1; i < sym_counts[current]; i++) {
            Elf32_Sym *sym1 = &sym_tables[current][i];
            char *sym_name = &str_tables[current][sym1->st_name];

            if (strlen(sym_name) == 0) continue;

            Elf32_Sym *sym2 = find_symbol_by_name(
                (other == 0) ? addr1 : addr2, 
                sym_tables[other], 
                sym_counts[other], 
                str_tables[other], 
                sym_name
            );

            if (sym1->st_shndx == SHN_UNDEF) {
                if (!sym2 || sym2->st_shndx == SHN_UNDEF) {
                    if (current == 0) {
                        printf("Symbol %s undefined\n", sym_name);
                    }
                }
            } 
            else if (sym1->st_shndx != SHN_UNDEF && sym2 && sym2->st_shndx != SHN_UNDEF) {
                if (current == 0) {
                    printf("Symbol %s multiply defined\n", sym_name);
                }
            }
        }
    }
}

// Helper function to find a section header by its string name
Elf32_Shdr* find_section_by_name(void *map_start, Elf32_Ehdr *header, Elf32_Shdr *sec_headers, char *sh_str_table, const char *name) {
    for (int i = 0; i < header->e_shnum; i++) {
        char *sec_name = sh_str_table + sec_headers[i].sh_name;
        if (strcmp(sec_name, name) == 0) {
            return &sec_headers[i];
        }
    }
    return NULL;
}

//parts 3.2 and 3.3
void merge_elf_files() {
    if (fileCount < 2 || !addr1 || !addr2) {
        printf("Error: Two ELF files must be opened and mapped first.\n");
        return;
    }

    int out_fd = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out_fd < 0) {
        perror("Error creating out.ro");
        return;
    }

    Elf32_Ehdr *hdr1 = (Elf32_Ehdr *)addr1;
    Elf32_Ehdr *hdr2 = (Elf32_Ehdr *)addr2;
    Elf32_Shdr *sec_hdrs1 = (Elf32_Shdr *)((char *)addr1 + hdr1->e_shoff);
    Elf32_Shdr *sec_hdrs2 = (Elf32_Shdr *)((char *)addr2 + hdr2->e_shoff);
    char *sh_str_table1 = (char *)addr1 + sec_hdrs1[hdr1->e_shstrndx].sh_offset;
    char *sh_str_table2 = (char *)addr2 + sec_hdrs2[hdr2->e_shstrndx].sh_offset;

    // Setup Base Output Header
    Elf32_Ehdr out_header = *hdr1;
    write(out_fd, &out_header, sizeof(Elf32_Ehdr));
    uint32_t current_offset = sizeof(Elf32_Ehdr);

    int shnum = hdr1->e_shnum;
    Elf32_Shdr *out_sec_headers = malloc(shnum * sizeof(Elf32_Shdr));
    memcpy(out_sec_headers, sec_hdrs1, shnum * sizeof(Elf32_Shdr));

    Elf32_Sym *sym_tab1 = NULL;
    char *str_tab1 = NULL;
    int sym_count1 = 0;
    for (int i = 0; i < shnum; i++) {
        if (sec_hdrs1[i].sh_type == SHT_SYMTAB) {
            sym_tab1 = (Elf32_Sym *)((char *)addr1 + sec_hdrs1[i].sh_offset);
            sym_count1 = sec_hdrs1[i].sh_size / sizeof(Elf32_Sym);
            str_tab1 = (char *)addr1 + sec_hdrs1[sec_hdrs1[i].sh_link].sh_offset;
        }
    }

    // Loop and concatenate sections
    for (int i = 0; i < shnum; i++) {
        char *sec_name = sh_str_table1 + sec_hdrs1[i].sh_name;
        Elf32_Shdr *shdr1 = &sec_hdrs1[i];

        if (shdr1->sh_type == SHT_NULL) {
            out_sec_headers[i].sh_offset = 0;
            continue;
        }

        out_sec_headers[i].sh_offset = current_offset;

        if (strcmp(sec_name, ".text") == 0 || strcmp(sec_name, ".data") == 0 || strcmp(sec_name, ".rodata") == 0) {
            write(out_fd, (char *)addr1 + shdr1->sh_offset, shdr1->sh_size);
            uint32_t merged_size = shdr1->sh_size;

            Elf32_Shdr *shdr2 = find_section_by_name(addr2, hdr2, sec_hdrs2, sh_str_table2, sec_name);
            if (shdr2) {
                write(out_fd, (char *)addr2 + shdr2->sh_offset, shdr2->sh_size);
                merged_size += shdr2->sh_size;
            }
            out_sec_headers[i].sh_size = merged_size;
            current_offset += merged_size;
        } 

        else if (shdr1->sh_type == SHT_SYMTAB && sym_tab1) {
            Elf32_Sym *out_sym_table = malloc(shdr1->sh_size);
            memcpy(out_sym_table, sym_tab1, shdr1->sh_size);

            // Locate File 2's Symbol Table context
            Elf32_Sym *sym_tab2 = NULL;
            char *str_tab2 = NULL;
            int sym_count2 = 0;
            for (int k = 0; k < hdr2->e_shnum; k++) {
                if (sec_hdrs2[k].sh_type == SHT_SYMTAB) {
                    sym_tab2 = (Elf32_Sym *)((char *)addr2 + sec_hdrs2[k].sh_offset);
                    sym_count2 = sec_hdrs2[k].sh_size / sizeof(Elf32_Sym);
                    str_tab2 = (char *)addr2 + sec_hdrs2[sec_hdrs2[k].sh_link].sh_offset;
                }
            }

            for (int s = 1; s < sym_count1; s++) {
                char *sym_name = str_tab1 + out_sym_table[s].st_name;
                
                if (out_sym_table[s].st_shndx == SHN_UNDEF && strlen(sym_name) > 0 && sym_tab2) {
                    Elf32_Sym *sym2 = find_symbol_by_name(addr2, sym_tab2, sym_count2, str_tab2, sym_name);
                    if (sym2 && sym2->st_shndx != SHN_UNDEF) {
                        char *f2_sec_name = sh_str_table2 + sec_hdrs2[sym2->st_shndx].sh_name;
                        for (int k = 0; k < shnum; k++) {
                            if (strcmp(sh_str_table1 + sec_hdrs1[k].sh_name, f2_sec_name) == 0) {
                                out_sym_table[s].st_shndx = k;
                                out_sym_table[s].st_value = sym2->st_value + sec_hdrs1[k].sh_size;
                                break;
                            }
                        }
                    }
                }
            }
            write(out_fd, out_sym_table, shdr1->sh_size);
            free(out_sym_table);
            current_offset += shdr1->sh_size;
        }
        else {
            write(out_fd, (char *)addr1 + shdr1->sh_offset, shdr1->sh_size);
            current_offset += shdr1->sh_size;
        }
    }

    out_header.e_shoff = current_offset;
    write(out_fd, out_sec_headers, shnum * sizeof(Elf32_Shdr));

    // Correct e_shoff mapping in header prefix
    lseek(out_fd, 0, SEEK_SET);
    write(out_fd, &out_header, sizeof(Elf32_Ehdr));

    close(out_fd);
    free(out_sec_headers);
    printf("Merge completed successfully. Saved output file as 'out.ro'.\n");
}

void quit() {
    if (addr1 && length1 > 0) munmap(addr1, length1);
    if (addr2 && length2 > 0) munmap(addr2, length2);
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);
    terminate = 1;
}