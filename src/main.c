/* Copyright 2015 9x6.me. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * author: Notis Hell (notishell@gmail.com)
 */
#include <zeus/zeus.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>


/* command-line options */
struct Options {
    const char *prog;
    const char *elf_file;
	int show_usage;
	int show_elf_header;
	int show_section_header;
	int show_section_index;
	int show_program_header;
	int show_program_index;
	int repair_elf;
	const char *save_repair_output;
};

struct Options gOptions;

const char *elf32_ehdr_class(unsigned int type) {
	switch (type) {
	case ELFCLASS32:
		return ("32-bit architecture.");
	case ELFCLASS64:
		return ("64-bit architecture.");
	case ELFCLASSNONE:
	default:
		return ("Unknown class.");
	}
}

const char *elf32_ehdr_data(unsigned int type) {
	switch (type) {
	case ELFDATA2LSB:
		return ("2's complement little-endian.");
	case ELFDATA2MSB:
		return ("2's complement big-endian.");
	case ELFDATANONE:
	default:
		return ("Unknown data format.");
	}
}

const char *elf32_ehdr_type(unsigned int type) {
	switch (type) {
	case ET_REL:
		return ("Relocatable.");
	case ET_EXEC:
		return ("Executable.");
	case ET_DYN:
		return ("Shared object.");
	case ET_CORE:
		return ("Core file.");
	case ET_NONE:
	default:
		if (type >= ET_LOOS && type <= ET_HIOS) {
			return ("Operating system specific.");
		} else if (type >= ET_LOPROC && type <= ET_HIPROC) {
			return ("Processor specific.");
		} else {
			return ("Unknown type.");
		}
	}
}

const char *elf32_ehdr_osabi(unsigned char type) {
	const char *osabis[] = {
		"UNIX System V ABI.",
		"HP-UX operating system.",
		"NetBSD.",
		"GNU/Linux.",
		"GNU/Hurd.",
		"86Open common IA32 ABI.",
		"Solaris.",
		"AIX.",
		"IRIX.",
		"FreeBSD.",
		"TRU64 UNIX.",
		"Novell Modesto.",
		"OpenBSD.",
		"Open VMS.",
		"HP Non-Stop Kernel.",
		"Amiga Research OS.",
	};

	if (type < sizeof(osabis) / sizeof(osabis[0])) {
		return (osabis[type]);
	}

	switch (type) {
	case ELFOSABI_ARM:
		return ("ARM.");
	case ELFOSABI_STANDALONE:
		return ("Standalone (embedded) application.");
	default:
		return ("Unknown OS/ABI.");
	}
}

const char *elf32_ehdr_machine(unsigned int type) {
	switch (type) {
	case EM_M32:
		return ("AT&T WE32100.");
	case EM_SPARC:
		return ("Sun SPARC.");
	case EM_386:
		return ("Intel i386.");
	case EM_68K:
		return ("Motorola 68000.");
		//...
	case EM_NONE:
	default:
		return ("Unknown machine.");
	}
}

void elf32_dump_ehdr(Elf32_Ehdr *pEhdr) {
	int i;

	const char *datas[256] = {
		"Unknown data format.",
		"2's complement little-endian.",
		"2's complement big-endian.",
	};

	printf("ELF header:\n");
	printf("  Magic: '%.*s'", SELFMAG, pEhdr->e_ident);
	for (i = SELFMAG; i < EI_NIDENT; i++) {
		printf(" %02X", pEhdr->e_ident[i]);
	}
	printf("\n");
	printf("  Class:               %s\n", elf32_ehdr_class(pEhdr->e_ident[EI_CLASS]));
	printf("  Data:                %s\n", elf32_ehdr_data(pEhdr->e_ident[EI_DATA]));
	printf("  Version:             %d\n", pEhdr->e_ident[EI_VERSION]);
	printf("  OS/ABI:              %s\n", elf32_ehdr_osabi(pEhdr->e_ident[EI_OSABI]));
	printf("  ABI Version:         %d\n", pEhdr->e_ident[EI_ABIVERSION]);
	printf("  Type:                %s\n", elf32_ehdr_type(pEhdr->e_type));
	printf("  Machine:             %s\n", elf32_ehdr_machine(pEhdr->e_machine));


	printf("e_version  : 0x%08x\n", pEhdr->e_version);
	printf("e_entry    : 0x%08x\n", pEhdr->e_entry);
	printf("e_phoff    : 0x%08x\n", pEhdr->e_phoff);
	printf("e_shoff    : 0x%08x\n", pEhdr->e_shoff);
	printf("e_flags    : 0x%08x\n", pEhdr->e_flags);
	printf("e_ehsize   : 0x%08x\n", pEhdr->e_ehsize);
	printf("e_phentsize: 0x%08x\n", pEhdr->e_phentsize);
	printf("e_phnum    : 0x%08x\n", pEhdr->e_phnum);
	printf("e_shentsize: 0x%08x\n", pEhdr->e_shentsize);
	printf("e_shnum    : 0x%08x\n", pEhdr->e_shnum);
	printf("e_shstrndx : 0x%08x\n", pEhdr->e_shstrndx);
	printf("\n");
}

const char *elf_shdr_name(Elf32_Word idx) {
	return ("-");
}

const char *elf_shdr_type(Elf32_Word type) {
	switch (type) {
	case SHT_NULL:
		return ("NULL");
	case SHT_PROGBITS:
		return ("PRGBITS");
	case SHT_SYMTAB:
		return ("SYMTAB");
	case SHT_STRTAB:
		return ("STRTAB");
	case SHT_RELA:
		return ("RELA");
	case SHT_HASH:
		return ("HASH");
	case SHT_DYNAMIC:
		return ("DYNAMIC");
	case SHT_NOTE:
		return ("NOTE");
	case SHT_NOBITS:
		return ("NOBITS");
	case SHT_REL:
		return ("REL");
	case SHT_SHLIB:
		return ("SHLIB");
	case SHT_DYNSYM:
		return ("DYNSYM");
	case SHT_INIT_ARRAY:
		return ("IARRAY");
	case SHT_FINI_ARRAY:
		return ("FARRAY");
	case SHT_PREINIT_ARRAY:
		return ("PARRAY");
	case SHT_GROUP:
		return ("GROUP");
	case SHT_SYMTAB_SHNDX:
		return ("SHNDX");
	case SHT_SUNW_dof:
		return ("dof");
	case SHT_SUNW_cap:
		return ("cap");
	case SHT_SUNW_SIGNATURE:
		return ("SIGNATURE");
	case SHT_SUNW_ANNOTATE:
		return ("ANNOTATE");
	case SHT_SUNW_DEBUGSTR:
		return ("DEBUGSTR");
	case SHT_SUNW_DEBUG:
		return ("DEBUG");
	case SHT_SUNW_move:
		return ("move");
	case SHT_SUNW_COMDAT:
		return ("COMDAT");
	case SHT_SUNW_syminfo:
		return ("syminfo");
	case SHT_GNU_verdef:
		return ("verdef");
	case SHT_GNU_verneed:
		return ("verneed");
	case SHT_GNU_versym:
		return ("versym");
	default:
		if (type >= SHT_LOSUNW && type <= SHT_HISUNW) {
			return ("SUNW");
		} else if (type >= SHT_LOOS && type <= SHT_HIOS) {
			return ("OS");
		} else if (type >= SHT_LOPROC && type <= SHT_HIPROC) {
			return ("PROC");
		} else if (type >= SHT_LOUSER && type <= SHT_HIUSER) {
			return ("USER");
		} else {
			return ("unknown");
		}
	}
}

const char *elf_shdr_flag(Elf32_Word flag) {
	static char buff[16];
	buff[0] = flag & SHF_WRITE ? 'W' : '-';
	buff[1] = flag & SHF_ALLOC ? 'A' : '-';
	buff[2] = flag & SHF_MERGE ? 'M' : '-';
	buff[3] = flag & SHF_STRINGS ? 'S' : '-';
	buff[4] = flag & SHF_INFO_LINK ? 'I' : '-';
	buff[5] = flag & SHF_LINK_ORDER ? 'L' : '-';
	buff[6] = flag & SHF_OS_NONCONFORMING ? 'O' : '-';
	buff[7] = flag & SHF_GROUP ? 'G' : '-';
	buff[8] = flag & SHF_TLS ? 'T' : '-';
	buff[9] = flag & SHF_MASKOS ? 'o' : '-';
	buff[10] = flag & SHF_MASKPROC ? 'p' : '-';
	buff[11] = '\0';
	return (buff);
}

void elf32_dump_shdr(Elf32_Ehdr *pEhdr, Elf32_Shdr *pShdr) {
	int i;

	printf("Find %d section headers at offset 0x%06x\n\n", pEhdr->e_shnum, pEhdr->e_shoff);
	printf("Section header:\n");
	printf("   No  Name         Type      Flags  Addr     Off    Size   ES  Lk Inf Al\n");
	printf("  -------------------------------------------------------------------------------\n");
	for (i = 0; i < pEhdr->e_shnum; i++) {
		printf("  [%2d] %-12d %-8s %-12s %08x %08x %06x % 4d % 4d %04x %04x\n",
			i,
			pShdr[i].sh_name,//elf_shdr_name(),
			elf_shdr_type(pShdr[i].sh_type),
			elf_shdr_flag(pShdr[i].sh_flags),
			pShdr[i].sh_addr,
			pShdr[i].sh_offset,
			pShdr[i].sh_size,
			pShdr[i].sh_link,
			pShdr[i].sh_info,
			pShdr[i].sh_addralign,
			pShdr[i].sh_entsize
			);
	}

	printf("\nKey to Flags:\n"
	  "  W (write), A (alloc), X (execute), M (merge), S (strings)\n"
	  "  I (info), L (link order), G (group), T (TLS), E (exclude)\n"
	  "  O (extra OS processing required) o (OS specific), p (processor specific)\n\n");

}

const char *elf_phdr_type(Elf32_Word type) {
	switch (type) {
	case PT_NULL:
		return ("PT_NULL");
	case PT_LOAD:
		return ("PT_LOAD");
	case PT_DYNAMIC:
		return ("PT_DYNAMIC");
	case PT_INTERP:
		return ("PT_INTERP");
	case PT_SHLIB:
		return ("PT_SHLIB");
	case PT_NOTE:
		return ("PT_NOTE");
	case PT_PHDR:
		return ("PT_PHDR");
	case PT_TLS:
		return ("PT_TLS");
	case PT_SUNW_UNWIND:
		return ("PT_SUNW_UNWIND");
	case PT_GNU_EH_FRAME:
		return ("PT_GNU_EH_FRAME");
	case PT_GNU_STACK:
		return ("PT_GNU_STACK");
	case PT_GNU_RELRO:
		return ("PT_GNU_RELRO");
	case PT_SUNWBSS:
		return ("PT_SUNWBSS");
	case PT_SUNWSTACK:
		return ("PT_SUNWSTACK");
	case PT_SUNWDTRACE:
		return ("PT_SUNWDTRACE");
	case PT_SUNWCAP:
		return ("PT_SUNWCAP");
	default:
		if (type >= PT_LOSUNW && type <= PT_HISUNW) {
			return (">SUNW<");
		} else if (type >= PT_LOOS && type <= PT_HIOS) {
			return (">OS<");
		} else if (type >= PT_LOPROC && type <= PT_HIPROC) {
			return (">PROC<");
		} else {
			return ("unknown");
		}
	}
}

const char *elf_phdr_flag(Elf32_Word flag) {
	static char buff[6];
	buff[0] = flag & PF_R ? 'R' : '-';
	buff[1] = flag & PF_W ? 'W' : '-';
	buff[2] = flag & PF_X ? 'X' : '-';
	buff[3] = flag & PF_MASKOS ? 'O' : '-';
	buff[4] = flag & PF_MASKPROC ? 'P' : '-';
	buff[5] = '\0';
	return (buff);
}

void elf32_dump_phdr(Elf32_Ehdr *pEhdr, Elf32_Phdr *pPhdr) {
	int i;

	printf("Find %d program headers at offset 0x%06x\n\n", pEhdr->e_phnum, pEhdr->e_phoff);
	printf("Pprogram header:\n");
	printf("   No   Type          Flags  Offset    VAddr     PAddr     FSize   MSize   Align\n");
	printf("  ------------------------------------------------------------------------------\n");
	for (i = 0; i < pEhdr->e_phnum; i++) {
		printf("  [%2d]  %-12s  %-5s  %08x  %08x  %08x  %06x %c%06x   %04x\n",
			i,
			elf_phdr_type(pPhdr[i].p_type),
			elf_phdr_flag(pPhdr[i].p_flags),
			pPhdr[i].p_offset,
			pPhdr[i].p_vaddr,
			pPhdr[i].p_paddr,
			pPhdr[i].p_filesz,
			pPhdr[i].p_filesz == pPhdr[i].p_memsz ? ' ' : '*',
			pPhdr[i].p_memsz,
			pPhdr[i].p_align);
	}

	printf("\nKey to Flags:\n"
	    "  R (read), W (write), X (execute), O (Operating system-specific),\n"
	    "  P (Processor-specific).\n\n"
	    "* File size not equal to memory.\n\n");
}

const char *elf_dynamic_type(Elf32_Word type) {
	switch (type) {
	case DT_NULL:
		return ("DT_NULL");
	case DT_NEEDED:
		return ("DT_NEEDED");
	case DT_PLTRELSZ:
		return ("DT_PLTRELSZ");
	case DT_PLTGOT:
		return ("DT_PLTGOT");
	case DT_HASH:
		return ("DT_HASH");
	case DT_STRTAB:
		return ("DT_STRTAB");
	case DT_SYMTAB:
		return ("DT_SYMTAB");
	case DT_RELA:
		return ("DT_RELA");
	case DT_RELASZ:
		return ("DT_RELASZ");
	case DT_RELAENT:
		return ("DT_RELAENT");
	case DT_STRSZ:
		return ("DT_STRSZ");
	case DT_SYMENT:
		return ("DT_SYMENT");
	case DT_INIT:
		return ("DT_INIT");
	case DT_FINI:
		return ("DT_FINI");
	case DT_SONAME:
		return ("DT_SONAME");
	case DT_RPATH:
		return ("DT_RPATH");
	case DT_SYMBOLIC:
		return ("DT_SYMBOLIC");
	case DT_REL:
		return ("DT_REL");
	case DT_RELSZ:
		return ("DT_RELSZ");
	case DT_RELENT:
		return ("DT_RELENT");
	case DT_PLTREL:
		return ("DT_PLTREL");
	case DT_DEBUG:
		return ("DT_DEBUG");
	case DT_TEXTREL:
		return ("DT_TEXTREL");
	case DT_JMPREL:
		return ("DT_JMPREL");
	case DT_BIND_NOW:
		return ("DT_BIND_NOW");
	case DT_INIT_ARRAY:
		return ("DT_INIT_ARRAY");
	case DT_FINI_ARRAY:
		return ("DT_FINI_ARRAY");
	case DT_INIT_ARRAYSZ:
		return ("DT_INIT_ARRAYSZ");
	case DT_FINI_ARRAYSZ:
		return ("DT_FINI_ARRAYSZ");
	case DT_RUNPATH:
		return ("DT_RUNPATH");
	case DT_FLAGS:
		return ("DT_FLAGS");
	case DT_PREINIT_ARRAY:
		return ("DT_PREINIT_ARRAY");
	case DT_PREINIT_ARRAYSZ:
		return ("DT_PREINIT_ARRAYSZ");
	case DT_MAXPOSTAGS:
		return ("DT_MAXPOSTAGS");
	case DT_SUNW_AUXILIARY:
		return ("DT_SUNW_AUXILIARY");
	case DT_SUNW_RTLDINF:
		return ("DT_SUNW_RTLDINF");
	case DT_SUNW_FILTER:
		return ("DT_SUNW_FILTER");
	case DT_SUNW_CAP:
		return ("DT_SUNW_CAP");
	case DT_CHECKSUM:
		return ("DT_CHECKSUM");
	case DT_PLTPADSZ:
		return ("DT_PLTPADSZ");
	case DT_MOVEENT:
		return ("DT_MOVEENT");
	case DT_MOVESZ:
		return ("DT_MOVESZ");
	case DT_FEATURE_1:
		return ("DT_FEATURE_1");
	case DT_POSFLAG_1:
		return ("DT_POSFLAG_1");
	case DT_SYMINSZ:
		return ("DT_SYMINSZ");
	case DT_SYMINENT:
		return ("DT_SYMINENT");
	case DT_GNU_HASH:
		return ("DT_GNU_HASH");
	case DT_CONFIG:
		return ("DT_CONFIG");
	case DT_DEPAUDIT:
		return ("DT_DEPAUDIT");
	case DT_AUDIT:
		return ("DT_AUDIT");
	case DT_PLTPAD:
		return ("DT_PLTPAD");
	case DT_MOVETAB:
		return ("DT_MOVETAB");
	case DT_SYMINFO:
		return ("DT_SYMINFO");
	case DT_VERSYM:
		return ("DT_VERSYM");
	case DT_RELACOUNT:
		return ("DT_RELACOUNT");
	case DT_RELCOUNT:
		return ("DT_RELCOUNT");
	case DT_FLAGS_1:
		return ("DT_FLAGS_1");
	case DT_VERDEF:
		return ("DT_VERDEF");
	case DT_VERDEFNUM:
		return ("DT_VERDEFNUM");
	case DT_VERNEED:
		return ("DT_VERNEED");
	case DT_VERNEEDNUM:
		return ("DT_VERNEEDNUM");
	case DT_DEPRECATED_SPARC_REGISTER:
		return ("DT_DEPRECATED_SPARC_REGISTER");
	case DT_AUXILIARY:
		return ("DT_AUXILIARY");
	case DT_USED:
		return ("DT_USED");
	case DT_FILTER:
		return ("DT_FILTER");
	default:
		if (type >= DT_VALRNGLO && type <= DT_VALRNGHI) {
			return (">VAL<");
		} else if (type >= DT_ADDRRNGLO && type <= DT_ADDRRNGHI) {
			return (">ADDR<");
		} else if (type >= DT_LOOS && type <= DT_HIOS) {
			return (">OS<");
		} else if (type >= DT_LOPROC && type <= DT_HIPROC) {
			return (">PROC<");
		} else {
			return ("unknown");
		}
	}
}

void elf32_dump_dynamic(Elf32_Dyn *pDyn, int size) {
	int i;

	printf("Segment dynamic:\n");
	printf("  No    Type                  Value\n");
	printf("  ---------------------------------\n");
	for (i = 0; i < size && pDyn[i].d_tag != DT_NULL; i++) {
		printf("  [%2d]  %-18s %08X\n", i, elf_dynamic_type(pDyn[i].d_tag), pDyn[i].d_un.d_val);
	}
}

void elf32_dump_phdr_with_index(Elf32_Ehdr *pEhdr, Elf32_Phdr *pPhdr, int idx) {
	int i;
	Elf32_Word type;

	if (pPhdr == 0 || idx >= pEhdr->e_phnum) {
	    fprintf(stderr, "%s: program header index too big\n", gOptions.prog);
	    return;
	}

	type = pPhdr[idx].p_type;

	switch (type) {
	case PT_NULL:
		break;
	case PT_LOAD:
		break;
	case PT_DYNAMIC:
		elf32_dump_dynamic((Elf32_Dyn *)((char *)(pEhdr) + pPhdr[idx].p_offset), pPhdr[idx].p_filesz / sizeof(Elf32_Dyn));
		break;
	case PT_INTERP:
	case PT_SHLIB:
	case PT_NOTE:
	case PT_PHDR:
	case PT_TLS:
	case PT_SUNW_UNWIND:
	case PT_GNU_EH_FRAME:
	case PT_GNU_STACK:
	case PT_GNU_RELRO:
	case PT_SUNWBSS:
	case PT_SUNWSTACK:
	case PT_SUNWDTRACE:
	case PT_SUNWCAP:
	default:
		if (type >= PT_LOSUNW && type <= PT_HISUNW) {
		} else if (type >= PT_LOOS && type <= PT_HIOS) {
		} else if (type >= PT_LOPROC && type <= PT_HIPROC) {
		} else {
		}
	}
}

void process_elf32(struct zeus_elf_file *elf) {
	Elf32_Ehdr *pEhdr;

	pEhdr = zeus_elf32_get_ehdr(elf);
	if (gOptions.show_elf_header) {
		elf32_dump_ehdr(pEhdr);
	}
	if (gOptions.show_section_header) {
		elf32_dump_shdr(pEhdr, zeus_elf32_get_shdr(elf));
	}
	if (gOptions.show_program_header) {
		if (gOptions.show_program_index == -1) {
			elf32_dump_phdr(pEhdr, zeus_elf32_get_phdr(elf));
		} else {
			elf32_dump_phdr_with_index(pEhdr, zeus_elf32_get_phdr(elf), gOptions.show_program_index);
		}
	}
}

void process_elf64(struct zeus_elf_file *elf) {

}

int process_elf(const char *file) {
	struct zeus_elf_file *elf;

	elf = zeus_elf_open(file);
	if (elf) {
		if (gOptions.repair_elf) {
			zeus_elf_repair(elf, gOptions.save_repair_output);
		} else {
			switch (zeus_elf_class(file)) {
			case ELFCLASS32:
				process_elf32(elf);
				break;
			case ELFCLASS64:
				process_elf64(elf);
				break;
			}
		}
		zeus_elf_close(elf);
	} else {
	    fprintf(stderr, "%s: read file failed\n", gOptions.prog);
		return (3);
	}

	return (0);
}

static const char *short_opts = "hesS:pP:r:";

struct option long_opts[] = {
	{"help", no_argument, NULL, 'h'},
	{"elf", no_argument, NULL, 'e'},
	{"section", no_argument, NULL, 's'},
	{"section-index", required_argument, NULL, 'S'},
	{"program", no_argument, NULL, 'p'},
	{"program-index", required_argument, NULL, 'P'},
	{"repair", required_argument, NULL, 'r'},
	{0, 0, 0, 0},
};

void show_usage() {
    fprintf(stderr, "Copyright (C) 2015 9x6.me by Notis Hell\n\n");
    fprintf(stderr, "usage :\n\n");
    fprintf(stderr, "%s: [-?] [-h] [-e] [-s] elf\n\n", gOptions.prog);
    fprintf(stderr, "Argument used list below.\n\n");
    fprintf(stderr, "   -h, --help : show this info and exit\n");
    fprintf(stderr, "   -e, --elf : show ELF header\n");
    fprintf(stderr, "   -s, --section : show section header\n");
    fprintf(stderr, "   -S, --section-index : show section header\n");
    fprintf(stderr, "   -p, --program : show program header\n");
    fprintf(stderr, "   -P, --program-index : show program header\n");
    fprintf(stderr, "   -r, --repair : repair elf\n");
}

int main (int argc, char* const argv[]) {
	int ic;

    memset(&gOptions, 0, sizeof(gOptions));
    gOptions.prog = argv[0];

    while (1) {
        ic = getopt_long(argc, argv, short_opts, long_opts, 0);
        if (ic < 0)
            break;

        switch (ic) {
        case 'h':
            gOptions.show_usage = 1;
            break;
        case 'e':
            gOptions.show_elf_header = 1;
            break;
        case 's':
        	gOptions.show_section_index = -1;
            gOptions.show_section_header = 1;
            if (optarg) {
            	gOptions.show_section_index = atoi(optarg);
            }
            break;
        case 'p':
            gOptions.show_program_index = -1;
            gOptions.show_program_header = 1;
            break;
        case 'P':
            gOptions.show_program_header = 1;
            if (optarg) {
            	gOptions.show_program_index = atoi(optarg);
            }
            break;
        case 'r':
            gOptions.repair_elf = 1;
            gOptions.save_repair_output = optarg;
            break;
        default:
            break;
        }
    }

    if (gOptions.show_usage == 1) {
        show_usage();
        return (1);
    }

    if (optind == argc) {
        fprintf(stderr, "%s: no file specified\n", gOptions.prog);
        return (2);
    }

	return (process_elf(argv[optind]));
}
