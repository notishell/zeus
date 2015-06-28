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

#include <sys/elf_common.h>
#include <sys/elf32.h>
#include <sys/elf64.h>

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


enum {
	STATUS_INIT 		= 0,
	STATUS_READY 		= 1,
	STATUS_DESTROY 		= 2,
};

enum {
	TYPE_ELF32			= 1,
	TYPE_ELF64			= 2,
};

struct zeus_elf32_file {
	Elf32_Ehdr *pEhdr;
	Elf32_Shdr *pShdr;
	Elf32_Phdr *pPhdr;
};

struct zeus_elf64_file {
	Elf64_Ehdr *pEhdr;
	Elf64_Shdr *pShdr;
	Elf64_Phdr *pPhdr;
};

struct zeus_elf_file {
	int status;
	int fd;

	char *buff;
	int buff_size;
	char *save_buff;
	int save_buff_size;

	int type;
	union {
		struct zeus_elf32_file elf32;
		struct zeus_elf64_file elf64;
	} elf;
};

void zeus_elf_close(struct zeus_elf_file *file) {
	if (file) {
		file->status = STATUS_DESTROY;

		if (file->buff) {
			free(file->buff);
		}

		if (file->save_buff) {
			free(file->save_buff);
		}

		if (file->fd > 0) {
			close(file->fd);
		}

		if (file) {
			free(file);
		}
	}
}

void zeus_elf32_init(struct zeus_elf_file *file) {
	Elf32_Ehdr *pEhdr;

	pEhdr = (Elf32_Ehdr *)file->buff;
	file->elf.elf32.pEhdr = pEhdr;
	file->elf.elf32.pShdr = (Elf32_Shdr *)(file->buff + pEhdr->e_shoff);
	file->elf.elf32.pPhdr = (Elf32_Phdr *)(file->buff + pEhdr->e_phoff);
}

void zeus_elf64_init(struct zeus_elf_file *file) {
	Elf64_Ehdr *pEhdr;

	pEhdr = (Elf64_Ehdr *)file->buff;
	file->elf.elf64.pEhdr = pEhdr;
	file->elf.elf64.pShdr = (Elf64_Shdr *)(file->buff + pEhdr->e_shoff);
	file->elf.elf64.pPhdr = (Elf64_Phdr *)(file->buff + pEhdr->e_phoff);
}

unsigned char zeus_elf_class(struct zeus_elf_file *file) {
	return (file->elf.elf32.pEhdr->e_ident[EI_CLASS]);
}

struct zeus_elf_file *zeus_elf_open(const char *path) {
	int ret = -1;
    off_t start, end;
	struct zeus_elf_file *file;
	Elf32_Ehdr *pEhdr;

	file = (struct zeus_elf_file *)malloc(sizeof(struct zeus_elf_file));
	if (!file) {
		goto bail;
	}
	memset(file, 0, sizeof(struct zeus_elf_file));
	file->status = STATUS_INIT;

	file->fd = open(path, O_BINARY | O_RDONLY);
	if (file->fd < 0) {
		goto bail;
	}

    start = lseek(file->fd, 0L, SEEK_CUR);
    end = lseek(file->fd, 0L, SEEK_END);
    lseek(file->fd, start, SEEK_SET);
    file->buff_size = end - start;

	file->buff = (char *)malloc(file->buff_size);
	if (!file) {
		goto bail;
	}

	if (read(file->fd, file->buff, file->buff_size) != file->buff_size) {
		goto bail;
	}

	pEhdr = (Elf32_Ehdr *)file->buff;
	if (!IS_ELF(*pEhdr)) {
		goto bail;
	}

	switch (pEhdr->e_ident[EI_CLASS]) {
	case ELFCLASS32:
		file->type = TYPE_ELF32;
		zeus_elf32_init(file);
		break;
	case ELFCLASS64:
		file->type = TYPE_ELF64;
		zeus_elf64_init(file);
		break;
	case ELFCLASSNONE:
	default:
		goto bail;
	}

	ret = 0;
	file->status = STATUS_READY;

bail:
	if (ret != 0) {
		zeus_elf_close(file);
		return (0);
	}
	return (file);
}

Elf32_Ehdr *zeus_elf32_get_ehdr(struct zeus_elf_file *file) {
	if (file->status != STATUS_READY) {
		return (0);
	}
	return (file->elf.elf32.pEhdr);
}

Elf32_Shdr *zeus_elf32_get_shdr(struct zeus_elf_file *file) {
	if (file->status != STATUS_READY) {
		return (0);
	}
	return (file->elf.elf32.pShdr);
}

Elf32_Phdr *zeus_elf32_get_phdr(struct zeus_elf_file *file) {
	if (file->status != STATUS_READY) {
		return (0);
	}
	return (file->elf.elf32.pPhdr);
}

void zeus_elf32_repair_section(struct zeus_elf_file *file) {
	int i;
	Elf32_Ehdr *pEhdr;
	Elf32_Shdr *pShdr;
	Elf32_Phdr *pPhdr, *pDynHdr = 0;
	Elf32_Dyn *pDyn;
	Elf32_Word	strSize;
	Elf32_Addr	strPptr;

	pEhdr = zeus_elf32_get_ehdr(file);
	pPhdr = zeus_elf32_get_phdr(file);

	for (i = 0; i < pEhdr->e_phnum; i++) {
		if (pPhdr[i].p_type == PT_DYNAMIC) {
			pDynHdr = &pPhdr[i];
			break;
		}
	}

	if (!pDynHdr) {
		return;
	}

	pDyn = (Elf32_Dyn *)(file->buff + pDynHdr->p_offset);
	for (i = 0; pDyn[i].d_tag != DT_NULL; i++) {
		switch (pDyn[i].d_tag) {
		case DT_STRTAB:
			strPptr = pDyn[i].d_un.d_ptr;
			break;
		case DT_STRSZ:
			strSize = pDyn[i].d_un.d_val;
			break;
		default:
			break;
		}
	}

	pShdr = zeus_elf32_get_shdr(file);
	for (i = 0; i < pEhdr->e_shnum; i++) {
		if (pShdr[i].sh_type == SHT_DYNAMIC) {
			pShdr[i].sh_addr = pDynHdr->p_vaddr;
			pShdr[i].sh_offset = pDynHdr->p_offset;
			pShdr[i].sh_size = pDynHdr->p_filesz;
		} else if (pShdr[i].sh_type == SHT_STRTAB) {
			pShdr[i].sh_addr = strPptr;
			pShdr[i].sh_offset = strPptr;
			pShdr[i].sh_size = strSize;
		}
	}
}

int zeus_elf_repair(struct zeus_elf_file *file, const char *path) {
	int fd, ret = 0;

	if (file->status != STATUS_READY) {
		return (-1);
	}

	if (file->save_buff_size < file->buff_size) {
		if (file->save_buff) {
			free(file->save_buff);
		}
		file->save_buff_size = 0;
	}

	file->save_buff = (char *)malloc(file->buff_size);
	if (!file->save_buff) {
		return (-2);
	}
	file->save_buff_size = file->buff_size;
	memcpy(file->save_buff, file->buff, file->buff_size);

	switch (zeus_elf_class(file)) {
	case ELFCLASS32:
		zeus_elf32_repair_section(file);
		break;
	case ELFCLASS64:
		break;
	}

	fd = open(path, O_WRONLY | O_BINARY | O_CREAT);
	if (fd > 0) {
		if (write(fd, file->buff, file->buff_size) != file->buff_size) {
		    fprintf(stderr, "ERROR: write file failed (%s)\n", strerror(errno));
			ret = -3;
		}
		close(fd);
	}

	memcpy(file->buff, file->save_buff, file->buff_size);

	return (ret);
}
