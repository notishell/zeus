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

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct zeus_elf_file {
	int fd;
	int buff_size;
	char *buff;
	int save_buff_size;
	char *save_buff;
	Elf32_Ehdr *pEhdr;
	Elf32_Shdr *pShdr;
	Elf32_Phdr *pPhdr;
};

void zeus_elf_close(struct zeus_elf_file *file) {
	if (file) {
		if (file->buff) {
			free(file->buff);
		}
		if (file->fd > 0) {
			close(file->fd);
		}
		if (file) {
			free(file);
		}
	}
}

struct zeus_elf_file *zeus_elf_open(const char *path) {
	int ret = -1;
    off_t start, end;
	struct zeus_elf_file *file;

	file = (struct zeus_elf_file *)malloc(sizeof(struct zeus_elf_file));
	if (!file) {
		goto bail;
	}
	memset(file, 0, sizeof(struct zeus_elf_file));

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
	file->pEhdr = (Elf32_Ehdr *)file->buff;
	file->pShdr = (Elf32_Shdr *)(file->buff + file->pEhdr->e_shoff);
	file->pPhdr = (Elf32_Phdr *)(file->buff + file->pEhdr->e_phoff);

	ret = 0;

bail:
	if (ret != 0) {
		zeus_elf_close(file);
		return (0);
	}
	return (file);
}

Elf32_Ehdr *zeus_elf32_get_ehdr(struct zeus_elf_file *file) {
	return (file->pEhdr);
}

Elf32_Shdr *zeus_elf32_get_shdr(struct zeus_elf_file *file) {
	return (file->pShdr);
}

Elf32_Phdr *zeus_elf32_get_phdr(struct zeus_elf_file *file) {
	return (file->pPhdr);
}

int zeus_elf32_recovery(struct zeus_elf_file *file, const char *path) {
	return (0);
}
