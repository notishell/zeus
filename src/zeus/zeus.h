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
#ifndef SRC_ZEUS_ZEUS_H_
#define SRC_ZEUS_ZEUS_H_

#include <sys/elf.h>

struct zeus_elf_file;

struct zeus_elf_file *zeus_elf_open(const char *);

Elf32_Ehdr *zeus_elf32_get_ehdr(struct zeus_elf_file *);

Elf32_Shdr *zeus_elf32_get_shdr(struct zeus_elf_file *);

Elf32_Phdr *zeus_elf32_get_phdr(struct zeus_elf_file *);

int zeus_elf32_repair(struct zeus_elf_file *, const char *);

void zeus_elf_close(struct zeus_elf_file *);

#endif /* SRC_ZEUS_ZEUS_H_ */
