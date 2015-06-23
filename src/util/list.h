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
 * Author: Notis Hell (notishell@gmail.com)
 */
#ifndef SRC_UTIL_LIST_H_
#define SRC_UTIL_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Element of linked list must contain two pointers (previous, next).
 */
struct linked_list {
	struct linked_list *prev, *next;
};

static inline void linked_list_init(struct linked_list *head) {
	head->prev = head;
	head->next = head;
}

static inline void linked_list_add(struct linked_list *head, struct linked_list *element) {
	element->prev = head->prev;
	element->next = head;
	head->prev->next = element;
	head->prev = element;
}

static inline struct linked_list *linked_list_del(struct linked_list *element) {
	element->next->prev = element->prev;
	element->prev->next = element->next;
	return (element);
}

#define list_entry(ptr, type, member)\
	(type *)((char *)(ptr) - offsetof(type, member))

#define list_for_each(pos, head, member)\
    for ((pos) = list_entry((head)->next, typeof(*(pos)), member);\
    &((pos)->member) != (head); (pos) = list_entry((pos)->member.next, typeof(*pos), member))

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SRC_UTIL_LIST_H_ */
