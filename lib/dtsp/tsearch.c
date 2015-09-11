/**
 * File: tsearch.c
 *
 * This code is part of Data Transfer Security Protocol (DTSP) library.
 *
 * ANSI C code for Tree search generalised from Knuth Algorithm T (6.2.2).
 * It is literally a copy of POSIX (not ANSI) search.h "t*" methods.
 * Many search.h implementations are missing "tdestroy" implementation.
 *
 * @author NetBSD Community Team (christos, lukem, kleink)
 * @author Alexander Lokhman <alex.lokhman@gmail.com>
 *
 * Copyright (c) 2015 Alexander Lokhman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Created on August 2015
 */

#include "tsearch.h"

typedef struct node {
    char *key;
    struct node *llink;
    struct node *rlink;
} node_t;

#if !TSEARCH_POSIX
#if !TSEARCH_DARWIN

/**
 * Search for an entry matching the given KEY in the tree pointed to by
 * *ROOTP and insert a new element if not found.
 *
 * @param key       Tree key
 * @param rootp     Tree root
 * @param compar    Comparison function
 *
 * @return new or existing entry
 */
void *tsearch(const void *key, void **rootp, int (*compar)(const void *, const void *)) {
    node_t *q, **vrootp = (node_t **) rootp;
    int r;

    assert(key != 0);
    assert(compar != 0);

    if (vrootp == 0)
        return 0;

    while (*vrootp != 0) {
        if ((r = (*compar)(key, (*vrootp)->key)) == 0)
            return *vrootp;

        vrootp = r < 0 ? &(*vrootp)->llink : &(*vrootp)->rlink;
    }

    if ((q = malloc(sizeof(node_t))) != 0) {
        *vrootp = q;
        q->key = (void *) key;
        q->llink = q->rlink = 0;
    }

    return q;
}

/**
 * Search for an entry matching the given KEY in the tree pointed to by
 * *ROOTP. If no matching entry is available return NULL.
 *
 * @param key       Tree key
 * @param rootp     Tree root
 * @param compar    Comparison function
 *
 * @return NULL or existing entry
 */
void *tfind(const void *key, const void **rootp, int (*compar)(const void *, const void *)) {
    node_t * const *vrootp = (node_t * const *) rootp;
    int r;

    assert(key != 0);
    assert(compar != 0);

    if (vrootp == 0)
        return 0;

    while (*vrootp != 0) {
        if ((r = (*compar)(key, (*vrootp)->key)) == 0)
            return *vrootp;

        vrootp = r < 0 ? &(*vrootp)->llink : &(*vrootp)->rlink;
    }

    return 0;
}

/**
 * Remove the element matching KEY from the tree pointed to by *ROOTP.
 *
 * @param key       Tree key
 * @param rootp     Tree root
 * @param compar    Comparison function
 *
 * @return pointer to the parent of the item deleted or NULL
 */
void *tdelete(const void *key, void **rootp, int (*compar)(const void *, const void *)) {
    node_t **vrootp = (node_t **) rootp;
    node_t *p, *q, *r;
    int cmp;

    assert(key != 0);
    assert(compar != 0);

    if (vrootp == 0 || (p = *vrootp) == 0)
        return 0;

    while ((cmp = (*compar)(key, (*vrootp)->key)) != 0) {
        p = *vrootp;
        vrootp = (cmp < 0) ? &(*vrootp)->llink : &(*vrootp)->rlink;
        if (*vrootp == 0)
            return 0;
    }

    r = (*vrootp)->rlink;
    if ((q = (*vrootp)->llink) == 0)
        q = r;
    else if (r != 0) {
        if (r->llink == 0) {
            r->llink = q;
            q = r;
        } else {
            for (q = r->llink; q->llink != 0; q = r->llink)
                r = q;

            r->llink = q->rlink;
            q->llink = (*vrootp)->llink;
            q->rlink = (*vrootp)->rlink;
        }
    }
    if (p != *vrootp)
        free(*vrootp);

    *vrootp = q;

    return p;
}

static void twalk_recurse(const node_t *root, void (*action)(const void *, const VISIT, const int), int level) {
    assert(root != 0);
    assert(action != 0);

    if (root->llink == 0 && root->rlink == 0)
        (*action)(root, leaf, level);
    else {
        (*action)(root, preorder, level);

        if (root->llink != 0)
            twalk_recurse(root->llink, action, level + 1);

        (*action)(root, postorder, level);

        if (root->rlink != 0)
            twalk_recurse(root->rlink, action, level + 1);

        (*action)(root, endorder, level);
    }
}

/**
 * Walk through the whole tree and call the ACTION callback for every node
 * or leaf.
 *
 * @param root      Tree root
 * @param action    Action function
 *
 * @return void
 */
void twalk(const void *root, void (*action)(const void *nodep, const VISIT which, const int depth)) {
    if (root != 0 && action != 0)
        twalk_recurse(root, action, 0);
}

#endif  /* TSEARCH_DARWIN */

static void tdestroy_recurse(node_t *root, void (*free_node)(void *nodep)) {
    if (root->llink != 0)
        tdestroy_recurse(root->llink, free_node);

    if (root->rlink != 0)
        tdestroy_recurse(root->rlink, free_node);

    (*free_node)((void *) root->key);

    free(root);
}

/**
 * Destroy the whole tree, call FREEFCT for each node or leaf.
 *
 * @param root      Tree root
 * @param free_node Memory free function
 *
 * @return void
 */
void tdestroy(void *root, void (*free_node)(void *nodep)) {
    node_t *vroot = (node_t *) root;

    if (vroot != 0)
        tdestroy_recurse(vroot, free_node);
}

#endif  /* TSEARCH_POSIX */
