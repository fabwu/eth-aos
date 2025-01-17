/**
 * \file
 * \brief Hello world application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>

int main(int argc, char *argv[])
{
    printf("Hello, world! from userspace\n");
    if (argc > 1) {
        printf("First argument: %s\n", argv[1]);
    }
    return EXIT_SUCCESS;
}
