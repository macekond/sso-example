/*
 * Copyright (C) 2007-2011, GoodData(R) Corporation. All rights reserved.
 */
package com.gooddata.security.pgp;

import java.security.SecureRandom;

class RandomUtils {
    /**
     * {@link java.security.SecureRandom} instance used for certificate generation. Since creation of instance is expensive,
     * shared static instance can be used - {@link java.security.SecureRandom} is thread safe.
     */
    static final SecureRandom SECURE_RANDOM = new SecureRandom();
}
