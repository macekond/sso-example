/*
 * Copyright (C) 2007-2011, GoodData(R) Corporation. All rights reserved.
 */
package com.gooddata.security.pgp;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecurityProvider {

    public static final String NAME = BouncyCastleProvider.PROVIDER_NAME;
    /**
     * Checks if required security provider has already been added and if no adds it via call of
     * {@link (java.security.Security).addProvider()} method.
     *
     * <p>
     *     This implementation relies on {@link org.bouncycastle.jce.provider.BouncyCastleProvider}.
     * </p>
     */
    static void ensureProviderAdded() {
        if (Security.getProvider(NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

    }
}
