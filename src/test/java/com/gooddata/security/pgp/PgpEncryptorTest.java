/*
 * Copyright (C) 2007-2011, GoodData(R) Corporation. All rights reserved.
 */
package com.gooddata.security.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

public class PgpEncryptorTest {

    /**
     * GoodData public key generated for tests.
     */
    static final String GOODDATA_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: GnuPG v1.4.9 (GNU/Linux)\n" +
            "\n" +
            "mQGhBExG6xERBACA7/8UMFWZhiy6KR9JuirPl42r/L/TXmefts/hmfknkxOSIRP5\n" +
            "OzMtRCXdpF7XxP6uBbMk6FSepv9cEqvGWnET+ncsqw3yeLxosD/b5Ypa1RRpyuRn\n" +
            "Z+hnXewojkKSRZGSkjTqnvFLZaKdo25yYrv0fvdM+1fEEl6tNUVthq2/AwCg5/Au\n" +
            "ZABOUHPIESa+QHgXeLvarFUD+JGei7WsWcVuZ7u2hrLMwzmJGATwAyveGkywCgka\n" +
            "ZTi7GR3S2QAxRq3CZI9qTkNUOiKoG7EzvmRsEBB6fg2tRaYX3LhBZYVp36xz56NZ\n" +
            "hldcEGYBYs5Cn8mOxvaceWmCWpq7+rrMXUkxXRFqBbMwgjRBzqV6s4l4hZH3eifb\n" +
            "FEsD/jiKXKmdC4FvXpJFhWUMwwF9/sJ2S14HSkiZ2VkvB6p+l6nRGYoBUcCicZCR\n" +
            "v/h3SqRwt1lI3+qDiajFcMJsDgSVDXsvNQGZ+Ht8oizbt0lOULuDVrcLAPWAFa7m\n" +
            "DZLLjMm9SlW06Za8BHWxl213Jk74wfLnLnmwXvnZNHIOREK7tE1Hb29kRGF0YSAo\n" +
            "R29vZERhdGEgdGVzdGluZyBrZXkgLSBnZW5lcmF0ZWQgZm9yIHVuaXR0ZXN0cykg\n" +
            "PHRlc3RAZ29vZGRhdGEuY29tPohgBBMRAgAgBQJMRusRAhsDBgsJCAcDAgQVAggD\n" +
            "BBYCAwECHgECF4AACgkQ/32AuAOa4dRgkgCg5+s15oNSeMBYQzaiBTH8EpYC71oA\n" +
            "n2ImhTbCSIjEHKxHJwKsElWgu+lEuQINBExG6xEQCACU7/OmfN/GvmV6UnUbGaXr\n" +
            "Vlve87IyABt+GABlXGnkNN5vC/Yu4MpYnp4cRj8vYdE1pODo9UsYlyhlVqHbnA76\n" +
            "xEa6Z6bjAudOoZfhA+YbfHa4GGbN8lGaOSOqdhxIL51iGEL7eVUI0H3N9DNHpe+K\n" +
            "v5CvHg9tK50zraRrh8Cq9VtSFjyrpakbhju7WjxNraDiaLkZF9nU/JHzcAyFpjIQ\n" +
            "mTQiX7HscbTRM/HzDWshpcWp6XoOMMJzWGEXH/AwMsD040ZpWue03SS+CfuQ+wy/\n" +
            "ffgMIC7DVJCAx3dnwKbIWf6RihmjjQLN7GVm5zw4zOHiRwU69B69UmT30oNHdORX\n" +
            "AAMFB/wLsBJSvH3coQ3z7qDhMTGzcD+ft3+JxCKe+YHx3QnELoKvd1VEhApOgveN\n" +
            "qDraqvSHcQd5pmOt+GayzDUOojX0UM47d7viBYJBfZ5hLMYwp33ahS6oUKpX1+LB\n" +
            "lyvXzM8PqBOcXvlH+wezwHEwG9BUsz3M2BP996DYPKoQ4JjWPvYwSYR4rx7kAAKf\n" +
            "H9mdW6kTW/RETXTD3Whhd424rS3I504y0J9wUc1RA9LDLIxrpWXsXLChAxkpZb6P\n" +
            "sp7kVK4TvasFeW5u0VHVGPrselxg4b/JB4vdB9yYjt4ogRRLHayaYkiZBZDFr24O\n" +
            "BTrL+pT9W3CaFHuhltGO4AdVv7kliEkEGBECAAkFAkxG6xECGwwACgkQ/32AuAOa\n" +
            "4dR4SQCfazRTcL+gH/47aHYkueDfUbRDhW4AoJMP3jWLip6q/T/owaYd8HhtzPiO\n" +
            "=wXjq\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";


    /**
     * Sample sso provider's private key generated for tests.
     */
    static final String SSO_PROVIDER_PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: GnuPG v1.4.9 (GNU/Linux)\n" +
            "\n" +
            "lQG7BExG64sRBADFJ+vTVvTj/HuisAoQAqKZWI5sivY04UzQB01sA4MTBVxselY2\n" +
            "qZuwt4DeOxdtkcORu7tqKn+zcVy3SU9Qf97SsbvOtTIaTxStyZeriPIaCUTSsvsX\n" +
            "TRbDopZJv/bg2qQp+kT9MGsh0dr9hmFZUuvFCSdx7wAVs2BIowjpjBJoywCgnpV7\n" +
            "W5t3wJIbGF0k9n5BUFXiH2EEALvxn/DlMb8ckc41RaDZBfHJ5cwkxNl7NHmgwG4z\n" +
            "oSzrkfwjTp6S43P5lDtVK80kbL+9Us/QKDgKQ71wHJZTYlptGGFt6IOPRe0VSB0H\n" +
            "s1OdzNa5n2h97LgrHdRkjx25FX5WNsCuQjIb3+x/uQrWXed6+rDzmh3wsHbqSU3P\n" +
            "6DnRA/4t4QEs+zdoTQ4PKnVGmKM6PCEQWRyr0wsY7OBCdVMDhDrmDemFTA3nGDmB\n" +
            "edf0R2VLmdpYvuZDWSaZjkVFs0PwoYwk5EMI99qkoRugRd8SqK8ddezUutWeokqU\n" +
            "tyz81jVGtN5D/cjPLTV6eFIkATTpFJKQ9OEafneXxuR3qxXSWgAAn2I9rK0sLMfO\n" +
            "hyhYpRMXf9SKZAARCKy0bUNhcEdlbWluaSBUZXN0IChDYXBHZW1pbmkgdGVzdGlu\n" +
            "ZyBrZXkuIEdlbmVyYXRlZCBieSBqaXJpLnphbG91ZGVrIC0gZm9yIHVuaXQgdGVz\n" +
            "dCBvbmx5ISkgPHRlc3RAY2FwZ2VtaW5pLmNvbT6IYAQTEQIAIAUCTEbriwIbAwYL\n" +
            "CQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEI9AmUkgvejYo08AnR1cn9slO9gZ8pIF\n" +
            "skyAg13rt0/fAJ9lN7kfFkMu4lHlPeSIAm95Wqdr/p0BMgRMRuuLEAQAkELdso0/\n" +
            "Nz3eEXFNFbDYB9XgkU3aJ2rAtOPrb7r/LVeZVfU4VRY0KSqKwdA22Tmyzoc1X24c\n" +
            "GtB80zuvFs1TMv3mZffp0P9vaKbZ538BpaEOI3R1/CRryI1T+ymMGRLOKAOCDQr/\n" +
            "qtqXkt2lsDh6orSyFx+JcehXzlpWgo5RflcAAwUD/3Sb11J9YP+A7UstoEqYY+f1\n" +
            "IFhMZriwXRi075NKVk/S3Yh4hlwcusY3wdnOM43aB/QtUh/XVNlTomhV7ZF3rlWu\n" +
            "lK4bg2m0zA5Ls809545gUwO9wwuZm4GeflXSMVlv+XZM4vVYz/yF3RWp0F3GbjMu\n" +
            "SacyYEVku06xcKriYlhoAAD6AwbEckQFvEjrNY3MSaKZgNtKwwFX/ZeFBtse+4Hq\n" +
            "T9cQ54hJBBgRAgAJBQJMRuuLAhsMAAoJEI9AmUkgvejYXIIAn1NYuxUEAFJB1Mva\n" +
            "4G3H6qS7XB8pAJ974HG6iS0QEk2QkvLVxSs9FEz1qg==\n" +
            "=oOtn\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";



    private static final String VALID_USER_JSON = "{\"email\": \"user@example.com\",\"validity\":1333559352}";
    private PgpEncryptor pgpEncryptor;


    @Before
    public void createEncryptor() {
        this.pgpEncryptor = new PgpEncryptor.Builder()
                .setPublicKeyForEncryption(IOUtils.toInputStream(GOODDATA_PUBLIC_KEY))
                .setSecretKeyForSigning(IOUtils.toInputStream(SSO_PROVIDER_PRIVATE_KEY))
                .setSecretKeyPassword(new char[0])
                .createPgpEncryptor();
    }

    @Test
    public void testSignMessage() throws Exception {
        // first decrypt file encrypted with GoodData public key and store result to the decryptedMessageOut
        pgpEncryptor.signMessage(IOUtils.toInputStream(VALID_USER_JSON),
                new ByteArrayOutputStream(),
                true);
    }


    @Test
    public void testSignAndEncryptValidMessage() throws Exception {
        final ByteArrayOutputStream signedMessageOut = new ByteArrayOutputStream();
        pgpEncryptor.signMessage(IOUtils.toInputStream(VALID_USER_JSON), signedMessageOut, true);

        final ByteArrayOutputStream encryptedMessageOut = new ByteArrayOutputStream();
        pgpEncryptor.encryptMessage(encryptedMessageOut, new ByteArrayInputStream(signedMessageOut.toByteArray()), true);
    }



    @Test
    public void testEncryptMessage() throws Exception {
        final ByteArrayOutputStream encryptedMessageOut = new ByteArrayOutputStream();
        pgpEncryptor.encryptMessage(encryptedMessageOut, IOUtils.toInputStream(VALID_USER_JSON), true);
    }

}
