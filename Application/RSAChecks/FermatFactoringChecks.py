# Copyright for code under fermatFactoringCheckPublicKey(). Original source: Badkeys by Hanno Böck. Copyright (c) Hanno Böck
import gmpy2

from Application.Util.CreateWeaknessJSON import *
import logging

logger = logging.getLogger(__name__)

def fermatFactoringCheckPrivateKey(key, foundWeaknesses, passphrase, settings):
    with key.unlock(passphrase):
        p = key._key.keymaterial.p
        q = key._key.keymaterial.q
        if p > q:
            diff = p - q
        else:
            diff = q - p
        effectiveLengthToCheck = settings["FermatFactoringEffectiveLengthToCheck"]
        if diff < 2 ** effectiveLengthToCheck:
            foundWeaknesses.append(createWeaknessJSON("Fermat Factoring Algorithm",
                                                      "The RSA Modulus can be factored efficiently with Fermat's Factoring Algorithm because p and q are too close together",
                                                      "Use a new RSA key pair that has been generated with a correct implementation of RSA"))
            logging.warning("RSA key vulnerable to Fermat's factoring algorithm")


def fermatFactoringCheckPublicKey(key, foundWeaknesses):
    n = key._key.keymaterial.n
    tries = 100
    a = gmpy2.isqrt(n)
    c = 0
    while not gmpy2.is_square(a ** 2 - n):
        a += 1
        c += 1
        if c > tries:
            return False
    bsq = a ** 2 - n
    b = gmpy2.isqrt(bsq)
    p = a + b
    q = a - b
    if (p * q == n):
        foundWeaknesses.append(createWeaknessJSON("Fermat Factoring Algorithm",
                                                  "The RSA Modulus can be factored efficiently with Fermat's Factoring Algorithm because p and q are too close together",
                                                  "Use a new RSA key pair that has been generated with a correct implementation of RSA"))
        logging.warning("RSA key vulnerable to Fermat's factoring algorithm")
