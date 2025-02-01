import gmpy2
from Application.Util.CreateWeaknessJSON import *
import logging

logger = logging.getLogger(__name__)
def checkForLowPrivateExponent(key, foundWeaknesses, passphrase, settings):
    with key.unlock(passphrase):
        d = key._key.keymaterial.d
        n = key._key.keymaterial.n
        boundToCheck = settings["LowPrivateExponentBound"]
        boundApplicable = True
        if boundToCheck == "Estimated Bound":
            bound = gmpy2.isqrt(n)
        elif boundToCheck == "Boneh and Durfee Bound":
            bound = pow(gmpy2.mpz(n), 0.292)
            upperEBound = pow(gmpy2.mpz(n), 1.875)
            e = key._key.keymaterial.e
            boundApplicable = e < upperEBound

        if boundApplicable and d < bound:
            foundWeaknesses.append(createWeaknessJSON("Low private Exponent",
                                   "A low private Exponent in the RSA Algorithm can lead to the recovery of the private exponent d using Wieners attack or Coppersmiths technique.",
                                   "Use a private Exponent that exceeds half the bit length of the common modulus."))
            logger.warning("RSA key with secret exponent lower than specified bound. Enables attacks like Wieners Attack or Boneh and Durfees Attack.")