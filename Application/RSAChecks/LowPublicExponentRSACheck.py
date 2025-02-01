from Application.Util.CreateWeaknessJSON import *
import logging

logger = logging.getLogger(__name__)
def checkLowPublicExponent(key, foundWeaknesses, settings):
    e = key._key.keymaterial.e
    bound = settings["LowPublicExponentBound"]
    if e < bound:
        foundWeaknesses.append(createWeaknessJSON("Low public Exponent",
                                                  "A low public Exponent in the RSA Algorithm can lead to the recovery of the message if enough ciphers with the same message are sent to different recipients using the Chinese Remainder Theorem.",
                                                  "Use a public Exponent that is bigger. A common public Exponent in RSA is 65537 due to its relatively low Hamming Weight."))
        logger.warning("RSA Public Exponent lower than specified Bound detected.")