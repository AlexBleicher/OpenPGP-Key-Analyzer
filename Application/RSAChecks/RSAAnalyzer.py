from Application.RSAChecks.FermatFactoringChecks import *
from Application.RSAChecks.LowPrivateExponentRSAChecks import *
from Application.RSAChecks.LowPublicExponentRSACheck import *
from Application.RSAChecks.ROCAChecks import *
from Application.Util.CreateWeaknessJSON import *
import logging
logger = logging.getLogger(__name__)
def analyzeRSAWeaknesses(key_info, keyfile, output, settings):
    isPrivate = key_info['is_private']
    key = key_info['key']
    foundWeaknesses = []
    if key_info["algorithm"] in [2,3]:
        logger.warning("RSA Encrypt-Only and RSA Sign-Only deprecated since RFC2440. Use Key Flag in Signature Packets instead.")
        foundWeaknesses.append(createWeaknessJSON("Deprecated Algorithm ID",
                                                  "RSA Encrypt-Only and RSA Sign-Only deprecated since RFC2440.",
                                                  "Use Key Flag in Signature Packets to specify type of key and RSA Encrypt and Sign (ID 1) instead."))
    if settings["RFCVersion"] == "RFC4880":
        logger.warning("RSA algorithm specified in OpenPGP standard uses insecure and deprecated PKCS1-v1.5 padding")
        foundWeaknesses.append(createWeaknessJSON("PKCS1-v1.5 padding, Bleichenbacher attacks",
                                                  "Using the PKCS1-v1.5 padding (which is the specified padding for OpenPGP implementations of RFC4880) enables the Bleichenbacher attack. Sending adaptively chosen ciphers to an encryption oracle that tells if a given cipher is PKCS1-v1.5 conform allows attackers to limit the space of the possible messages until only the original message is left thus breaking the encryption. This attack could also be applied to signatures.",
                                                  "Implementation of a different padding, restricting access to an encryption oracle or using a different encryption or signature algorithm."))
    elif settings["RFCVersion"] == "RFC9580":
        logger.warning("Usage of RSA is deprecated in RFC9580")
        foundWeaknesses.append(createWeaknessJSON("Deprecated Algorithm RSA",
                                                  "The RSA encryption or signature algorithm is deprecated in RFC9580 due to its usage of the PKCS1-v1.5 padding algorithm that allowed Bleichenbacher attacks. No new Keys for RSA should be generated.",
                                                  "Using a different algorithm."))
    if settings["LowPublicExponentCheckIncluded"]:
        checkLowPublicExponent(key, foundWeaknesses, settings)

    if settings["ROCACheckIncluded"] and key_info["asciiArmoredData"] is not None:
        checkKeyForROCA(key_info["asciiArmoredData"], keyfile, foundWeaknesses)

    if isPrivate:
        passphrase = key_info["passphrase"]

        if settings["FermatFactoringCheckIncluded"]:
            fermatFactoringCheckPrivateKey(key, foundWeaknesses, passphrase, settings)
        if settings["LowPrivateExponentCheckIncluded"]:
            checkForLowPrivateExponent(key, foundWeaknesses, passphrase, settings)
    else:
        if settings["FermatFactoringCheckIncluded"]:
            fermatFactoringCheckPublicKey(key, foundWeaknesses)

    output["Algorithm Specific Weaknesses"] = foundWeaknesses
