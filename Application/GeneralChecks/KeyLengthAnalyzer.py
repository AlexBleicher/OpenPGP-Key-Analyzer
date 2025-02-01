from Application.Util.GeneralInformation import *
import logging
keyLifetimesNIST = {
    0: "Insecure",
    112: "Secure up to 2030",
    128: "Secure beyond 2030"
}

keyLifetimesBSI = {
    0: "Insecure",
    120: "Secure up to 2030"
}

effectiveKeyLengthsBSIClassical = {
    2800: 120,
    3000: 128
}

effectiveKeyLengthsNISTClassical = {
    1024: 80,
    2048: 112,
    3072: 128,
    7680: 192,
    15360: 256
}

effectiveKeyLengthsBSIECC = {
    240: 120,
    250: 128
}

effectiveKeyLengthsNISTECC = {
    160: 80,
    224: 112,
    256: 128,
    384: 192,
    512: 256
}

logger = logging.getLogger(__name__)

def analyzeKeyLengths(key, output, settings):
    keysize = key.key_size
    algorithm = key.key_algorithm
    effectiveKeyLengthBSI = 0
    effectiveKeyLengthNIST = 0

    if algorithm in RSAAlgorithmIDs or algorithm in ElGamalAlgorithmIDs or algorithm in DSAAlgorithmIDs:
        effectiveKeyLengthBSI = setEffectiveKeyLength(keysize, effectiveKeyLengthsBSIClassical)
        effectiveKeyLengthNIST = setEffectiveKeyLength(keysize, effectiveKeyLengthsNISTClassical)
    elif algorithm in EllipticCurveAlgorithmIDs:
        keysize = keysize.key_size
        effectiveKeyLengthBSI = setEffectiveKeyLength(keysize, effectiveKeyLengthsBSIECC)
        effectiveKeyLengthNIST = setEffectiveKeyLength(keysize, effectiveKeyLengthsNISTECC)
    else:
        print("Unknown algorithm")  #TODO: Make this better

    bsiSecurityLevel = ""
    nistSecurityLevel = ""
    for key in keyLifetimesBSI.keys():
        if key <= effectiveKeyLengthBSI:
            bsiSecurityLevel = keyLifetimesBSI.get(key)
    for key in keyLifetimesNIST.keys():
        if key <= effectiveKeyLengthNIST:
            nistSecurityLevel = keyLifetimesNIST.get(key)

    userSpecifiedKeyLength = int(settings["UserSpecifiedKeyLength"])
    satisfies = "No User Key Length specified"
    if userSpecifiedKeyLength >= 0:
        satisfies = str(effectiveKeyLengthNIST >= userSpecifiedKeyLength)

    if bsiSecurityLevel == "Insecure":
        logger.warning("Key Length considered insecure by BSI")
    if nistSecurityLevel == "Insecure":
        logger.warning("Key Length considered insecure by NIST")
    if satisfies == "False":
        logger.warning("Key Length does not meet effective length specified by user")

    lengthInfo = {}
    lengthInfo["Key Length"] = keysize
    lengthInfo["BSI Security Level"] = bsiSecurityLevel
    lengthInfo["NIST Security Level"] = nistSecurityLevel
    lengthInfo["Meets User Key Length Specification"] = satisfies
    output["Key Length Information"] = lengthInfo



def setEffectiveKeyLength(keysize, applyingDict):
    currentEffectiveKeyLength = 0
    for value in applyingDict.keys():
        if value <= keysize:
            currentEffectiveKeyLength = applyingDict.get(value)
        else:
            return currentEffectiveKeyLength
    return currentEffectiveKeyLength
