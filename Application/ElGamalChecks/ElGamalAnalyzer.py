from Application.Util.CreateWeaknessJSON import *

def analyzeElGamalWeaknesses(key_info, output, settings):
    foundWeaknesses = []
    if settings["RFCVersion"] == "RFC4880":
        foundWeaknesses.append(createWeaknessJSON("PKCS1-v1.5 padding deprecated, Bleichenbacher attack on signatures possible",
                                                  "Using the deprecated PKCS1-v1.5 padding (which is the specified padding for OpenPGP implementations of RFC4880) is not recommended. It also allowed the attack on ElGamal signatures described by Bleichenbacher.",
                                                  "Implementation of a different padding, using a different encryption or signature algorithm."))
    elif settings["RFCVersion"] == "RFC9580":
        foundWeaknesses.append(createWeaknessJSON("Deprecated Algorithm ElGamal",
                                                  "The ElGamal Algorithm has been deprecated for both signature and encryption in RFC9580 due to its usage of the deprecated PKCS1_v1.5 padding.",
                                                  "Usage of another algorithm (ECC is recommended)."))
    foundWeaknesses.append(createWeaknessJSON("No further checks for ElGamal implemented yet",
                                              "No further checks for ElGamal implemented yet",
                                              "No checks for ElGamal implemented yet"))
    output["Found Weaknesses"] = foundWeaknesses