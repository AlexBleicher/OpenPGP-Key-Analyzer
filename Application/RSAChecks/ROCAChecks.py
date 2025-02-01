#Usage of ROCA Detection Tool. Copyright (c) 2017, CRoCS, EnigmaBridge Ltd.

from roca.detect import RocaFingerprinter
from Application.Util.CreateWeaknessJSON import *
import os
def checkKeyForROCA(key, keyfile, foundWeaknesses):
    foundWeakness = False
    detector = RocaFingerprinter()
    fname = os.path.basename(keyfile)
    res = detector.process_file_autodetect(key, fname)
    for l in res:
        for subl in l:
            for sub in subl:
                if(sub.marked):
                    foundWeakness = True
    if foundWeakness:
        foundWeaknesses.append(createWeaknessJSON("ROCA Vulnerability",
                                                  "The ROCA Vulnerability has been found in the key and or one of its subkeys. The Key therefore has been created by a faulty library and should not be used, since the structure of the secret key can be guessed which makes Coppersmiths algorithm applicable. This allows the factorization of the RSA modulus.",
                                                  "Generate new keys with an secure library. Discontinue the usage of key generation with the faulty library."))

