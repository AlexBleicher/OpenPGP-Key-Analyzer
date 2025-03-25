def checkDSAPrivateParametersForLLLReduction(key, foundWeaknesses, passphrase):
    with key.unlock(passphrase):
        q = key._key.keymaterial.q
        a = key._key.keymaterial.a
        k = key._key.keymaterial.k
    return True
