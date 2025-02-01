import unittest

from pgpy import PGPKey

from Application.GeneralChecks.KeyLengthAnalyzer import *
from Application.RSAChecks.FermatFactoringChecks import *
from Application.RSAChecks.LowPrivateExponentRSAChecks import *
from Application.RSAChecks.LowPublicExponentRSACheck import *
from Application.RSAChecks.ROCAChecks import *


class TestClass(unittest.TestCase):
    def test_keyLengthRSAShort(self):
        key, _ = PGPKey.from_file('Testkeys/SelfGeneratedKeys/VulnerableKeys/ShortRSAPublicKey1.gpg')
        expectedOutput = {}
        temp = {}
        temp["Key Length"] = 1024
        temp["BSI Security Level"] = "Insecure"
        temp["NIST Security Level"] = "Insecure"
        temp["Meets User Key Length Specification"] = "False"
        expectedOutput["Key Length Information"] = temp
        actualOutput = {}
        testSettings = {}
        testSettings["UserSpecifiedKeyLength"] = 2048
        analyzeKeyLengths(key, actualOutput, testSettings)
        self.assertEqual(expectedOutput, actualOutput)

    def test_FermatWeakness(self):
        key, _ = PGPKey.from_file('Testkeys/SelfGeneratedKeys/VulnerableKeys/FermatTest1.gpg')
        expectedOutput = []
        weakness = {}
        weakness["Name of Weakness"] = "Fermat Factoring Algorithm"
        weakness[
            "Description"] = "The RSA Modulus can be factored efficiently with Fermat's Factoring Algorithm because p and q are too close together"
        weakness[
            "Countermeasure"] = "Use a new RSA key pair that has been generated with a correct implementation of RSA"
        expectedOutput.append(weakness)
        testSettings = {}
        testSettings["FermatFactoringEffectiveLengthToCheck"] = 120
        actualOutput = []
        fermatFactoringCheckPrivateKey(key, actualOutput, "test", testSettings)
        self.assertEqual(expectedOutput, actualOutput)

        key, _ = PGPKey.from_file('Testkeys/SelfGeneratedKeys/VulnerableKeys/FermatTest1.asc')
        expectedOutput = []
        weakness = {}
        weakness["Name of Weakness"] = "Fermat Factoring Algorithm"
        weakness[
            "Description"] = "The RSA Modulus can be factored efficiently with Fermat's Factoring Algorithm because p and q are too close together"
        weakness[
            "Countermeasure"] = "Use a new RSA key pair that has been generated with a correct implementation of RSA"
        expectedOutput.append(weakness)
        actualOutput = []
        fermatFactoringCheckPublicKey(key, actualOutput)
        self.assertEqual(expectedOutput, actualOutput)

    def test_ROCAWeakness(self):
        key = str(PGPKey.from_file('./Testkeys/KeysFromROCA/key04.pgp')[0])
        filepath = os.path.abspath('./Testkeys/KeysFromROCA/key04.pgp')
        expectedOutput = []
        weakness = {}
        weakness["Name of Weakness"] = "ROCA Vulnerability"
        weakness[
            "Description"] = "The ROCA Vulnerability has been found in the key and or one of its subkeys. The Key therefore has been created by a faulty library and should not be used, since the structure of the secret key can be guessed which makes Coppersmiths algorithm applicable. This allows the factorization of the RSA modulus."
        weakness[
            "Countermeasure"] = "Generate new keys with an secure library. Discontinue the usage of key generation with the faulty library."
        expectedOutput.append(weakness)
        actualOutput = []
        checkKeyForROCA(key, filepath, actualOutput)
        self.assertEqual(expectedOutput, actualOutput)

    def test_RSALowPublicExponent(self):
        key, _ = PGPKey.from_file('Testkeys/SelfGeneratedKeys/VulnerableKeys/LowPublicExponentTest1.asc')
        expectedOutput = []
        weakness = {}
        weakness["Name of Weakness"] = "Low public Exponent"
        weakness[
            "Description"] = "A low public Exponent in the RSA Algorithm can lead to the recovery of the message if enough ciphers with the same message are sent to different recipients using the Chinese Remainder Theorem."
        weakness[
            "Countermeasure"] = "Use a public Exponent that is bigger. A common public Exponent in RSA is 65537 due to its relatively low Hamming Weight."
        expectedOutput.append(weakness)
        testSettings = {}
        testSettings["LowPublicExponentBound"] = 65537
        actualOutput = []
        checkLowPublicExponent(key, actualOutput, testSettings)
        self.assertEqual(expectedOutput, actualOutput)

    def test_RSALowPrivateExponentEstimatedBound(self):
        key, _ = PGPKey.from_file('Testkeys/SelfGeneratedKeys/VulnerableKeys/RSALowPrivateExponent1.gpg')
        expectedOutput = []
        weakness = {}
        weakness["Name of Weakness"] = "Low private Exponent"
        weakness[
            "Description"] = "A low private Exponent in the RSA Algorithm can lead to the recovery of the private exponent d using Wieners attack or Coppersmiths technique."
        weakness["Countermeasure"] = "Use a private Exponent that exceeds half the bit length of the common modulus."
        expectedOutput.append(weakness)
        testSettings = {}
        testSettings["LowPrivateExponentBound"] = "Estimated Bound"
        actualOutput = []
        checkForLowPrivateExponent(key, actualOutput, "test", testSettings)
        self.assertEqual(expectedOutput, actualOutput)

    def test_RSALowPrivateExponentBonehAndDurfeeBound(self):
        key, _ = PGPKey.from_file('Testkeys/SelfGeneratedKeys/VulnerableKeys/RSALowPrivateExponent1.asc')
        expectedOutput = []
        weakness = {}
        weakness["Name of Weakness"] = "Low private Exponent"
        weakness[
            "Description"] = "A low private Exponent in the RSA Algorithm can lead to the recovery of the private exponent d using Wieners attack or Coppersmiths technique."
        weakness["Countermeasure"] = "Use a private Exponent that exceeds half the bit length of the common modulus."
        expectedOutput.append(weakness)
        testSettings = {}
        testSettings["LowPrivateExponentBound"] = "Boneh and Durfee Bound"
        actualOutput = []
        checkForLowPrivateExponent(key, actualOutput, "test", testSettings)
        self.assertEqual(expectedOutput, actualOutput)
