import cmd
import os
import warnings
from time import sleep

from OpenPGPKeyAnalyzer.Application.DSAChecks.DSAAnalyzer import *
from OpenPGPKeyAnalyzer.Application.ECCChecks.ECCAnalyzer import *
from OpenPGPKeyAnalyzer.Application.ElGamalChecks.ElGamalAnalyzer import *
from OpenPGPKeyAnalyzer.Application.GeneralChecks.DeprecatedKeyVersionCheck import *
from OpenPGPKeyAnalyzer.Application.GeneralChecks.KeyLengthAnalyzer import *
from OpenPGPKeyAnalyzer.Application.KeyParser import *
from OpenPGPKeyAnalyzer.Application.RSAChecks.RSAAnalyzer import *
from OpenPGPKeyAnalyzer.Application.Settings.AlterSettings import *
from OpenPGPKeyAnalyzer.Application.Util.GeneralInformation import *

warnings.filterwarnings("ignore")


class OpenPGPKeyAnalyzerApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to the OpenPGP Key Analyzer. Type help or ? to list commands."

    def __init__(self, settingsPath):
        super().__init__()
        self.settingsPath = settingsPath
        self.settings = json.load(open(settingsPath))

    def analyzeKey(self, output, key_info, keyfile):
        key = key_info["key"]
        analyzeKeyLengths(key, output, self.settings)
        checkKeyVersion(key, output, self.settings)
        if key_info["algorithm"] in RSAAlgorithmIDs:
            analyzeRSAWeaknesses(key_info, keyfile, output, self.settings)
        elif key_info["algorithm"] in ElGamalAlgorithmIDs:
            analyzeElGamalWeaknesses(key_info, output, self.settings)
        elif key_info["algorithm"] in EllipticCurveAlgorithmIDs:
            analyzeECCKWeaknesses(key_info, output, self.settings)
        elif key_info["algorithm"] in DSAAlgorithmIDs:
            analyzeDSAWeaknesses(key_info, output, self.settings)
        elif key_info["algorithm"] in ElGamalSignatureID:
            logger.warning("Deprecated Algorithm used. Elgamal Signature Algorithm deprecated since RFC 4880")
            output["Algorithm Specific Weaknesses"] = [].append(
                createWeaknessJSON("Deprecated Algorithm used.",
                                   "The Elgamal Signature Algorithm deprecated since RFC 4880 due to an vulnerability discovered by Bleichenbacher.",
                                   "Usage of another algorithm (ECC is recommended)."))
        else:
            logger.warning("Unknown algorithm: " + key_info["algorithm"])
            output["Algorithm Specific Weaknesses"] = [].append(
                createWeaknessJSON("Usage of unknown or reserved algorithm",
                                   "The Usage of unknown or reserved algorithm IDs is discouraged for keys in practical settings",
                                   "Usage of an known algorithm (ECC is recommended)."))
        if key.subkeys is not None:
            output["Subkey Information"] = []
            subkeys = key.subkeys.items()
            for subkey in subkeys:
                subkey_info = parseKeyInfoFromKey(subkey[1], key_info["passphrase"])
                subkey_output = {}
                subkey_output["Algorithm"] = subkey_info["algorithmName"]
                self.analyzeKey(subkey_output, subkey_info, keyfile)
                output["Subkey Information"].append(subkey_output)

    def analyzeKeyFromFile(self, keyfile):
        output = {}
        general_info = parseKeyFromFile(keyfile, output)
        if general_info is None:
            print("Error parsing key from file: " + keyfile)
            return None
        self.analyzeKey(output, general_info["keyInfo"], keyfile)
        return output

    def do_analyze(self, arg):
        """Analyze a given Keyfile for possible Vulnerabilities"""
        output = {}
        try:
            if arg == "":
                print("Please enter a Keyfile to analyze.")
                arg = input()
            print("Analyzing the given Keyfile. This could take some time please stand by.")
            keyfile = arg
            output = self.analyzeKeyFromFile(keyfile)
            if output is not None:
                sleep(1) #To finish logging
                writeOutput = False
                while not writeOutput:
                    outputDir = input("Please enter the directory to save the output files: ").strip()
                    outputName = input("Please specify the name of the outputfile: ").strip()
                    outputName += ".json"
                    path = os.path.join(outputDir, outputName)
                    if os.path.exists(path):
                        print("Warning: Output file already exists, will overwrite it. Continue anyway (yes/no)? ")
                        userInput = input().strip()
                        if userInput == "yes":
                            writeOutput = True
                            os.remove(path)
                    elif not os.path.exists(outputDir):
                        print("No such path exists. Please input a correct path.")
                    else:
                        writeOutput = True
                    if writeOutput:
                        json.dump(output, open(path, 'w'), indent=4)
                print("Analysis complete. The result can be found under " + path)
            else:
                print("Analysis failed")
        except Exception as e:
            print("Exception occured: " + str(e))

    def do_analyzedir(self, arg):
        """Analyze every File in a Directory full of Keyfiles for possible Vulnerabilities"""
        output = []
        try:
            if arg == "":
                print("Please enter a directory to analyze.")
                arg = input()
            print("Analyzing all Keyfiles in the given directory. This could take some time please stand by.")
            for keyfile in os.listdir(arg):
                filepath = os.path.join(arg, keyfile)
                logger.info("Analysis for key: " + filepath)
                outputForKey = self.analyzeKeyFromFile(filepath)
                if outputForKey is not None:
                    output.append(outputForKey)
            if len(output) > 0:
                sleep(1) #To finish logging
                writeOutput = False
                while not writeOutput:
                    outputDir = input("Please enter the directory to save the output files: ").strip()
                    outputName = input("Please specify the name of the outputfile: ").strip()
                    outputName += ".json"
                    path = os.path.join(outputDir, outputName)
                    if os.path.exists(path):
                        print("Warning: Output file already exists, will overwrite it. Continue anyway (yes/no)? ")
                        userInput = input().strip()
                        if userInput == "yes":
                            writeOutput = True
                            os.remove(path)
                    elif not os.path.exists(outputDir):
                        print("No such path exists. Please input a correct path.")
                    else:
                        writeOutput = True
                    if writeOutput:
                        json.dump(output, open(path, 'w'), indent=4)
                print("Analysis complete. The result can be found under " + path)
            else:
                print("Analysis failed. No parseable key was found.")
        except Exception as e:
            print("Exception occured: " + str(e))

    def do_sources(self, arg):
        """Display the sources for implemented vulnerabilities"""
        for source in sources:
            print("---------------------------------------------------------------")
            print(source["name"]+ ":")
            print(source["source"])

    def do_settings(self, arg):
        """Display and alter Settings for Vulnerability Checks"""
        calledSettings(input, self.settingsPath)
        self.settings = json.load(open(self.settingsPath))

    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True

def main():
    path = os.path.join(os.getcwd(), "settings.json")
    if not os.path.exists(path):
        print("Warning! No settings for the application existed. settings.json file will be created in current directory with default values")
        settings = {"RFCVersion": "RFC4880", "UserSpecifiedKeyLength": -1, "FermatFactoringCheckIncluded": True, "FermatFactoringEffectiveLengthToCheck": 120, "LowPrivateExponentCheckIncluded": True, "LowPrivateExponentBound": "Estimated Bound", "LowPublicExponentCheckIncluded": True, "LowPublicExponentBound": 65537, "ROCACheckIncluded": True}
        json.dump(settings, open(path, 'w'))
    OpenPGPKeyAnalyzerApp(path).cmdloop()

if __name__ == '__main__':
    OpenPGPKeyAnalyzerApp("Application/Settings/settings.json").cmdloop()
