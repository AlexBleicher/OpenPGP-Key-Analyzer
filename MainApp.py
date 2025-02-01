import cmd
import warnings
from time import sleep

from Application.DSAChecks.DSAAnalyzer import *
from Application.ECCChecks.ECCAnalyzer import *
from Application.ElGamalChecks.ElGamalAnalyzer import *
from Application.GeneralChecks.DeprecatedKeyVersionCheck import *
from Application.GeneralChecks.KeyLengthAnalyzer import *
from Application.KeyParser import *
from Application.RSAChecks.RSAAnalyzer import *
from Application.Settings.AlterSettings import *

warnings.filterwarnings("ignore")


class MyApp(cmd.Cmd):
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
                    path = os.path.join(outputDir, "output.json")
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
                    path = os.path.join(outputDir, "output.json")
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

    def do_settings(self, arg):
        """Display and alter Settings for Vulnerability Checks"""
        calledSettings(input, self.settingsPath)
        self.settings = json.load(open('Application/Settings/settings.json'))

    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True


if __name__ == '__main__':
    MyApp("Application/Settings/settings.json").cmdloop()
