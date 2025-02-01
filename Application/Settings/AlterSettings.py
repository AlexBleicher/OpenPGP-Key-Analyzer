import json
from Application.Util.GeneralInformation import *


def calledSettings(arg, settingsPath):
    try:
        exit = False
        settings = json.load(open(settingsPath, 'r'))
        userInput = arg
        while not exit:
            print("Current Settings: " + str(settings))
            print("To Alter Settings input 'alter'. If you want to exit the settings, "
                  "input 'exit' \n")
            if userInput is None or type(userInput) is not str:
                print("Please enter a command")
                userInput = input()
            if userInput == 'exit':
                exit = True
                break
            elif userInput == 'alter':
                print("Please enter the name of the setting you want to change. \n")
                userInput = input()
                if userInput == "exit":
                    exit = True
                    break
                elif userInput not in settings:
                    print("Unknown setting " + userInput)
                else:
                    settingToChange = userInput
                    if settingToChange == "RFCVersion":
                        print("The RFC version the keys should be checked against.\nAllowed Values: " + str(
                            possibleSettingsValuesRFC) +"\n")
                    elif settingToChange == "UserSpecifiedKeyLength":
                        print("A minimum Key length (effective length) the given key should have.\nAllowed Values: Numbers greater than 0\n")
                    elif settingToChange == "FermatFactoringCheckIncluded":
                        print(
                            "A given RSA Key should be checked against possible Fermat Factorization.\nAllowed Values: Booleans\n")
                    elif settingToChange == "FermatFactoringEffectiveLengthToCheck":
                        print(
                            "A effective Key Length that should be the minimum distance between the two primes p and q of an RSA key in order to disable Fermat Factoring Attacks. This check is only applicable for secret keys.\n Allowed Values: Numbers greater than 0\n")
                    elif settingToChange == "LowPrivateExponentCheckIncluded":
                        print("A given RSA secret Key should be checked against attacks using small private exponents like Wieners attack.\nAllowed Values: Booleans\n")
                    elif settingToChange == "LowPrivateExponentBound":
                        print("The possible Bounds to check the private exponent against.\nAllowed Values: " + str(possibleSettingsBoundsLowPrivateExponentRSA) + "\n")
                    elif settingToChange == "LowPublicExponentCheckIncluded":
                        print("A given RSA Key should be checked if the public exponent is low. This would enable some attacks like calculating back to the original message from sending multiple ciphers with the same message to different recipients and using the chinese remainder theorem on them.\nAllowed Values: Booleans\n")
                    elif settingToChange == "LowPublicExponentBound":
                        print("The minimum value a RSA public Exponent should have.\nAllowed Values: Numbers greater than 3")
                    elif settingToChange == "ROCACheckIncluded":
                        print("A given RSA Key shoult be checked for the ROCA vulnerability.\nAllowed Values: Booleans\n")
                    try:
                        print("Please enter the value you want to change the setting to.\n")
                        userInput = input()

                        if userInput == "exit":
                            exit = True
                            break
                        elif settingToChange == "RFCVersion" and userInput not in possibleSettingsValuesRFC:
                            raise Exception
                        elif settingToChange == "LowPrivateExponentBound" and userInput not in possibleSettingsBoundsLowPrivateExponentRSA:
                            raise Exception
                        elif settingToChange == "UserSpecifiedKeyLength" or settingToChange == "FermatFactoringEffectiveLengthToCheck":
                            userInput = int(userInput)
                            if userInput <= 0:
                                raise Exception
                        elif settingToChange == "LowPublicExponentBound":
                            userInput = int(userInput)
                            if userInput<=3:
                                raise Exception
                        elif settingToChange == "FermatFactoringCheckIncluded" or settingToChange == "LowPrivateExponentCheckIncluded" or settingToChange == "LowPublicExponentCheckIncluded" or settingToChange == "ROCACheckIncluded":
                            if userInput.lower() == "false":
                                userInput = False
                            elif userInput.lower() == "true":
                                userInput = True
                            else:
                                raise Exception
                        settings[settingToChange] = userInput
                        json.dump(settings, open(settingsPath, "w"))
                        print("Settings changed")
                    except Exception:
                        print("Entered Value not applicable to given setting: " + str(userInput))

            else:
                print("Unknown command " + userInput)
            userInput = None
    except Exception as e:
        print("Exception occured: " + str(e))
