from Application.Util.CreateWeaknessJSON import *
def analyzeECCKWeaknesses(key_info, output, settings):
    foundWeaknesses = []
    foundWeaknesses.append(createWeaknessJSON("No checks for ECC implemented yet",
                                              "No checks for ECC implemented yet",
                                              "No checks for ECC implemented yet"))
    output["Found Weaknesses"] = foundWeaknesses