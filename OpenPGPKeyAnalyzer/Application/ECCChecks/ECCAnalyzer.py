from OpenPGPKeyAnalyzer.Application.Util.CreateWeaknessJSON import createWeaknessJSON


def analyzeECCKWeaknesses(key_info, output, settings):
    foundWeaknesses = []
    foundWeaknesses.append(createWeaknessJSON("No checks for ECC implemented yet",
                                              "No checks for ECC implemented yet",
                                              "No checks for ECC implemented yet"))
    output["Found Weaknesses"] = foundWeaknesses