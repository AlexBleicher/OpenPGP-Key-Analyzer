from OpenPGPKeyAnalyzer.Application.Util.CreateWeaknessJSON import createWeaknessJSON


def analyzeECCKWeaknesses(key_info, output, settings):
    foundWeaknesses = []
    foundWeaknesses.append(createWeaknessJSON("No checks for ECC implemented yet",
                                              "No checks for ECC implemented yet",
                                              "No checks for ECC implemented yet"))
    #TODO: Check for used curves (Literature: BSI and RFC9580)
    #TODO: Check parameters for possible side channel (need to check if feasible in practice)
    output["Found Weaknesses"] = foundWeaknesses