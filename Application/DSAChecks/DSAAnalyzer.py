from Application.Util.CreateWeaknessJSON import *
import logging

logger = logging.getLogger(__name__)
def analyzeDSAWeaknesses(key_info, output, settings):
    foundWeaknesses = []
    if settings["RFCVersion"] == "RFC4880":
        logger.warning("DSA is deprecated by NIST. Usage not recommended.")
        foundWeaknesses.append(createWeaknessJSON("Warning: DSA has been deprecated by NIST",
                                                  "Usage of DSA is not recommended due to its deprecation by NIST. In the most recent RFC9580 for OpenPGP it has also been deprecated.",
                                                  "Usage of another algorithm (ECC is recommended)."))
    elif settings["RFCVersion"] == "RFC9580":
        logger.warning("DSA is deprecated in RFC9580.")
        foundWeaknesses.append(createWeaknessJSON("Deprecated Algorithm DSA",
                                                  "The DSA Algorithm has been deprecated in RFC9580.",
                                                  "Usage of another algorithm (ECC is recommended)."))
    foundWeaknesses.append(createWeaknessJSON("No further checks for DSA implemented yet",
                                              "No further checks for DSA implemented yet",
                                              "No further checks for DSA implemented yet"))
    output["Found Weaknesses"] = foundWeaknesses