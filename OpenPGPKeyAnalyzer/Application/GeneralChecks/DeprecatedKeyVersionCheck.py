import logging
logger = logging.getLogger(__name__)
def checkKeyVersion(key, output, settings):
    version = key._key.header.version
    versionInfo = {}
    versionInfo["Key Version"] = version
    if settings["RFCVersion"] == "RFC4880" and version<4 or settings["RFCVersion"] == "RFC9580" and version<6:
        versionInfo["Deprecated"] = True
        logger.warning("Key Version deprecated according to specified RFC Version")
    else:
        versionInfo["Deprecated"] = False
    output["Key Version Information"] = versionInfo