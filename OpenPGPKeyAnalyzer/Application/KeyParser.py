from pgpy import PGPKey
import logging

logger = logging.getLogger(__name__)


def parseKeyFromFile(file_path, output):
    """
    Parses a PGP key file to determine its type and format.
    Args:
        file_path (str): Path to the PGP key file.
    Returns:
        dict: Information about the key type and format.
    """
    general_Info = {
        "format": None,
        "key": None,
        "keyInfo": None,
        "passphrase": None
    }
    try:
        # Read the key file
        with open(file_path, "rb") as f:
            key_data = f.read()

        # Try to parse it as ASCII-armored
        try:
            key, _ = PGPKey.from_blob(key_data.decode("utf-8"))
            general_Info["format"] = "ASCII Armor"
            general_Info["key"] = key
        except Exception:
            # If decoding as UTF-8 fails, treat it as binary
            key, _ = PGPKey.from_blob(key_data)
            general_Info["format"] = "Binary"
            general_Info["key"] = key

        if key.is_protected:
            print("Please enter the passphrase to unlock the given key")
            general_Info["passphrase"] = input()

        if key.expires_at is None:
            expirationDate = "Never"
            logger.warning("Expiration date should be set!")
        else:
            expirationDate = key.expires_at

        general_Info["keyInfo"] = parseKeyInfoFromKey(key, general_Info["passphrase"])
        output["Keyfile"] = file_path
        genInfo = {}
        genInfo["Protocol"] = key.key_algorithm.name
        genInfo["Secret Key"] = general_Info["keyInfo"]["is_private"]
        genInfo["Expiration Date"] = str(expirationDate)
        output["General Key Information"] = genInfo
        return general_Info

    except Exception as e:
        print(f"Error parsing PGP key: {e}")
        return None


def parseKeyInfoFromKey(key, passphrase):
    key_info = {
        "is_public": None,
        "is_private": None,
        "key": None,
        "algorithm": None,
        "algorithmName": None,
        "asciiArmoredData": None,
        "passphrase": None
    }
    key_info["algorithm"] = key.key_algorithm.value
    key_info["algorithmName"] = key.key_algorithm.name
    # Determine if the key is public or private
    if key.is_public:
        key_info["is_public"] = True
        key_info["is_private"] = False
    else:
        key_info["is_public"] = False
        key_info["is_private"] = True
    key_info["key"] = key
    key_info["asciiArmoredData"] = str(key) #To allow ROCA checks
    return key_info

