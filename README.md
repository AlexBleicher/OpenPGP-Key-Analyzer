# OpenPGP-Key-Analyzer
An Open Source Python CLI, which can parse keyfiles conforming to the OpenPGP standard and analyze them for vulnerability to known cryptographic weaknesses

## Supported Formats
The Analyzer supports OpenPGP Key Files in ASCII-armored or Binary Format.<br>
Both [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880.html) and [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) are supported.

:warning: <b>If no warning is created for a given key this does not automatically make the key secure against any attack. It only indicates, that no weakness to the already implemented vulnerabilities could be detected!</b>
## Installation
The OpenPGP Key Analyzer can be installed [via pip](https://pypi.org/project/OpenPGPKeyAnalyzer/) (it is encouraged to use a virtual environment):<br>
```pip install OpenPGPKeyAnalyzer```<br>
Alternatively you can execute the OpenPGPKeyAnalyzerApp.py file in the OpenPGPKeyAnalyzer Directory directly from this repository.

## Usage
If installed via pip: Enter the command <em>openpgp-analyze</em> in a shell wherever you installed the application to.<br>
> :warning: ***The first time you use this command a settings.json file will be created in an specified directory, if no settings.json yet exists there. This file will be read and written to by the application and can alter the workflow of evaluations. It therefore poses a potential security risk!***

After starting the application, a Python CLI will start. At the moment, the following commands are supportet:
<ol>
 <li><em>?</em> or <em>help</em>: Displays the allowed commands of the cli as well as their docstring</li>
 <li><em>settings</em>: Display the current settings and possibly alter them</li>
 <li><em>analyze</em>: Enter an OpenPGP Keyfile and evaluate it for cryptographic vulnerabilities</li>
 <li><em>analyzedir</em>: Enter the path to a directory and evaluate all OpenPGP Keyfiles in it. Only Keyfiles on the top level of the directory will be evaluated. No recursive check in subdirectories is currently implemented</li>
</ol>

## Implemented Checks
<ol>
 <li><b>Deprecated Key Version</b>: Checks if the version of a given Keyfile is deprecated according to the specified RFC</li>
 <li><b>Key lengths</b>: Checks wether a given Keyfile has an key length that is considered insecure according to the NIST and BSI specifications. Additionally, users can specify an effective key length against which Keyfiles should be checked</li>
 <li><b>Deprecated algorithm</b>; Checks, wether a given Keyfile uses an deprecated algorithm</li>
 <li><b>RSA specific checks: </b><ol>
  <li><b>Fermat Factoring Algorithm</b>: Checks an RSA key for vulnerability to Fermat's Factoring Algorithm</li>
  <li><b>Low private exponent</b>: Checks an RSA secret key for low private exponent</li>
  <li><b>Low public exponent</b>: Checks an RSA key for low public exponent </li>
  <li><b>ROCA</b>: Checks an RSA key for the ROCA vulnerability</li></ol></li>
 <li><b>Elgamal specific checks</b>: No further checks implemented yet</li>
 <li><b>DSA specific checks</b>: No further checks implemented yet</li>
 <li><b>ECC specific checks</b>: No further checks implemented yet</li>
</ol>

## Settings
| Setting                                      | Allowed Values                      | Default Value       | Purpose |
|----------------------------------------------|-------------------------------------|---------------------|---------|
| **RFCVersion**                               | RFC4880, RFC9580                   | RFC4880            | Specifies the RFC version a key should be checked against. |
| **UserSpecifiedKeyLength**                   | Integer values greater than 0       | -1                 | Specifies the minimum effective key length a key must possess. |
| **FermatFactoringCheckIncluded**             | Boolean values                      | True               | Specifies whether the RSA key should be checked for vulnerabilities against Fermat's factoring algorithm. |
| **FermatFactoringEffectiveLengthToCheck**    | Integer values greater than 0       | 120                | Specifies the minimum bit-length difference between *p* and *q* in RSA keys for Fermat checks with secret keys. |
| **LowPrivateExponentCheckIncluded**          | Boolean values                      | True               | Specifies if a given RSA secret key should be checked for a low private exponent. |
| **LowPrivateExponentBound**                  | Estimated Bound, Boneh and Durfee Bound | Estimated Bound  | Specifies the bound to check the private exponent *d* of an RSA secret key against. |
| **LowPublicExponentCheckIncluded**           | Boolean values                      | True               | Specifies if a given RSA key should be checked for a low public exponent. |
| **LowPublicExponentBound**                   | Integer values greater than 3       | 65537              | Specifies the lower bound an RSA public exponent should have. |
| **ROCACheckIncluded**                         | Boolean values                      | True               | Specifies if a given RSA key should be checked for the ROCA vulnerability. |

