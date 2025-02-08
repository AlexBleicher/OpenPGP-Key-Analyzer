#IDs are identical between RFC 4880 with RFC 6637 for ECC extension and RFC 9580
RSAAlgorithmIDs = [1,2,3]
ElGamalAlgorithmIDs = [16]
EllipticCurveAlgorithmIDs = [18,19,22,25,26,27,28]
DSAAlgorithmIDs = [17]
#Settings
possibleSettingsValuesRFC = ["RFC4880", "RFC9580"]
possibleSettingsBoundsLowPrivateExponentRSA=["Estimated Bound", "Boneh and Durfee Bound"]
#Sources
sources = [
    {
        "name": "RFC 4880",
        "source": "J. Callas, L. Donnerhacke, H. Finney, D. Shaw, and R. Thayer, 'OpenPGP message format', Internet "
                  "Request for Comments, Network Working Group, RFC 4880, Nov. 2007."
    },
    {
        "name": "RFC 9580",
        "source":  "P. Wouters, D. Huigens, J. Winter, and N. Yutaka, 'OpenPGP,' Internet Request for Comments, Internet Engineering Task Force (IETF), RFC 9580, Jul. 2024."
    },
    {
        "name": "BSI Key length recommendations",
        "source":   "BSI TR-02102-1: 'cryptographic mechanisms: Recommendations and key lengths version: 2024-1,' Bundesamt für Sicherheit in der Informationstechnik, Tech. Rep., Feb. 2024."
    },
    {
        "name": "NIST Key length recommendations",
        "source": "E. Barker, 'Recommendation for key management part 1: General,' National Institute of Standards and Technology, Tech. Rep. NIST SP 800-57pt1r4, May 2020."
    },
    {
        "name": "Fermat Factorization of RSA Keys",
        "source": "H. Böck, 'Fermat factorization in the wild,' Cryptology ePrint Archive, Paper 2023/026, Sep. 2023."
    },
    {
        "name": "ROCA",
        "source": "M. Nemec, M. Sys, P. Svenda, D. Klinec, and V. Matyas, 'The return of coppersmith’s attack: "
                  "Practical factorization of widely used RSA moduli,' in Proceedings of the 2017 ACM SIGSAC "
                  "Conference on Computer and Communications Security. Dallas Texas USA: ACM, Oct. 2030, pp. 1631–1648."
    },
    {
        "name": "Wieners attack on RSA with low private exponent",
        "source": "M. Wiener, 'Cryptanalysis of short rsa secret exponents,' IEEE Transactions on Information Theory, "
                  "vol. 36, no. 3, pp. 553–558, 1990."
    },
    {
        "name": "Boneh and Durfee bound on low private RSA exponents",
        "source": "D. Boneh and G. Durfee, 'Cryptanalysis of rsa with private key d less than n^0.292,"
                  "' IEEE Transactions on Information Theory, vol. 46, no. 4, pp. 1339–1349, 2000."
    },
    {
        "name": "Hastad on low RSA public exponents",
        "source": ". Hastad, 'N using rsa with low exponent in a public key network,' in Advances in Cryptology — "
                  "CRYPTO ’85 Proceedings, H. C. Williams, Ed. Berlin, Heidelberg Springer Berlin Heidelberg, 1986, "
                  "pp. 403–408"
    },
    {
        "name": "Boneh et al. on factoring RSA with low public exponent if bits of d are leaked",
        "source": "D. Boneh, G. Durfee, and Y. Frankel, 'An attack on rsa given a small fraction of the private key "
                  "bits,' in Advances in Cryptology — ASIACRYPT’98, K. Ohta and D. Pei, Eds. Berlin, Heidelberg: "
                  "Springer Berlin Heidelberg, 1998, pp. 25–34."
    },
    {
        "name": "Bleichenbachers attack on RSA with PKCS#1-v1.5 padding",
        "source": "D. Bleichenbacher, 'Chosen ciphertext attacks against protocols based on the rsa encryption "
                  "standard pkcs #1,' in Advances in Cryptology — CRYPTO ’98, H. Krawczyk, Ed. Berlin, Heidelberg: "
                  "Springer Berlin Heidelberg, 1998, pp. 1–12"
    },
    {
        "name": "Bleichenbachers attack on Elgamal signatures",
        "source": "D. Bleichenbacher, 'Generating elgamal signatures without knowing the secret key,' in Advances in "
                  "Cryptology — EUROCRYPT ’96, U. Maurer, Ed. Berlin, Heidelberg: Springer Berlin Heidelberg, 1996, "
                  "pp. 10–18."
    },

]