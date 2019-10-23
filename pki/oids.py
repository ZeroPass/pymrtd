# File contains object identifiers specified in ICAO doc 9303 standard
id_icao_mrtd_security                  = '2.23.136.1.1'                # ICAO 9303-10-p22
id_icao_cscaMasterList                 = id_icao_mrtd_security + '.2'  # ICAO 9303-12-p26
id_icao_cscaMasterListSigningKey       = id_icao_mrtd_security + '.3'  # ICAO 9303-12-p27
id_icao_mrtd_security_aaProtocolObject = id_icao_mrtd_security + '.5'  # ICAO 9303-11-p38


# ICAO 9303-11-p37
bsi_de = '0.4.0.127.0.7'

# ICAO 9303-11-p39
id_PK      = bsi_de + '.2.2.1'
id_PK_DH   = id_PK  + '.1'
id_PK_ECDH = id_PK  + '.2'


id_TA      = bsi_de +  '.2.2.2'

# ICAO 9303-11-p39
id_CA                       = bsi_de   + '.2.2.3'

id_CA_DH                    = id_CA    + '.1'
id_CA_DH_3DES_CBC_CBC       = id_CA_DH + '.1'
id_CA_DH_AES_CBC_CMAC_128   = id_CA_DH + '.2'
id_CA_DH_AES_CBC_CMAC_192   = id_CA_DH + '.3'
id_CA_DH_AES_CBC_CMAC_256   = id_CA_DH + '.4'

id_CA_ECDH                  = id_CA      + '.2'
id_CA_ECDH_3DES_CBC_CBC     = id_CA_ECDH + '.1'
id_CA_ECDH_AES_CBC_CMAC_128 = id_CA_ECDH + '.2'
id_CA_ECDH_AES_CBC_CMAC_192 = id_CA_ECDH + '.3'
id_CA_ECDH_AES_CBC_CMAC_256 = id_CA_ECDH + '.4'

# ICAO 9303-11-p37
id_PACE = bsi_de + '2.2.4'


# ECDSA plain signatures oids
ecdsa_plain_signatures = bsi_de + '.1.1.4.1'
ecdsa_plain_SHA1       = ecdsa_plain_signatures + '.1'
ecdsa_plain_SHA224     = ecdsa_plain_signatures + '.2'
ecdsa_plain_SHA256     = ecdsa_plain_signatures + '.3'
ecdsa_plain_SHA384     = ecdsa_plain_signatures + '.4'
ecdsa_plain_SHA512     = ecdsa_plain_signatures + '.5'
