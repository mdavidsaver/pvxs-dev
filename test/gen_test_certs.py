#!/usr/bin/env python3
"""Generate a set of certificates and keys for use by unit tests.

Create a root CA, and an intermediate CA.
Intermediate CA will issue some client and server certificates.
"""

from pathlib import Path
from typing import List, Tuple, Optional

from OpenSSL import crypto

# certs only for testing.  no need to waste RNG
nBits = 2048

hashalg = 'sha256'

def getargs():
    from argparse import ArgumentParser
    P = ArgumentParser()
    P.add_argument('-O', '--outdir', metavar='DIR',
                   type=Path, default=Path(__file__).parent,
                   help='Write files to this directory')
    return P

def main(args):
    outdir = args.outdir
    expire = 10*365*24*60*60 # 10 years

    rootCA = create_cert(
        subject=[('CN', 'rootCA')],
        SN = 0,
        notAfter= expire,
        isCA = True,
    )
    write_cert(outdir / 'ca.pem', rootCA[0])
    write_p12(outdir / 'ca.p12', None, [rootCA[0]])
    # don't save the root CA key, this would be kept offline anyway,
    # and these certs are after all only for testing...

    # special case w/o intermediate CA
    superserver1 = create_cert(
        subject=[('CN', 'superserver1')],
        issuer=rootCA,
        SN = 1,
        notAfter= expire,
        isServer= True,
    )
    write_p12(outdir / 'superserver1.p12', superserver1, [rootCA[0]])
    write_cert(outdir / 'superserver1.pem', superserver1[0])
    write_key(outdir / 'superserver1.key', superserver1[1])

    intermediateCA = create_cert(
        subject=[('CN', 'intermediateCA')],
        issuer=rootCA,
        SN = 2,
        notAfter= expire,
        isCA = True,
    )
    # intermediate CA may be used for OCSP or CRL signing
    write_cert(outdir / 'intermediateCA.pem', intermediateCA[0])
    write_p12(outdir / 'intermediateCA.p12', intermediateCA, [rootCA[0]])

    full_chain = [intermediateCA[0], rootCA[0]]
    incomplete_chain = [rootCA[0]]

    # IOC is both client and server
    ioc1 = create_cert(
        subject=[('CN', 'ioc1')],
        issuer=intermediateCA,
        SN = 3,
        notAfter= expire,
        isServer= True,
        isClient= True,
    )
    write_p12(outdir / 'ioc1.p12', ioc1, full_chain)
    write_p12(outdir / 'ioc1-incomplete.p12', ioc1, incomplete_chain)

    server1 = create_cert(
        subject=[('CN', 'server1')],
        issuer=intermediateCA,
        SN = 4,
        notAfter= expire,
        isServer = True,
    )
    write_p12(outdir / 'server1.p12', server1, full_chain)

    server2 = create_cert(
        subject=[('CN', 'server2')],
        issuer=intermediateCA,
        SN = 5,
        notBefore= -1000, # will be expired
        isServer = True,
    )
    write_p12(outdir / 'server2-expired.p12', server2, full_chain)

    client1 = create_cert(
        subject=[('CN', 'client1')],
        issuer=intermediateCA,
        SN = 6,
        notAfter= expire,
        isClient= True,
    )
    write_p12(outdir / 'client1.p12', client1, full_chain)

    client2 = create_cert(
        subject=[('CN', 'client2')],
        issuer=intermediateCA,
        SN = 7,
        notAfter= expire,
        isClient= True,
    )
    write_p12(outdir / 'client2.p12', client2, full_chain, pw='oraclesucks')

def create_cert(subject: List[Tuple[str,str]],
                issuer : Optional[Tuple[crypto.X509, crypto.PKey]] = None,
                SN : Optional[int]=None,
                notBefore = 0,
                notAfter = 0,
                isCA = False,
                isServer = False,
                isClient = False,
    ) -> Tuple[crypto.X509, crypto.PKey]:
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, nBits)

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_pubkey(key)

    subj = cert.get_subject()
    for comp, val in subject:
        setattr(subj, comp, val)

    if issuer is None:
        issuer, ikey = cert, key # self-signed
    else:
        issuer, ikey = issuer

    cert.set_issuer(issuer.get_subject())

    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)

    if SN is not None:
        cert.set_serial_number(SN)

    # nsCertType = [] # deprecated
    keyUsage = []
    extendedKeyUsage = []

    if isCA:
        #nsCertType += [b'sslCA']
        if cert is not issuer:
            keyUsage += [b'digitalSignature']
            extendedKeyUsage += [b'serverAuth', b'clientAuth', b'OCSPSigning']
        else:
            pass # root CA doesn't need extendedKeyUsage
        keyUsage += [b'cRLSign', b'keyCertSign', ]

    if isServer or isClient:
        keyUsage += [b'digitalSignature', b'keyEncipherment']

    if isServer:
        #nsCertType += [b'server']
        extendedKeyUsage += [b'serverAuth']

    if isClient:
        #nsCertType += [b'client', b'email', b'objsign']
        extendedKeyUsage += [b'clientAuth']

    cert.add_extensions([
        crypto.X509Extension(b'subjectKeyIdentifier', False, b"hash", subject=cert),
    ])
    # for self-signed, must set subjectKeyIdentifier before authorityKeyIdentifier.
    # for others, makes no difference.
    cert.add_extensions([
        crypto.X509Extension(b'authorityKeyIdentifier', False, b"keyid:always,issuer:always", issuer=issuer),
        crypto.X509Extension(b'basicConstraints', True, b"CA:TRUE" if isCA else b"CA:FALSE"),
        #crypto.X509Extension(b'nsCertType', False, b', '.join(nsCertType)),
        crypto.X509Extension(b'keyUsage', False, b', '.join(keyUsage)),
    ])
    if extendedKeyUsage:
        cert.add_extensions([
            crypto.X509Extension(b'extendedKeyUsage', False, b', '.join(extendedKeyUsage)),
        ])

    cert.sign(ikey, hashalg)

    return cert, key

def write_p12(out : Path,
              pair : Optional[Tuple[crypto.X509, crypto.PKey]] = None,
              CAs : List[crypto.X509] = [],
              pw : str = None,
              ):
    P = crypto.PKCS12()

    if pair is not None:
        cert, key = pair
        P.set_certificate(cert)
        P.set_privatekey(key)

    P.set_ca_certificates(CAs)

    out.write_bytes(P.export(passphrase=pw.encode() if pw else b''))

def write_cert(out : Path, cert : crypto.X509):
    out.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def write_key(out : Path, key : crypto.PKey):
    out.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

if __name__=='__main__':
    main(getargs().parse_args())
