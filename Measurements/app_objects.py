#!/usr/bin/env python3
"""
app_objects.py - real application-layer security objects signed with OpenSSL 3.5.

Builds, for each signature algorithm, the objects the simulator models and measures their size:
  * JWS compact client assertion (RFC 7523 style) and access token (RFC 9068 style)
  * DPoP proof with the public key in the JOSE header (RFC 9449; AKP key type for ML-DSA/SLH-DSA)
  * enveloped XMLDSig over a pacs.008-like document, exclusive C14N, signer certificate in KeyInfo
Signatures are real (OpenSSL); ECDSA JWS signatures are converted to the raw r||s form of RFC 7518.
There is no registered XMLDSig URI for ML-DSA/SLH-DSA; an example URN is used.

    python3 app_objects.py  -> data/app_objects.csv
"""
import base64
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile

from lxml import etree

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(HERE, "certs")
O = os.path.expanduser("~/opt/openssl-3.5/bin/openssl")
ENV = dict(os.environ, LD_LIBRARY_PATH=os.path.expanduser("~/opt/openssl-3.5/lib"))
sys.path.insert(0, os.path.join(HERE, "..", "Simulation"))
import pqc_sim as S   # noqa: E402

ALGS = {"ECDSA-P256": ("ES256", "ECDSA-P256"), "RSA-2048": ("PS256", "RSA-2048"),
        "ML-DSA-44": ("ML-DSA-44", "ML-DSA-44"), "ML-DSA-65": ("ML-DSA-65", "ML-DSA-65"),
        "ML-DSA-87": ("ML-DSA-87", "ML-DSA-87"), "SLH-DSA-128s": ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s"),
        "SLH-DSA-128f": ("SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f")}
XMLDSIG_URI = {"ECDSA-P256": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
               "RSA-2048": "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def run(args, data=None):
    return subprocess.run([O] + args, env=ENV, input=data, capture_output=True, check=True).stdout


def der_to_raw_ecdsa(der):
    """DER ECDSA-Sig-Value -> 64-byte r||s (RFC 7518 section 3.4)."""
    assert der[0] == 0x30
    i = 2
    out = b""
    for _ in range(2):
        assert der[i] == 0x02
        n = der[i + 1]
        v = der[i + 2:i + 2 + n].lstrip(b"\x00")
        out += v.rjust(32, b"\x00")
        i += 2 + n
    return out


def sign(alg, key, msg):
    with tempfile.NamedTemporaryFile() as f:
        f.write(msg)
        f.flush()
        if alg == "ECDSA-P256":
            return der_to_raw_ecdsa(run(["dgst", "-sha256", "-sign", key, f.name]))
        if alg == "RSA-2048":
            return run(["dgst", "-sha256", "-sign", key, "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", f.name])
        return run(["pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", f.name])


def raw_pub(alg, key):
    der = run(["pkey", "-in", key, "-pubout", "-outform", "DER"])
    return der, der[-(S.SIGS[alg].pk):] if alg not in ("RSA-2048",) else der


def jwk(alg, key):
    spki, pub = raw_pub(alg, key)
    if alg == "ECDSA-P256":
        pt = spki[-65:]
        return {"kty": "EC", "crv": "P-256", "x": b64u(pt[1:33]), "y": b64u(pt[33:])}
    if alg == "RSA-2048":
        txt = run(["pkey", "-in", key, "-pubin" if False else "-noout", "-text_pub"]).decode()
        mod = "".join(l.strip() for l in txt.split("Modulus:")[1].split("Exponent")[0].splitlines()).replace(":", "")
        n = bytes.fromhex(mod).lstrip(b"\x00")
        return {"kty": "RSA", "n": b64u(n), "e": "AQAB"}
    return {"kty": "AKP", "alg": ALGS[alg][0], "pub": b64u(spki[-S.SIGS[alg].pk:])}


def jws(alg, key, header, claims):
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = sign(alg, key, f"{h}.{p}".encode())
    return f"{h}.{p}.{b64u(sig)}"


PACS008 = """<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"><FIToFICstmrCdtTrf><GrpHdr><MsgId>EXBKVNVX20261028000123</MsgId><CreDtTm>2026-10-28T09:15:42.123+07:00</CreDtTm><NbOfTxs>1</NbOfTxs><SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf></GrpHdr><CdtTrfTxInf><PmtId><InstrId>INSTR-0000123</InstrId><EndToEndId>E2E-2026-000123</EndToEndId><UETR>5f1c2a8e-3b4d-4c6e-9a7b-1d2e3f405162</UETR></PmtId><IntrBkSttlmAmt Ccy="VND">250000000</IntrBkSttlmAmt><IntrBkSttlmDt>2026-10-28</IntrBkSttlmDt><ChrgBr>SLEV</ChrgBr><Dbtr><Nm>Example Trading Company Limited</Nm><PstlAdr><StrtNm>Tran Hung Dao</StrtNm><BldgNb>12</BldgNb><TwnNm>Ha Noi</TwnNm><Ctry>VN</Ctry></PstlAdr></Dbtr><DbtrAcct><Id><Othr><Id>0123456789012</Id></Othr></Id></DbtrAcct><DbtrAgt><FinInstnId><BICFI>EXBKVNVX</BICFI></FinInstnId></DbtrAgt><CdtrAgt><FinInstnId><BICFI>EXCBVNVX</BICFI></FinInstnId></CdtrAgt><Cdtr><Nm>Example Supplier Joint Stock Company</Nm><PstlAdr><StrtNm>Le Loi</StrtNm><BldgNb>45</BldgNb><TwnNm>Ho Chi Minh City</TwnNm><Ctry>VN</Ctry></PstlAdr></Cdtr><CdtrAcct><Id><Othr><Id>9876543210987</Id></Othr></Id></CdtrAcct><RmtInf><Ustrd>Invoice 2026-10-0457 payment for goods delivered under contract 88/2026</Ustrd></RmtInf></CdtTrfTxInf></FIToFICstmrCdtTrf></Document>"""
DS = "http://www.w3.org/2000/09/xmldsig#"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"


def xmldsig(alg, key, cert_der):
    doc = etree.fromstring(PACS008.encode())
    digest = base64.b64encode(hashlib.sha256(etree.tostring(doc, method="c14n", exclusive=True)).digest()).decode()
    E = lambda tag, **kw: etree.Element(f"{{{DS}}}{tag}", nsmap={"ds": DS}, **kw)
    sig = E("Signature")
    si = etree.SubElement(sig, f"{{{DS}}}SignedInfo")
    etree.SubElement(si, f"{{{DS}}}CanonicalizationMethod", Algorithm=EXC)
    etree.SubElement(si, f"{{{DS}}}SignatureMethod", Algorithm=XMLDSIG_URI.get(alg, f"urn:example:xmldsig:{alg.lower()}"))
    ref = etree.SubElement(si, f"{{{DS}}}Reference", URI="")
    tr = etree.SubElement(ref, f"{{{DS}}}Transforms")
    etree.SubElement(tr, f"{{{DS}}}Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    etree.SubElement(tr, f"{{{DS}}}Transform", Algorithm=EXC)
    etree.SubElement(ref, f"{{{DS}}}DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    etree.SubElement(ref, f"{{{DS}}}DigestValue").text = digest
    sv = sign(alg, key, etree.tostring(si, method="c14n", exclusive=True))
    if alg == "ECDSA-P256":
        pass   # XMLDSig ECDSA also uses raw r||s (RFC 4050 / xmldsig-more)
    etree.SubElement(sig, f"{{{DS}}}SignatureValue").text = base64.b64encode(sv).decode()
    ki = etree.SubElement(sig, f"{{{DS}}}KeyInfo")
    xd = etree.SubElement(ki, f"{{{DS}}}X509Data")
    etree.SubElement(xd, f"{{{DS}}}X509Certificate").text = base64.b64encode(cert_der).decode()
    doc.append(sig)
    signed = etree.tostring(doc)
    return len(etree.tostring(sig)), len(signed) - len(PACS008.encode()), len(sv)


def main():
    rows = []
    for alg, (jalg, cdir) in ALGS.items():
        d = os.path.join(CERTS, cdir, "d2")
        key = os.path.join(d, "client.key")
        cert_der = run(["x509", "-in", os.path.join(d, "client.pem"), "-outform", "DER"])
        ca = jws(alg, key, {"alg": jalg, "kid": "client-2026-01", "typ": "JWT"},
                 {"iss": "client-8f3a2b", "sub": "client-8f3a2b", "aud": "https://as.examplebank.example/token",
                  "jti": "4e0b5c7a-2f61-4a8d-9c3e-71b2d6e0f915", "iat": 1793167200, "exp": 1793167260})
        at = jws(alg, key, {"alg": jalg, "kid": "as-2026-01", "typ": "at+jwt"},
                 {"iss": "https://as.examplebank.example", "sub": "user-0012345", "aud": "https://api.examplebank.example",
                  "client_id": "client-8f3a2b", "scope": "payments accounts", "jti": "c1d9e8f7-6a5b-4c3d-2e1f-0a9b8c7d6e5f",
                  "iat": 1793167200, "exp": 1793167500, "cnf": {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}})
        dp = jws(alg, key, {"typ": "dpop+jwt", "alg": jalg, "jwk": jwk(alg, key)},
                 {"jti": "e1j3V_bKic8-LAEB", "htm": "POST", "htu": "https://api.examplebank.example/payments",
                  "iat": 1793167210, "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"})
        xs, xadd, siglen = xmldsig(alg, key, cert_der)
        sg = S.SIGS[alg]
        m = S.Model()
        leaf = S.cert_len(sg, True, m)
        model = {
            "client_assertion": 440 + S.b64u(sg.sig), "access_token": 700 + S.b64u(sg.sig),
            "dpop": 400 + S.b64u(sg.sig) + S.b64u(S.b64u(sg.pk) + 90),
            "xmldsig": 750 + S.b64(sg.sig) + S.b64(leaf),
        }
        real = {"client_assertion": len(ca), "access_token": len(at), "dpop": len(dp), "xmldsig": xs}
        for obj in real:
            rows.append([alg, obj, real[obj], model[obj], siglen, len(cert_der)])
        print(alg, real, "model:", model)
    with open(os.path.join(HERE, "data", "app_objects.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["alg", "object", "real_bytes", "model_bytes", "sig_bytes", "signer_cert_der"])
        w.writerows(rows)


if __name__ == "__main__":
    main()
