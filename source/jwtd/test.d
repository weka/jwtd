module jwtd.test;

version (unittest) {

	version(UseBotan) {
		string private256 = q"EOS
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCr5790wT0yuSWn
yG+HOqgCr4JYLI4dCuygyHK6qJ5OvdB9RG1Rj531VXQ2F+BJGtvOxgah05X6y6jm
Ov/OL/NMN8S8MWMhXPYd9/NPOuJD+ricXalmp9pL5y2qrrAhrkTTlptbiYrq/PVe
e6qLXC7wp9RmMQDlTxlrkykzgTo/rbjMzP43wL2TovI2ATc+v15T63uhtk1mdAIs
EXiDljFhD6alW8+tHlZmF9EJERPfCE8LSRHHLt/V0HGnGr3Pq519Q/lL9TJSqWJ4
x4Lpjz715qDsN//8aEdvwyVRSACVNeceE4t/WVQSqVZZwfElz2y1uAyw8I6W+S6t
AJXfoc5JAgMBAAECggEAW2TjwlQ2kDAlV/XVbcT+rCbZmr1ddQ1ozvajIKAjQmPi
Y6cso69CYLvlBBlfkh5ofJ+FySWv2F3M11LIy7tsk7oWq6NqO8OryjUYM6hvwYqb
+e5F8SEOi0pGWjdzxwRa7U9mG52dsN96KJiBDISfJC1mXEpzWnbaYfokbpCnAlEf
mJrFoJwBj7PFcN/U0lyou2UJB8/JwtPx89Y4VVSu1SdQbwMSbxXyvWgeHpSwJCyt
BsHbSpYl2JDGv1bauLDp478Scr2+xdepEbOtfK5oTbNl7OBRG2GBViI+l746sPJ5
RZ2mfVSiHQ+sXM+0tUSNikyZPlOkGRuEoFL/it7TnQKBgQDgmY7A5eD32R526zLl
yCGwRcjd8399RoCPad8/euMlosSIw5Kb+Y3wIMZ2g4peaGTvDW6ne/YAwATIpsh2
swBVz+b0aIo0+6I42Udlb/FAYGKX0xjzg2FZSzCDR+DvS7g6el/JiduucM+34Gko
g7SflbpPMOziIWiBOVqTLkHvtwKBgQDD8D+NkEjHJhQmB7G3tqiH9Zjd3+AeYDKK
aTSBrBCzMhAXjbjwcY+bdlMvwWhcAwI0UQC3Tew25siHJtLpsfP6CLY/+81QYavD
dt1dbiB5ahpkbB8OYqDQH+rvI4fcyEnWhKGaEibI3VAY+nd9y11prHvwmcZOblpc
gEBzV34x/wKBgEBurQ5XpEdWCTBSXwKefFOmYW6S+UMGI8GAvOPoLBvS6xDVEk0e
tYJq1KSRLfPRfQs7TkBMBpHGhFjPx/iNd44mm3oIN4Xlnm8ynhHSoGI4hHBLxf+t
9BJ6yIsQ5s2falWUX8BghR4xDNYSUfimd/3EJXOsdHiW3vUbcAmDHrVXAoGBAKtp
IOACSnjWSige8Q0r4XHXnFz1/oX0WCKX+NQ8J/vsHwHL/O90GVLCh/GuPFLKWwJT
ntG9fJlm+iSqBTdmc27Ycj+1VB8u4unDsdKLhiNRfDdAE0ctZ0vLsGZ2aePu4BGn
xAwaNw3f9rNzYleNMnJA78hDbqWsiqaDmF6POxoXAoGAEsj9YmS8/kgoJITjNII6
04wowxcMS/eUffQ7bPizLDYRPQQ0CKhAPC+vVz+wWzJSgHCcuYmHBjG6940Ethg1
+AsWwkm893VF6r6eLjt7byoqfaJEbsZm9y2mQi353PHIChq7CynEQSI+kaPP3V28
FIb2otyo1D4EXhfhvIH2K1A=
-----END PRIVATE KEY-----
EOS";
	} else {
		string private256 = q"EOS
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq+e/dME9Mrklp8hvhzqoAq+CWCyOHQrsoMhyuqieTr3QfURt
UY+d9VV0NhfgSRrbzsYGodOV+suo5jr/zi/zTDfEvDFjIVz2HffzTzriQ/q4nF2p
ZqfaS+ctqq6wIa5E05abW4mK6vz1Xnuqi1wu8KfUZjEA5U8Za5MpM4E6P624zMz+
N8C9k6LyNgE3Pr9eU+t7obZNZnQCLBF4g5YxYQ+mpVvPrR5WZhfRCRET3whPC0kR
xy7f1dBxpxq9z6udfUP5S/UyUqlieMeC6Y8+9eag7Df//GhHb8MlUUgAlTXnHhOL
f1lUEqlWWcHxJc9stbgMsPCOlvkurQCV36HOSQIDAQABAoIBAFtk48JUNpAwJVf1
1W3E/qwm2Zq9XXUNaM72oyCgI0Jj4mOnLKOvQmC75QQZX5IeaHyfhcklr9hdzNdS
yMu7bJO6FqujajvDq8o1GDOob8GKm/nuRfEhDotKRlo3c8cEWu1PZhudnbDfeiiY
gQyEnyQtZlxKc1p22mH6JG6QpwJRH5iaxaCcAY+zxXDf1NJcqLtlCQfPycLT8fPW
OFVUrtUnUG8DEm8V8r1oHh6UsCQsrQbB20qWJdiQxr9W2riw6eO/EnK9vsXXqRGz
rXyuaE2zZezgURthgVYiPpe+OrDyeUWdpn1Uoh0PrFzPtLVEjYpMmT5TpBkbhKBS
/4re050CgYEA4JmOwOXg99kedusy5cghsEXI3fN/fUaAj2nfP3rjJaLEiMOSm/mN
8CDGdoOKXmhk7w1up3v2AMAEyKbIdrMAVc/m9GiKNPuiONlHZW/xQGBil9MY84Nh
WUswg0fg70u4OnpfyYnbrnDPt+BpKIO0n5W6TzDs4iFogTlaky5B77cCgYEAw/A/
jZBIxyYUJgext7aoh/WY3d/gHmAyimk0gawQszIQF4248HGPm3ZTL8FoXAMCNFEA
t03sNubIhybS6bHz+gi2P/vNUGGrw3bdXW4geWoaZGwfDmKg0B/q7yOH3MhJ1oSh
mhImyN1QGPp3fctdaax78JnGTm5aXIBAc1d+Mf8CgYBAbq0OV6RHVgkwUl8CnnxT
pmFukvlDBiPBgLzj6Cwb0usQ1RJNHrWCatSkkS3z0X0LO05ATAaRxoRYz8f4jXeO
Jpt6CDeF5Z5vMp4R0qBiOIRwS8X/rfQSesiLEObNn2pVlF/AYIUeMQzWElH4pnf9
xCVzrHR4lt71G3AJgx61VwKBgQCraSDgAkp41kooHvENK+Fx15xc9f6F9Fgil/jU
PCf77B8By/zvdBlSwofxrjxSylsCU57RvXyZZvokqgU3ZnNu2HI/tVQfLuLpw7HS
i4YjUXw3QBNHLWdLy7Bmdmnj7uARp8QMGjcN3/azc2JXjTJyQO/IQ26lrIqmg5he
jzsaFwKBgBLI/WJkvP5IKCSE4zSCOtOMKMMXDEv3lH30O2z4syw2ET0ENAioQDwv
r1c/sFsyUoBwnLmJhwYxuveNBLYYNfgLFsJJvPd1Req+ni47e28qKn2iRG7GZvct
pkIt+dzxyAoauwspxEEiPpGjz91dvBSG9qLcqNQ+BF4X4byB9itQ
-----END RSA PRIVATE KEY-----
EOS";
	}

	string public256 = q"EOS
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+e/dME9Mrklp8hvhzqo
Aq+CWCyOHQrsoMhyuqieTr3QfURtUY+d9VV0NhfgSRrbzsYGodOV+suo5jr/zi/z
TDfEvDFjIVz2HffzTzriQ/q4nF2pZqfaS+ctqq6wIa5E05abW4mK6vz1Xnuqi1wu
8KfUZjEA5U8Za5MpM4E6P624zMz+N8C9k6LyNgE3Pr9eU+t7obZNZnQCLBF4g5Yx
YQ+mpVvPrR5WZhfRCRET3whPC0kRxy7f1dBxpxq9z6udfUP5S/UyUqlieMeC6Y8+
9eag7Df//GhHb8MlUUgAlTXnHhOLf1lUEqlWWcHxJc9stbgMsPCOlvkurQCV36HO
SQIDAQAB
-----END PUBLIC KEY-----
EOS";

    string private384 = q"EOS
EOS";

    string public384 = q"EOS
EOS";

    string private512 = q"EOS
EOS";

    string public512 = q"EOS
EOS";

	version(UseBotan) {
		string es256_private = q"EOS
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgHxxA+0sQXmE4myibmhVT
l0ymANRHZBi4lNd22/F7NCWhRANCAAQy5KexZuIg/J8UAgC+VuWI85SdCWJtvrvI
TolSpdVp69vxmisrYd/F8WD2kZWGDdIa4EJsdwnzhYo5fcZIwTBw
-----END PRIVATE KEY-----
EOS";
	} else {
		string es256_private = q"EOS
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgg/gqKvqXVkiszRgw
txfuteSY9GfvEKh5GEH8qp13Az+hRANCAAQ99/1NXTPVC9/ihzR0PAbq5wQbhwNm
uB4h1zAIVXr5dM4miLaENFWHYuJOJpbLxg+AYlJlSZnOGtmUxFqY+I8O
-----END PRIVATE KEY-----
EOS";
	}

	string es256_public = q"EOS
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPff9TV0z1Qvf4oc0dDwG6ucEG4cD
ZrgeIdcwCFV6+XTOJoi2hDRVh2LiTiaWy8YPgGJSZUmZzhrZlMRamPiPDg==
-----END PUBLIC KEY-----
EOS";

		string es384_private = q"EOS
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAmGm9VDiSRyJsd51uD6zFK0gvTyLEcoSkYBcUl/pPdkMD/vo41bWNG
F2sFigYLcuigBwYFK4EEACKhZANiAATp/2wbbOdcM1uhzikBtjfMZ7EINbGNsbg0
BIYCjkw8mLInTADXG5JkickFlzX7gNJBsSX1Lmo/sy9o+hqbh8m9jvgpCeS6ySI6
ZGXVYliVoZeryBvHod2okqKamKY0bg0=
-----END EC PRIVATE KEY-----
EOS";

		string es384_public = q"EOS
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE6f9sG2znXDNboc4pAbY3zGexCDWxjbG4
NASGAo5MPJiyJ0wA1xuSZInJBZc1+4DSQbEl9S5qP7MvaPoam4fJvY74KQnkuski
OmRl1WJYlaGXq8gbx6HdqJKimpimNG4N
-----END PUBLIC KEY-----
EOS";

    string es512_private = q"EOS
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAwpRKaINqELw34fWnXu9fzsKVTXKcuEfbZX2RXJmAExnJMay14VjQ
+tXASWvE5/CcyeQciJGlvQNW6Z3XBljmnQmgBwYFK4EEACOhgYkDgYYABAA5czxA
R1DG+4zYiAcHJX5ktiW2XTgDUAb3h4ned4YFOnA68prdPM8H8OsKTspWxhdUHQ68
OiCA0uR1LoLlRrSu2wA7zCDJBx/8nwSW0KpsphPR0fmokWVzpYpAhE2az0M1GFmY
A8JsVWBwsK9cyDpf2uYczqrjQkoOTkXVO1U2Pnp1ag==
-----END EC PRIVATE KEY-----
EOS";

    string es512_public = q"EOS
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAOXM8QEdQxvuM2IgHByV+ZLYltl04
A1AG94eJ3neGBTpwOvKa3TzPB/DrCk7KVsYXVB0OvDoggNLkdS6C5Ua0rtsAO8wg
yQcf/J8EltCqbKYT0dH5qJFlc6WKQIRNms9DNRhZmAPCbFVgcLCvXMg6X9rmHM6q
40JKDk5F1TtVNj56dWo=
-----END PUBLIC KEY-----
EOS";

} // version (unittest)
