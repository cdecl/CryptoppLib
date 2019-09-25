

Dim seed
Dim txt, key, iv, enc, rec

Set seed = CreateObject("CryptoppLib.Crypto")

txt = "12345678901234561234567890123456"
txt = "hex:31,32,33,34,35,36,37,38,39,30,31,32,33,34,35,36"
txt = "1234567890123456"
key = "1234567890abcdef"
iv = "hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00"
iv = "1234567890abcdef"


enc = seed.Encrypt("SEED/CBC", key, iv, txt)
rec = seed.Decrypt("SEED/CBC", key, iv, enc)
MsgBox txt & vbCrLf & enc & vbCrLf & rec

enc = seed.Encrypt("SEED/ECB", key, iv, txt)
rec = seed.Decrypt("SEED/ECB", key, iv, enc)
MsgBox txt & vbCrLf & enc & vbCrLf & rec


Set seed = Nothing 