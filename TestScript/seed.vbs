

Dim seed
Dim txt, key, enc, rec

Set seed = CreateObject("CryptoppLib.Seed")

txt = "abc±è"
key = "interpark"


enc = seed.Encrypt(key, txt)
rec = seed.Decrypt(key, enc)

Set seed = Nothing 

MsgBox txt & vbCrLf & enc & vbCrLf & rec