<%
Option Explicit 

Response.AddHeader "Pragma","no-cache"
Response.AddHeader "cache-control", "no-store"
Response.Expires    = -1 


Sub Run()
	Dim s, r, key, info, name
	Dim o
	
	Dim key24 : key24 = "123456789012345678901234"
	Dim key16 : key16 = "1234567890123456"
	Dim key8 : key8 = "12345678"
	Dim iv16 : iv16 = "1234567890123456"
	Dim iv8 : iv8 = "12345678"
	

	s = Request("q")
	
	Set o = Server.CreateObject("CryptoppLib.Crypto")

	Response.Write "<table style='font-size:9pt' border='1''>"
	Response.Write "<tr><td>원문</td><td>" & s & "</td></tr>"
	Response.Write "<tr><td>&nbsp;</td><td>&nbsp;</td></tr>"
	
	Response.Write "<tr><td>AES</td><td>" & o.GetValidKeyLength("AES") & "</td></tr>"
	Response.Write "<tr><td>DES</td><td>" & o.GetValidKeyLength("DES") & "</td></tr>"
	Response.Write "<tr><td>3DES</td><td>" & o.GetValidKeyLength("3DES") & "</td></tr>"
	Response.Write "<tr><td>SEED</td><td>" & o.GetValidKeyLength("SEED") & "</td></tr>"
	
	Response.Write "<tr><td>&nbsp;</td><td>&nbsp;</td></tr>"
	
	

	r = o.ECB_Encrypt("AES", key16, s)
	Response.Write "<tr><td>AES/ECB</td><td>" & r & "</td></tr>"
	s = o.ECB_Decrypt("AES", key16, r)
	Response.Write "<tr><td>AES/ECB</td><td>" & s & "</td></tr>"

	r = o.CBC_Encrypt("AES", key16, iv16, s)
	Response.Write "<tr><td>AES/CBC</td><td>" & r & "</td></tr>"
	s = o.CBC_Decrypt("AES", key16, iv16, r)
	Response.Write "<tr><td>AES/CBC</td><td>" & s & "</td></tr>"	
	
	
	r = o.ECB_Encrypt("DES", key8, s)
	Response.Write "<tr><td>DES/ECB</td><td>" & r & "</td></tr>"
	s = o.ECB_Decrypt("DES", key8, r)
	Response.Write "<tr><td>DES/ECB</td><td>" & s & "</td></tr>"
	
	r = o.CBC_Encrypt("DES", key8, iv8, s)
	Response.Write "<tr><td>DES/CBC</td><td>" & r & "</td></tr>"
	s = o.CBC_Decrypt("DES", key8, iv8, r)
	Response.Write "<tr><td>DES/CBC</td><td>" & s & "</td></tr>"
	
	
	r = o.ECB_Encrypt("3DES", key24, s)
	Response.Write "<tr><td>3DES/ECB</td><td>" & r & "</td></tr>"
	s = o.ECB_Decrypt("3DES", key24, r)
	Response.Write "<tr><td>3DES/ECB</td><td>" & s & "</td></tr>"
	
	r = o.CBC_Encrypt("3DES", key24, iv8, s)
	Response.Write "<tr><td>3DES/CBC</td><td>" & r & "</td></tr>"
	s = o.CBC_Decrypt("3DES", key24, iv8, r)
	Response.Write "<tr><td>3DES/CBC</td><td>" & s & "</td></tr>"	
		
		
	r = o.ECB_Encrypt("SEED", key16, s)
	Response.Write "<tr><td>SEED/ECB</td><td>" & r & "</td></tr>"
	s = o.ECB_Decrypt("SEED", key16, r)
	Response.Write "<tr><td>SEED/ECB</td><td>" & s & "</td></tr>"

	r = o.CBC_Encrypt("SEED", key16, iv16, s)
	Response.Write "<tr><td>SEED/CBC</td><td>" & r & "</td></tr>"
	s = o.CBC_Decrypt("SEED", key16, iv16, r)
	Response.Write "<tr><td>SEED/CBC</td><td>" & s & "</td></tr>"	
			

	Response.Write " </table><br>"

	Set o = Nothing
	
End Sub 


Sub QookTest()
	Dim o
	Dim s, r
	
	s = Request("q")
	
	Set o = Server.CreateObject("CryptoppLib.Crypto")

	Dim key_0, iv_0
	key_0 = "hex:20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20"
    iv_0 = "QOOK)*)!"
	

	r = o.CBC_Encrypt("3DES", key_0, iv_0, s)
	Response.Write "3DES/CBC : " & r & "<br>"
	s = o.CBC_Decrypt("3DES", key_0, iv_0, r)
	Response.Write "3DES/CBC : " & s & "<br><br>"
	
End Sub 

%>


<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<html>
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=euc-kr">
  <title></title>
 </head>

 <body style="font-size:9pt">
	<form method="post" action="crypto.asp" >
	평문 : <input type="text" name="q" size="60" value="<%=Request("q")%>">
	<input type="submit" value="확인">
	</form>
	쿡 테스트<br>
	<% Call QookTest() %>
	<br>
	<% Call Run() %>
	
 </body>
</html>


<% Response.End %>