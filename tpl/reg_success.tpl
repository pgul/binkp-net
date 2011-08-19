<html>
<head>
<title>
[[title]] - Confirmation success
</title>
<link rel="stylesheet" href="binkp.css" type="text/css">
<b>[[title]] - Confirmation success</b><hr />
</head>
<body>
<p>
Thank you for register in this site.
Now you can choose password for your account.
<form method=post action="[[myname]]">
<input type="hidden" name="code" value="[[code]]">
<input type="hidden" name="node" value="[[node]]">
<input type="hidden" name="m" value="setpass">
<table>
<tr><td>Enter Password :</td><td><input type="password" name="pw" size=16></td></tr>
<tr><td>Confirm Password :</td><td><input type="password" name="pw2" size=16></td></tr>
<tr><td colspan=2 align=center><input type="submit" value="Enter"></td></tr>
</table>
</form>
</p>
</body>
</html>
