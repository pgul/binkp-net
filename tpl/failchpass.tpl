<html>
<head>
<title>
[[title]] - Change password
</title>
<link rel="stylesheet" href="binkp.css" type="text/css">
<b>[[title]] - Change password</b><hr />
</head>
<body>
<p>
Change password failed: [[error]].
<form method=post action="[[myname]]">
<input type="hidden" name="node" value="[[node]]">
<input type="hidden" name="m" value="p2">
<table>
<tr><td>Enter Current Password :</td><td><input type="password" name="pw" size=16 value="[[pw]]"></td></tr>
<tr><td>New Password :</td><td><input type="password" name="newpw" size=16></td></tr>
<tr><td>Confirm New Password :</td><td><input type="password" name="newpw2" size=16></td></tr>
<tr><td colspan=2 align=center><input type="submit" value="Enter"></td></tr>
</table>
</form>
</p>
</body>
</html>
