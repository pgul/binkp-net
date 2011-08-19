<html>
<head>
<title>
[[title]] - Registration page
</title>
<link rel="stylesheet" href="binkp.css" type="text/css">
<b>[[title]] - Registration</b><hr />
</head>
<body>
<p>Please enter your fidonet node number (in 3D-notation, i.e. 2:463/68) and <b>nodelist</b> sysop name.</p>
<p>If entered information will be correct (node listed in the current world fidonet nodelist and has matched sysop name) this system will send you confirmation code by fidonet netmail.
After receiving this code you should enter it in form of this site (page will be specified in the same netmail), and then you will be able to edit DNS records for your node.</p>
<p>Good luck!</p>
<p>
<form method=post action="[[myname]]">
<table>
<input type="hidden" name="m" value="r2">
<tr><td>Node :</td><td><input type="text" name="node" size=16></td></tr>
<tr><td>Sysop Name :</td><td><input type="text" name="sysop" size=32></td></tr>
<tr><td colspan=2 align=center><input type="submit" value="Send confirmation code"></td></tr>
</table>
</form>
</p>
</body>
</html>
