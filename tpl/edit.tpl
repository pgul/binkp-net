<html>
<head>
<title>
[[title]] - edit data
</title>
<link rel="stylesheet" href="binkp.css" type="text/css">
<b>[[title]] - EDIT</b><hr />
</head>
<body>
$!ifdef result
<p>[[result]]</p>
$!endif
<p>Edit data for node [[node]]</p>
<p>Set IP-address(es) or hostname (CNAME) for [[hostname]].binkp.net (use empty host to delete the record):</p>
$!ifdef myip
<p>Use special keyword <code>dyn</code> or <code>dyn:&lt;ip-addr&gt;</code> for dynamic ip. Then, poll [[myaka]] ([[myip]]) for automatically change it.</p>
$!endif
<p>
<form method=post action=[[myname]]>
<input type="hidden" name="m" value="u">
<input type="hidden" name="node" value="[[node]]">
<input type="hidden" name="pwc" value="[[pwc]]">
<table>
<tr><td> Host: </td><td><input type="text" name="host1" value="[[host1]]" size=16></td>
<td> Port: </td><td><input type="text" name="port1" value="[[port1]]" size=5></td></tr>
$!ifdef host1
<tr><td> Host: </td><td><input type="text" name="host2" value="[[host2]]" size=16></td>
<td> Port: </td><td><input type="text" name="port2" value="[[port2]]" size=5></td></tr>
$!ifdef host2
<tr><td> Host: </td><td><input type="text" name="host3" value="[[host3]]" size=16></td>
<td> Port: </td><td><input type="text" name="port3" value="[[port3]]" size=5></td></tr>
$!ifdef host3
<tr><td> Host: </td><td><input type="text" name="host4" value="[[host4]]" size=16></td>
<td> Port: </td><td><input type="text" name="port4" value="[[port4]]" size=5></td></tr>
$!endif
$!endif
$!endif
<tr><td colspan=4 align=center><input type="submit" value="Submit"></td></tr>
</table>
</form>
</p>
<p>
<a href="[[myname]]?m=p">Change password</a>
</p>
</body>
</html>
