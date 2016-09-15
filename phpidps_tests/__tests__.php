<?php

$_CORE = "PHPIDPS/phpidps_core/";
include($_CORE . "detect.php");
include($_CORE . "xsslists.php");
include($_CORE . "sqlInjections.php");
include($_CORE . "falsePositives.php");

$_getRequestsLimit = 9999;
$_postRequestsLimit = 9999;


echo"<center>";
echo"<br>";

echo"<table border='1' style='width:100%;'>
<tr><td colspan='2'><center> <br>TESTING PHP IDPS<br>&nbsp; </center></td></tr>
<tr><td colspan='2'><b>TESTING GET REQUESTS FUNCTIONS</b></td></tr>";

$_GET = ["arg" => "white", "list" => true];
$_getWhiteList = ["arg", "list"];
$result = PHPIDPS_functions::checkWhiteListGet() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if all arguments are in white list </td><td> {$result} </td></tr>";

$_GET = ["arg" => "black", "list" => true];
$_getWhiteList = ["white", "list"];
$result = PHPIDPS_functions::checkWhiteListGet() == false ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if not all arguments are in white list </td><td> {$result} </td></tr>";

$_getWhiteList =[];

$_GET = ["arg" => "black", "list" => true];
$_getBlackList = ["list"];
$result = PHPIDPS_functions::checkBlackListGet() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if argument appears in blacklist </td><td> {$result} </td></tr>";

$_GET = ["arg" => "black", "list" => true];
$_getBlackList = ["black"];
$result = PHPIDPS_functions::checkBlackListGet() == false ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if none of the arguments is blacklisted </td><td> {$result} </td></tr>";

$_getBlackList = [];

$_GET = ["arg'" => "\\black", "li<>st" => true, "/" => "!;\""];
$result = PHPIDPS_functions::detectCharactersGet() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing illegal characters in GET </td><td> {$result} </td></tr>";

$_GET = ["arg" => "black", "list" => true, ":_-"];
$result = PHPIDPS_functions::detectCharactersGet() == false ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if GET doesn't contain illegal characters </td><td> {$result} </td></tr>";

$_GET = ["onafterpring", "onbeforeprint", "onbeforeunload", "onerror", "onhashchange", 
			"onload", "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate", 
			"onresize", "onstorage", "onunload", "onblur", "onchange", "oncontextmenu", "onfocus", "oninput", 
			"oninput", "oninvalid", "onreset", "onsearch", "onselect", "onsubmit", "onkeydown", "onkeypress", 
			"onkeyup", "onclick", "ondbclick", "ondrag", "ondragend", "ondragenter", "ondragleave", 
			"ondragover", "ondratstart", "ondrop", "onmousedown", "onmousemove", "onmouseout", "onmouseover", 
			"onmouseup", "onmousewheel", "onscroll", "onwheel", "oncopy", "oncut", "onpaste", "onabort", 
			"oncanplay", "oncanplaythrough", "oncuechange", "ondurationchange", "onemptied", "onended", "onloadeddata", 
			"onloadedmetadata", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onseeked", "onseeking", 
			"oninstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "onshow", "ontoggle"];
$result = PHPIDPS_functions::detectJSOnEventsGet() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if GET contains any JavaScript onevents </td><td> {$result} </td></tr>";



echo"<tr><td colspan='2'><b>TESTING POST REQUESTS FUNCTIONS</b></td></tr>";


$_POST = ["arg" => "white", "list" => true];
$_postWhiteList = ["arg", "list"];
$result = PHPIDPS_functions::checkWhiteListPost() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if all arguments are in white list </td><td> {$result} </td></tr>";

$_POST = ["arg" => "black", "list" => true];
$_postWhiteList = ["white", "list"];
$result = PHPIDPS_functions::checkWhiteListPost() == false ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if not all arguments are in white list </td><td> {$result} </td></tr>";

$_postWhiteList = [];

$_POST = ["arg" => "black", "list" => true];
$_postBlackList = ["list"];
$result = PHPIDPS_functions::checkBlackListPost() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if argument appears in blacklist </td><td> {$result} </td></tr>";

$_POST = ["arg" => "black", "list" => true];
$_postBlackList = ["black"];
$result = PHPIDPS_functions::checkBlackListPost() == false ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if none of the arguments is blacklisted </td><td> {$result} </td></tr>";

$_postBlackList = [];

$_POST = ["arg'" => "\\black", "li<>st" => true, "/" => "!;\""];
$result = PHPIDPS_functions::detectCharactersPost() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing illegal characters in POST </td><td> {$result} </td></tr>";

$_POST = ["arg" => "black", "list" => true, ":_-"];
$result = PHPIDPS_functions::detectCharactersPost() == false ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if POST doesn't contain illegal characters </td><td> {$result} </td></tr>";

$_POST = ["onafterpring", "onbeforeprint", "onbeforeunload", "onerror", "onhashchange", 
			"onload", "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate", 
			"onresize", "onstorage", "onunload", "onblur", "onchange", "oncontextmenu", "onfocus", "oninput", 
			"oninput", "oninvalid", "onreset", "onsearch", "onselect", "onsubmit", "onkeydown", "onkeypress", 
			"onkeyup", "onclick", "ondbclick", "ondrag", "ondragend", "ondragenter", "ondragleave", 
			"ondragover", "ondratstart", "ondrop", "onmousedown", "onmousemove", "onmouseout", "onmouseover", 
			"onmouseup", "onmousewheel", "onscroll", "onwheel", "oncopy", "oncut", "onpaste", "onabort", 
			"oncanplay", "oncanplaythrough", "oncuechange", "ondurationchange", "onemptied", "onended", "onloadeddata", 
			"onloadedmetadata", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onseeked", "onseeking", 
			"oninstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "onshow", "ontoggle"];
$result = PHPIDPS_functions::detectJSOnEventsPost() == true ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing if POST contains any JavaScript onevents </td><td> {$result} </td></tr>";


echo"<tr><td colspan='2'><b>TESTING XSS IN GET REQUEST</b></td></tr>";

$_PHPIDPS = new PHPIDPS_detection();

unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_1 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_1) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing first list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_1)."]</td></tr>";

unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_2 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_2) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing second list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_2)."]</td></tr>";

 
unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_3 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_3) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing third list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_3)."]</td></tr>";


unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_4 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_4) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing fourth list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_4)."]</td></tr>";

unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_5 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_5) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing fifth list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_5)."]</td></tr>";



unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_6 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_6) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing sixth list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_6)."]</td></tr>";

 
unset($_GET); 
$detectedXSS = 0;
foreach ($XSS_List_7 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_7) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing seventh list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_7)."]</td></tr>";


 
unset($_GET); 
$detectedSQLi = 0;
foreach ($sqlInjection1 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedSQLi += 1;
	}
}
$result = $detectedSQLi == sizeof($sqlInjection1) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing first list of SQL injections </td><td> {$result} [{$detectedSQLi}/".sizeof($sqlInjection1)."]</td></tr>";



unset($_GET); 
$detectedSQLi = 0;
foreach ($sqlInjection2 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedSQLi += 1;
	}
}
$result = $detectedSQLi == sizeof($sqlInjection2) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing second list of SQL injections </td><td> {$result} [{$detectedSQLi}/".sizeof($sqlInjection2)."]</td></tr>";



unset($_GET); 
$detectedSQLi = 0;
foreach ($sqlInjection3 as $key => $value) {
	$infectedRequests["GET"] = false;
	$_GET[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["GET"]){
		$detectedSQLi += 1;
	}
}
$result = $detectedSQLi == sizeof($sqlInjection3) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing third list of SQL injections </td><td> {$result} [{$detectedSQLi}/".sizeof($sqlInjection3)."]</td></tr>";



echo"<tr><td colspan='2'><b>TESTING XSS IN POST REQUEST</b></td></tr>";

$_GET = [];
unset($_POST); 
$detectedXSS = 0;
foreach ($XSS_List_1 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_1) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing first list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_1)."]</td></tr>";



$_GET = [];
unset($_POST);
$detectedXSS = 0;
foreach ($XSS_List_2 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_2) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing second list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_2)."]</td></tr>";

$_GET = [];
unset($_POST);
$detectedXSS = 0;
foreach ($XSS_List_3 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_3) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing third list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_3)."]</td></tr>";

$_GET = [];
unset($_POST);
$detectedXSS = 0;
foreach ($XSS_List_4 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_4) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing fourth list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_4)."]</td></tr>";

$_GET = [];
unset($_POST);
$detectedXSS = 0;
foreach ($XSS_List_5 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_5) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing fifth list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_5)."]</td></tr>";


$_GET = [];
unset($_POST);
$detectedXSS = 0;
foreach ($XSS_List_6 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_6) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing sixth list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_6)."]</td></tr>";

$_GET = [];
unset($_POST);
$detectedXSS = 0;
foreach ($XSS_List_7 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedXSS += 1;
	}
}
$result = $detectedXSS == sizeof($XSS_List_7) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing seventh list of XSS attacks </td><td> {$result} [{$detectedXSS}/".sizeof($XSS_List_7)."]</td></tr>";

$_GET = [];
unset($_POST);
$detectedSQLi = 0;
foreach ($sqlInjection1 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;	
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedSQLi += 1;
	}
}
$result = $detectedSQLi == sizeof($sqlInjection1) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing first list of SQL injections </td><td> {$result} [{$detectedSQLi}/".sizeof($sqlInjection1)."]</td></tr>";


$_GET = [];
unset($_POST);
$detectedSQLi = 0;
foreach ($sqlInjection2 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedSQLi += 1;
	}
}
$result = $detectedSQLi == sizeof($sqlInjection2) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing second list of SQL injections </td><td> {$result} [{$detectedSQLi}/".sizeof($sqlInjection2)."]</td></tr>";


$_GET = [];
unset($_POST);
$detectedSQLi = 0;
foreach ($sqlInjection3 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if($infectedRequests["POST"]){
		$detectedSQLi += 1;
	}
}
$result = $detectedSQLi == sizeof($sqlInjection3) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing third list of SQL injections </td><td> {$result} [{$detectedSQLi}/".sizeof($sqlInjection3)."]</td></tr>";



echo"<tr><td colspan='2'><b>TESTING FALSE POSITIVES</b> (OK means not detected as positive)</td></tr>";



$_GET = [];
unset($_POST);
$detectedFP = 0;
foreach ($FP_1 as $key => $value) {
	$infectedRequests["POST"] = false;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if(!$infectedRequests["POST"]){
		$detectedFP += 1;
	}
}
$result = $detectedFP == sizeof($FP_1) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing regular text</td><td> {$result} [{$detectedFP}/".sizeof($FP_1)."]</td></tr>";


$_GET = [];
unset($_POST);
$detectedFP = 0;
foreach ($FP_2 as $key => $value) {
	$infectedRequests["POST"] = false;
	$threatLevel = 0;
	$_POST[$key] = $value;
	$_PHPIDPS->detect();
	if(!($infectedRequests["POST"] && $threatLevel > 25)){
		$detectedFP += 1;
	}
}
$result = $detectedFP == sizeof($FP_2) ? "<font color='#2D2'>OK</font>" : "<font color='#D22'>WRONG</font>";
echo"<tr><td> Testing text that might look like SQLi </td><td> {$result} [{$detectedFP}/".sizeof($FP_2)."]</td></tr>";




echo"</table>";
echo"</center>";

unset($_POST);
unset($_GET);