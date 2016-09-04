<?

include_once("core/settings.php");

include_once("core/detect.php");

function feedback(){
	global $threatLevel, $description, $infectedRequests, $tags;
	return array("threatLevel" => $threatLevel, 
				"description" => $description, 
				"infectedRequests" => $infectedRequests,
				"tags" => $tags);
}

/* run function that detects intrusion */
detect();

if($_autoBlock && $threatLevel >= $_threshold){
	unset($_GET);
	unset($_POST);
	exit("Threshold reached. Threat level is too high!.");
}

if($_autoUnsetGet && $infectedRequests["GET"] && $threatLevel >= $_threshold){
	unset($_GET);
}

if($_autoUnsetPost && $infectedRequests["POST"] && $threatLevel >= $_threshold){
	unset($_POST);
}