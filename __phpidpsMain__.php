<?php
/*
author: smiks
version: 0.2
*/

$_CORE = "PHPIDPS/phpidps_core/";
if(!file_exists($_CORE . "settings.php")){
	exit("File " . $_CORE . "settings.php is not found");
}
if(!file_exists($_CORE . "detect.php")){
	exit("File " . $_CORE . "settings.php is not found");
}

include($_CORE . "settings.php");
include($_CORE . "detect.php");


/* run function that detects intrusion */
$_PHPIDPS = new PHPIDPS_detection();
$_PHPIDPS->detect();

$_PHPIDPS_threatLevel = $_PHPIDPS->threatLevel;
$_PHPIDPS_description = $_PHPIDPS->description;
$_PHPIDPS_infectedRequests = $_PHPIDPS->infectedRequests;
$_PHPIDPS_tags = $_PHPIDPS->tags;

if($_PHPIDPS_autoBlock && $_PHPIDPS_threatLevel >= $_PHPIDPS_threshold){
	unset($_GET);
	unset($_POST);
	exit("Threshold reached. Threat level is too high!.");
}

if($_PHPIDPS_autoUnsetGet && $_PHPIDPS_infectedRequests["GET"] && $_PHPIDPS_threatLevel >= $__PHPIDPSthreshold){
	unset($_GET);
}

if($_PHPIDPS_autoUnsetPost && $_PHPIDPS_infectedRequests["POST"] && $_PHPIDPS_threatLevel >= $_PHPIDPS_threshold){
	unset($_POST);
}
if(file_exists("PHPIDPS/phpidps_custom/" . $_PHPIDPS_customFile) && $_PHPIDPS_threatLevel >= $_PHPIDPS_threshold){
	include("PHPIDPS/phpidps_custom/" . $_PHPIDPS_customFile);
}

foreach($_PHPIDPS_intrusionReport as $report){
	if($report == "tags"){

		if(sizeOf($_PHPIDPS_tags) == 0) continue;

		echo"<br><b><big>TAGS:</b></big> ";
		$s = sizeof($_PHPIDPS_tags);
		$c = 1;
		echo"<b>";
		foreach ($_PHPIDPS_tags as $value) {
			echo"{$value}";
			if($c < $s){echo", ";}
			echo"&nbsp;&nbsp;";
			$c += 1;
		}
		echo"</b>";
	}

	elseif($report == "description"){

		if(sizeOf($_PHPIDPS_description) == 0) continue;

		echo"<br><br>Description<br>";
		foreach ($_PHPIDPS_description as $value) {
			echo"<li>{$value}</li>";
		}
	}

	elseif($report == "threatLevel"){

		if($_PHPIDPS_threatLevel == 0) continue;

		echo"<br><br><b>Threat level: </b> {$_PHPIDPS_threatLevel}<br>";
	}

	elseif($report == "infectedRequests"){

		if(sizeOf($_PHPIDPS_infectedRequests) == 0) continue;

		foreach ($_PHPIDPS_infectedRequests as $key => $value) {
			if($value){
				echo"Infected request: {$key}<br>";
			}
		}
	}	
}