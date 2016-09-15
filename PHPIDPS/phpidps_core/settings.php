<?php

/* General settings */
$_PHPIDPS_threshold = 0;
$_PHPIDPS_autoBlock = false;  // auto unset both GET and POST and block execution when threshold reached
$_PHPIDPS_autoUnsetGet = true;  // auto unset GET when threshold reached
$_PHPIDPS_autoUnsetPost = true;  // auto unset POST when threshold reached
$_PHPIDPS_originURL = "avatar-rpg.net";
$_PHPIDPS_customFile = "custom.php"; // custom file to run when threshold is reached (if there is no file, none will be executed)
$_PHPIDPS_intrusionReport = ['description', 'tags', 'threatLevel', 'infectedRequests'];  // list what you want to print. Possible values 'description', 'tags', 'threatLevel', 'infectedRequests'

/* limit how many GET and POST requests can be made at once */
$_PHPIDPS_getRequestsLimit = 9999;
$_PHPIDPS_postRequestsLimit = 9999;

/* white/black list for GET and POST requests */
	/* white list - leave blank if you want it to be disabled */
	/* Put names of parameters in array eg.  array("parameter1", "parameter2") */
	$_PHPIDPS_getWhiteList = array();
	$_PHPIDPS_postWhiteList = array();

	/* black list - leave blank if you want it to be disabled */
	/* Put names of parameters in array eg.  array("parameter1", "parameter2") */
	$_PHPIDPS_getBlackList = array();
	$_PHPIDPS_postBlackList = array();