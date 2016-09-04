<?php

/* General settings */
$_threshold = 0;
$_autoBlock = false;  // auto unset both GET and POST and block execution when threshold reached
$_autoUnsetGet = true;  // auto unset GET when threshold reached
$_autoUnsetPost = true;  // auto unset POST when threshold reached
$_originURL = "avatar-rpg.net";

/* limit how many GET and POST requests can be made at once */
$_getRequestsLimit = 9999;
$_postRequestsLimit = 9999;

/* white/black list for GET and POST requests */
	/* white list - leave blank if you want it to be disabled */
	/* Put names of parameters in array eg.  array("parameter1", "parameter2") */
	$_getWhiteList = array();
	$_postWhiteList = array();

	/* black list - leave blank if you want it to be disabled */
	/* Put names of parameters in array eg.  array("parameter1", "parameter2") */
	$_getBlackList = array();
	$_postBlackList = array();