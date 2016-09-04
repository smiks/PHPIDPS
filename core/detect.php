<?
include_once("functions.php");

$threatLevel = 0;
$description = [];
$infectedRequests = ["GET" => false, "POST" => false];
$tags = [];

function addTag($tag, $tags){
	foreach ($tags as $value) {
		if($tag == $value){
			return $tags;
		}
	}
	array_push($tags, $tag);
	return $tags;
}

function detect(){ 
	global $threatLevel, $description, $infectedRequests, $_getRequestsLimit, $_getWhiteList, $_getBlackList, 
			$_postRequestsLimit, $_postWhiteList, $_postBlackList, $tags;

	/* check limits */
	if(checkLimitGet() > $_getRequestsLimit){
		$threatLevel += 5;
		$tmp = "Number of GET requests exceeds the limit.";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
	}

	if(checkLimitPost() > $_postRequestsLimit){
		$threatLevel += 5;	
		$tmp = "Number of POST requests exceeds the limit.";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
	}

	/* check white/black lists */
	if(sizeof($_getWhiteList) > 0 && !checkWhiteListGet()){
		$threatLevel += 5;	
		$tmp = "Detected GET request argument that is not whitelisted.";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
	}

	if(sizeof($_postWhiteList) > 0 && !checkWhiteListPost()){
		$threatLevel += 5;	
		$tmp = "Detected POST request argument that is not whitelisted.";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
	}

	if(sizeof($_getBlackList) > 0 && checkBlackListGet()){
		$threatLevel += 5;	
		$tmp = "Detected blacklisted GET request argument";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
	}

	if(sizeof($_postBlackList) > 0 && checkBlackListPost()){
		$threatLevel += 5;	
		$tmp = "Detected blacklisted POST request argument";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
	}


	/* check for suspicious data structures */
	if(detectSuspiciousDatasctructureGet()){
		$threatLevel += 35;	
		$tmp = "Detected suspicious data structure in GET request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
		$tags = addTag("Suspicious data structure", $tags);
	}

	if(detectSuspiciousDatasctructurePost()){
		$threatLevel += 35;	
		$tmp = "Detected suspicious data structure in POST request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
		$tags = addTag("Suspicious data structure", $tags);
	}	

	/* check for illegal characters */
	if(detectCharactersGet()){
		$threatLevel += 25;	
		$tmp = "Detected illegal characters in GET request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
		$tags = addTag("Suspicious characters", $tags);
	}

	if(detectCharactersPost()){
		$threatLevel += 25;	
		$tmp = "Detected illegal characters in POST request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
		$tags = addTag("Suspicious characters", $tags);
	}

	/* detect javascript "ON" events */
	if(detectJSOnEventsGet()){
		$threatLevel += 40;	
		$tmp = "Detected possible XSS in GET request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
		$tags = addTag("XSS", $tags);
	}

	if(detectJSOnEventsPost()){
		$threatLevel += 40;	
		$tmp = "Detected possible XSS in POST request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
		$tags = addTag("XSS", $tags);
	}


	/* detect XSS vectors */
	if(detectXSSGet()){
		$threatLevel += 40;	
		$tmp = "Detected possible XSS in GET request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
		$tags = addTag("XSS", $tags);
	}

	if(detectXSSPost()){
		$threatLevel += 40;	
		$tmp = "Detected possible XSS in POST request";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
		$tags = addTag("XSS", $tags);
	}



	/* detect sql injections */
	if(detectSQLinjectionGet()){
		$threatLevel += 75;
		$tmp = "Detected possible SQL injection in GET request.";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["GET"] = true;
		$tags = addTag("SQLi", $tags);
	}

	if(detectSQLinjectionPost()){
		$threatLevel += 75;
		$tmp = "Detected possible SQL injection in POST request.";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
		$tags = addTag("SQLi", $tags);
	}


	/* detect CSRF attack */
	if(detectCSRF()){
		$threatLevel += 30;
		$tmp = "Detected possible CSRF attack .";
		array_push($description, $tmp);
		unset($tmp);
		$infectedRequests["POST"] = true;
		$tags = addTag("CSRF", $tags);
	}
}