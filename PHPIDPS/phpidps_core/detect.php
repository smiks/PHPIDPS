<?php
include("functions.php");
include("settings.php");
class PHPIDPS_detection {

	var $threatLevel = 0;
	var $description = [];
	var $infectedRequests = ["GET" => false, "POST" => false];
	var $_tags = [];

	public function addTag($tag){
		array_push($this->_tags, $tag);
		return;
	}

	public function detect(){ 
		global $_PHPIDPS_postRequestsLimit, $_PHPIDPS_getRequestsLimit, $_PHPIDPS_getWhiteList, $_PHPIDPS_postWhiteList, 
				$_PHPIDPS_getBlackList, $_PHPIDPS_postBlackList;

		/* check limits */
		if(PHPIDPS_functions::checkLimitGet() > $_PHPIDPS_getRequestsLimit){
			$this->threatLevel += 5;
			$tmp = "Number of GET requests exceeds the limit.";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
		}

		if(PHPIDPS_functions::checkLimitPost() > $_PHPIDPS_postRequestsLimit){
			$this->threatLevel += 5;	
			$tmp = "Number of POST requests exceeds the limit (Limit is: {$_PHPIDPS_postRequestsLimit}).";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
		}

		/* check white/black lists */
		if(sizeof($_PHPIDPS_getWhiteList) > 0 && !checkWhiteListGet()){
			$this->threatLevel += 5;	
			$tmp = "Detected GET request argument that is not whitelisted.";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
		}

		if(sizeof($_PHPIDPS_postWhiteList) > 0 && !checkWhiteListPost()){
			$this->threatLevel += 5;	
			$tmp = "Detected POST request argument that is not whitelisted.";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
		}

		if(sizeof($_PHPIDPS_getBlackList) > 0 && checkBlackListGet()){
			$this->threatLevel += 5;	
			$tmp = "Detected blacklisted GET request argument";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
		}

		if(sizeof($_PHPIDPS_postBlackList) > 0 && checkBlackListPost()){
			$this->threatLevel += 5;	
			$tmp = "Detected blacklisted POST request argument";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
		}


		/* check for suspicious data structures */
		if(PHPIDPS_functions::detectSuspiciousDatasctructureGet()){
			$this->threatLevel += 35;	
			$tmp = "Detected suspicious data structure in GET request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
			$tags = $this->addTag("Suspicious data structure");
		}

		if(PHPIDPS_functions::detectSuspiciousDatasctructurePost()){
			$this->threatLevel += 35;	
			$tmp = "Detected suspicious data structure in POST request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
			$tags = $this->addTag("Suspicious data structure");
		}	

		/* check for illegal characters */
		if(PHPIDPS_functions::detectCharactersGet()){
			$this->threatLevel += 25;	
			$tmp = "Detected illegal characters in GET request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
			$tags = $this->addTag("Suspicious characters");
		}

		if(PHPIDPS_functions::detectCharactersPost()){
			$this->threatLevel += 25;	
			$tmp = "Detected illegal characters in POST request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
			$tags = $this->addTag("Suspicious characters");
		}

		/* detect javascript "ON" events */
		if(PHPIDPS_functions::detectJSOnEventsGet()){
			$this->threatLevel += 40;	
			$tmp = "Detected possible XSS in GET request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
			$tags = $this->addTag("XSS");
		}

		if(PHPIDPS_functions::detectJSOnEventsPost()){
			$this->threatLevel += 40;	
			$tmp = "Detected possible XSS in POST request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
			$tags = $this->addTag("XSS");
		}


		/* detect XSS vectors */
		if(PHPIDPS_functions::detectXSSGet()){
			$this->threatLevel += 40;	
			$tmp = "Detected possible XSS in GET request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
			$tags = $this->addTag("XSS");
		}

		if(PHPIDPS_functions::detectXSSPost()){
			$this->threatLevel += 40;	
			$tmp = "Detected possible XSS in POST request";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
			$tags = $this->addTag("XSS");
		}



		/* detect sql injections */
		if(PHPIDPS_functions::detectSQLinjectionGet()){
			$this->threatLevel += 75;
			$tmp = "Detected possible SQL injection in GET request.";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["GET"] = true;
			$tags = $this->addTag("SQLi");
		}

		if(PHPIDPS_functions::detectSQLinjectionPost()){
			$this->threatLevel += 75;
			$tmp = "Detected possible SQL injection in POST request.";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
			$tags = $this->addTag("SQLi");
		}


		/* detect CSRF attack */
		if(PHPIDPS_functions::detectCSRF()){
			$this->threatLevel += 30;
			$tmp = "Detected possible CSRF attack .";
			array_push($this->description, $tmp);
			unset($tmp);
			$this->infectedRequests["POST"] = true;
			$tags = $this->addTag("CSRF");
		}
	}
}