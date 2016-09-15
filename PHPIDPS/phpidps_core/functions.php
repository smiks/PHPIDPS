<?php

class PHPIDPS_functions {
	/* functions for checking limit */
	public static function checkLimitGet(){
		global $_GET;
		return sizeof($_GET);
	}

	public static function checkLimitPost(){
		global $_POST;
		return sizeof($_POST);
	}

	/* functions for checking white and black lists */
	public static function checkWhiteListGet(){
		global $_GET, $_getWhiteList;
		
		foreach ($_GET as $key => $value) {
				if(!in_array($key, $_getWhiteList)){
					return false;
				}
		}
		return true;
	}

	public static function checkWhiteListPost(){
		global $_POST, $_postWhiteList;

		foreach ($_POST as $key => $value) {
				if(!in_array($key, $_postWhiteList)){
					return false;
				}
		}	
		return true;
	}


	public static function checkBlackListGet(){
		global $_GET, $_getBlackList;

		foreach ($_GET as $key => $value) {
				if(in_array($key, $_getBlackList)){
					return true;
				}
		}	
		return false;
	}

	public static function checkBlackListPost(){
		global $_POST, $_postBlackList;

		foreach ($_POST as $key => $value) {
				if(in_array($key, $_postBlackList)){
					return true;
				}
		}	
		return false;
	}

	/* detect suspicious datastructures */
	public static function detectSuspiciousDatasctructureGet(){
		global $_GET;

		foreach ($_GET as $key => $value) {
			if(is_array($key) || is_array($value) || is_object($key) || is_object($value)){
				return true;
			}
		}
		return false;
	}

	public static function detectSuspiciousDatasctructurePost(){
		global $_POST;

		foreach ($_POST as $key => $value) {
			if(is_array($key) || is_array($value) || is_object($key) || is_object($value)){
				return true;
			}
		}
		return false;
	}


	/* detect illegal characters in requests */
	public static $illegalCharacters = ["'", "\"", "\\", "/", "<", ">", ";", "!"];

	public static function detectCharactersGet(){
		global $_GET;

		foreach ($_GET as $key => $value) {
			foreach (self::$illegalCharacters as $chr) {
				if(is_array($key)){
					$tmp = "";
					foreach ($key as $k => $v) {
						$tmp .= $k." ".$v;
					}
					$key = $tmp;
				}
				if(is_array($value)){
					$tmp = "";
					foreach ($value as $k => $v) {
						$tmp .= $k." ".$v;
					}
					$value = $tmp;
				}
				if(strpos(urldecode($key), $chr) || strpos(urldecode($value), $chr)){
					return true;
				}
			}
		}

		return false;
	}

	public static function detectCharactersPost(){
		global $_POST;

		foreach ($_POST as $key => $value) {
			foreach (self::$illegalCharacters as $chr) {
				if(is_array($key)){
					$tmp = "";
					foreach ($key as $k => $v) {
						$tmp .= $k." ".$v;
					}
					$key = $tmp;
				}
				if(is_array($value)){
					$tmp = "";
					foreach ($value as $k => $v) {
						$tmp .= $k." ".$v;
					}
					$value = $tmp;
				}
				if(strpos(urldecode($key), $chr) || strpos(urldecode($value), $chr)){
					return true;
				}
			}
		}

		return false;
	}

	/* detect javascript ON events */
	public static $onEvents = ["onafterpring", "onbeforeprint", "onbeforeunload", "onerror", "onhashchange", 
				"onload", "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate", 
				"onresize", "onstorage", "onunload", "onblur", "onchange", "oncontextmenu", "onfocus", "oninput", 
				"oninput", "oninvalid", "onreset", "onsearch", "onselect", "onsubmit", "onkeydown", "onkeypress", 
				"onkeyup", "onclick", "ondbclick", "ondrag", "ondragend", "ondragenter", "ondragleave", 
				"ondragover", "ondratstart", "ondrop", "onmousedown", "onmousemove", "onmouseout", "onmouseover", 
				"onmouseup", "onmousewheel", "onscroll", "onwheel", "oncopy", "oncut", "onpaste", "onabort", 
				"oncanplay", "oncanplaythrough", "oncuechange", "ondurationchange", "onemptied", "onended", "onloadeddata", 
				"onloadedmetadata", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onseeked", "onseeking", 
				"oninstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "onshow", "ontoggle"];


	public static function detectJSOnEventsGet(){
		global $_GET;

		foreach ($_GET as $key => $value) {
			foreach (self::$onEvents as $event) {
				if(strpos(urldecode(strtolower($key)), $event) || strpos(urldecode(strtolower($value)), $event)){
					return true;
				}
			}
		}

		return false;
	}

	public static function detectJSOnEventsPost(){
		global $_POST;

		foreach ($_POST as $key => $value) {
			foreach (self::$onEvents as $event) {
				if(strpos(urldecode(strtolower($key)), $event) || strpos(urldecode(strtolower($value)), $event)){
					return true;
				}
			}
		}

		return false;
	}

	/* Detecting XSS vectors */
	public static $XSSpatterns = [
		#"/(.*)a(.*)l(.*)e(.*)r(.*)t(.*)/i",
		#"/(.*)a((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*l((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*e((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*r((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*t(.*)/i",
		"/(\W)*[^\s]+a((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*l((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*e((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*r((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*t(.*)(\s)*[^\s]+(\W)*/i",
		#"/(.*)e(.*)v(.*)a(.*)l(.*)/i",
		"/(\W)*[^\s]+e((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*v((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*a((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*l(.*)(\s)*[^\s]+(\W)*/i",
		#"/(.*)j(.*)a(.*)v(.*)a(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t(.*)/i",
		"/(\W)*[^\s]+j((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*a((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*v((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*a((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*s((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*r((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*i((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*p((&#x[0-9,a-f,A-F][0-9,a-f,A-F];)|(\s))*t(.*)(\s)*[^\s]+(\W)*/i",
		"/((\%3C)|<)script(.*)((\%3E)|>)(.*)((\%3C)|<)((\%2F)|\/)script((\%3E)|>)/i",
		"/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))(.*)(on(.*))*/i",
		"/((\%3C)|<)((\%53)|s|(\%73))((\%43)|c|(\%63))((\%52)|r|(\%72))((\%49)|i|(\%69))((\%50)|p|(\%70))((\%54)|t|(\%74))(.*)/i",
		"/(.*)((\%3C)|<)(.*)((\%53)|s|(\%73))((\%54)|t|(\%74))((\%59)|y|(\%79))((\%4C)|l|(\%6C))((\%65)|e|(\%45))(.*)*/i",
		"/(.*)\\00(.*)/i",
		"/(.*)\\0(.*)/i",
		"/(var)* (.*) = (.*)/i"
		];

	public static function detectXSSGet(){
		global $_GET;

		foreach ($_GET as $key => $value) {
			foreach (self::$XSSpatterns as $pattern) {
				if(!is_array($value) && preg_match($pattern, $value) || preg_match($pattern, html_entity_decode(urldecode($value))) || !is_array($key) && preg_match($pattern, $key) || preg_match($pattern, html_entity_decode(urldecode($key)))) {
					return true;
				}
			}
		}

		return false;
	}

	public static function detectXSSPost(){
		global $_POST;

		foreach ($_POST as $key => $value) {
			foreach (self::$XSSpatterns as $pattern) {
				if(!is_array($value) && preg_match($pattern, $value) || preg_match($pattern, html_entity_decode(urldecode($value))) || !is_array($key) && preg_match($pattern, $key) || preg_match($pattern, html_entity_decode(urldecode($key)))){
					#echo("Pattern: {$pattern}<br>");
					return true;
				}
			}
		}

		return false;
	}




	/* Detecting SQL injections */
	public static $SQLpatterns = [
		#"/' OR (.*)/i",
		#"/(.*)'[\)]* OR (.*)/i",
		"/(.*)'[\)]* OR (.*) [--]*/i",
		#"/' AND (.*)/i",
		#"/(.*)'[\)]* AND (.*)/i",
		"/(.*)'[\)]* AND (.*) [--]*/i",
		#"/' XOR (.*)/i",
		#"/(.*)'[\)]* XOR (.*)/i",
		"/(.*)'[\)]* XOR (.*) [--]*/i",
		"/^[']+$/i",
		"/(.*)'(\/\*\*\/)*--(\/\*\*\/)*(.*)/i",
		"/(.*)'(.*)[OR|AND]+(.*)*[=]+(.*)--/i",
		"/(.*)'(.*)[OR|AND]+(.*)--/i",
		"/(.*)(SELECT)+ (.*) (FROM)+(.*)/i",
		"/(.*)(SELECT)+ (.*)/i",
		"/(.*)(DROP)+(.*)/i",
		"/(.*)(DELETE FROM)+(.*)/i",
		"/(.*)(DELETE)+(.*)/i",
		"/(.*)(UPDATE)+(.*)/i",
		"/(.*)(ALTER)+(.*)/i",
		"/(.*)(INSERT)+(.*)/i",
		"/(.*)(GRANT)+(.*)/i",
		"/(.*)(MERGE)+(.*)/i",
		"/(.*)(UNION)+(.*)/i",
		"/(.*)(U(\/\*\*\/)*P(\/\*\*\/)*D(\/\*\*\/)*A(\/\*\*\/)*T(\/\*\*\/)*E(\/\*\*\/)*)+(.*)/i",
		"/(.*)(D(\/\*\*\/)*R(\/\*\*\/)*O(\/\*\*\/)*P)+(.*)/i",
		"/(.*)(D(\/\*\*\/)*E(\/\*\*\/)*L(\/\*\*\/)*E(\/\*\*\/)*T(\/\*\*\/)*E)+(.*)/i",
		"/(.*)(A(\/\*\*\/)*L(\/\*\*\/)*T(\/\*\*\/)*E(\/\*\*\/)*R)+(.*)/i",
		"/(.*)(I(\/\*\*\/)*N(\/\*\*\/)*S(\/\*\*\/)*E(\/\*\*\/)*R(\/\*\*\/)*T)+(.*)/i",
		"/(.*)(G(\/\*\*\/)*R(\/\*\*\/)*A(\/\*\*\/)*N(\/\*\*\/)*T)+(.*)/i",
		"/(.*)(M(\/\*\*\/)*E(\/\*\*\/)*R(\/\*\*\/)*G(\/\*\*\/)*E)+(.*)/i",
		"/(.*)(\/\*\*\/)*S(\/\*\*\/)*E(\/\*\*\/)*L(\/\*\*\/)*E(\/\*\*\/)*C(\/\*\*\/)*T(\/\*\*\/)*(.*)(\/\*\*\/)*F(\/\*\*\/)*R(\/\*\*\/)*O(\/\*\*\/)*M(.*)/i",
		"/(.*)(DECLARE)+(.*)(SET)+/i",
		"/(.*)(EXEC\((.*)\))+/i",
		"/(.*)([\d|\w]+=[\d|\w]+)*(.*)--/i",
		"/(.*)'(.*)[=|\||+|-]*(!)+(.*)'(.*)/i",
		"/(.*)'(.*)[=|\||+|-]+(.*)'(.*)/i"
		];


	public static function detectSQLinjectionGet(){
		global $_GET;

		foreach ($_GET as $key => $value) {
			foreach (self::$SQLpatterns as $pattern) {
				if((!is_array($value) && preg_match($pattern, $value)) || !is_array($key) && preg_match($pattern, $key)){
					return true;
				}
			}
		}

		return false;
	}

	public static function detectSQLinjectionPost(){
		global $_POST;

		foreach ($_POST as $key => $value) {
			foreach (self::$SQLpatterns as $pattern) {
				if((!is_array($value) && preg_match($pattern, $value)) || !is_array($key) && preg_match($pattern, $key)){
					#echo("Pattern: {$pattern}<br>");
					return true;
				}
			}
		}

		return false;
	}


	/* detecting CSRF attacks */
	public static function detectCSRF(){
		global $_POST, $_GET, $_PHPIDPS_originURL, $_SERVER;
		if((isset($_POST) || isset($_GET)) && isset($_SERVER['HTTP_REFERER']) && parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) != $_PHPIDPS_originURL){
			return true;
		}
		return false;
	}
}