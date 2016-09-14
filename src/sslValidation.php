<?php

/*
 * This file is part of btafoya/sslvalidation bundle.
 *
 * (c) Composer <https://github.com/btafoya/sslvalidation>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace btafoya\sslValidation;

use \Composer\CaBundle\CaBundle;

/**
 * @author Brian Tafoya <btafoya@briantafoya.com>
 */
class sslValidation {
	public $errors = array();

	/**
	 * Small utility library that downloads and returns ssl certificate information from a running web server.
	 *
	 * @param  $domain, $port         The domain and port which the ssl certificate is accessible.
	 * @return array                  certificate information parsed into an array for ease of use. Always return a status key, true for a valid response, false for any failure.
	 */
	public function getSSLInformation ($domain, $port = "443") {

		$cafile = CaBundle::getSystemCaRootBundlePath();

		try {
			$g = @stream_context_create (array("ssl" => array("capture_peer_cert" => true, "cafile" => $cafile)));
			$r = @stream_socket_client("ssl://" . (string)$domain. ":" . (int)$port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $g);

			if (!$r) {
				$this->errors[] = $this->cleanStringData($errstr);
				return array(
					"status"=>false,
					"errorString"=>$this->cleanStringData($errstr),
					"errorNumber"=>$errno
				);
			} else {
				$cont = @stream_context_get_params($r);
				$cert = @openssl_x509_parse($cont["options"]["ssl"]["peer_certificate"]);

				return
					array(
						"status"=>true,
						"cert"=>$cert,
						"validFrom_date"=>date("r",$cert["validFrom_time_t"]),
						"validTo_date"=>date("r",$cert["validTo_time_t"]),
						"certificatePolicies"=>$this->parseStringDataToArray($cert["extensions"]["certificatePolicies"]),
						"subjectAltName"=>$this->parseAltNameToArray($cert["extensions"]["subjectAltName"]),
						"caPath"=>$cafile
					)
				;
			}


		} catch (Exception $e) {
			$this->errors[] = $e->getMessage();
			return array(
				"status"=>false,
				"errorString"=>$e->getMessage(),
				"errorNumber"=>911
			);
		}
	}

	/**
	 * Simple string cleanup.
	 *
	 * @return string
	 */
	private function cleanStringData($string) {
		return trim(preg_replace('/\s\s+/', ' ', $string));
	}

	/**
	 * Parse string data into an array, such as certificatePolicies.
	 *
	 * @return array
	 */
	private function parseStringDataToArray($string) {
		$results = array();
		$data_array = preg_split("/\\r\\n|\\r|\\n/", trim($string));
		foreach($data_array as $i) {
			$results = $this->explodeToArray($i, $results);
		}

		return (array)$results;
	}

	/**
	 * Parse subjectAltName string data into an array.
	 *
	 * @return array
	 */
	private function parseAltNameToArray($string) {
		$results = array();
		$names = explode(",",trim($string));

		foreach($names as $i) {
			$results = $this->explodeToArray($i, $results);
		}

		return (array)$results;
	}

	/**
	 * Specific utility method to explode and clean strings into an array.
	 *
	 * Used by: parseStringDataToArray() and parseAltNameToArray()
	 *
	 * @return array
	 */
	private function explodeToArray($i, $sourceArray) {
		$tmp = explode(":", $i, 2);
		$keyName = strtolower(str_replace(" ","_",trim($tmp[0])));
		$valueData = trim($tmp[1]);

		if(key_exists($keyName, $sourceArray)) {
			if(is_array($sourceArray[$keyName])) {
				$sourceArray[$keyName][] = $valueData;
			} else {
				$tmpVal = $sourceArray[$keyName];
				$sourceArray[$keyName] = array($tmpVal,$valueData);
			}
		} else {
			$sourceArray[$keyName] = array($valueData);
		}

		return (array)$sourceArray;
	}
}
