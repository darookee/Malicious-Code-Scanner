<?php
/*
Plugin Name: php Malicious Code Scanner
Plugin URI: http://www.mikestowe.com/phpmalcode
Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Version: 1.3 alpha
Author: Michael Stowe
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
*/


// Set to your email:
define('SEND_EMAIL_ALERTS_TO','youremail@example.com');


############################################ START CLASS


class phpMalCodeScan {

    public $infected_files = array();
    private $scanned_files = array();
    private $scan_patterns = array(
        '/if\(isset\($_GET\[[a-z][0-9][0-9]+/i',
        '/eval\(base64/i',
        '/eval\(\$./i',
        '/[ue\"\'];\$/',
        '/;@ini/i',
    );


    function __construct() {
        $this->scan(dirname(__FILE__));
        $this->sendalert();
    }


    function scan($dir) {
        $this->scanned_files[] = $dir;
        $files = scandir($dir);

        if(!is_array($files)) {
            throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
        }

        foreach($files as $file) {
            if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
                $this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
            } elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
                $this->scan($dir.'/'.$file);
            }
        }
    }


    function check($contents,$file) {
        $this->scanned_files[] = $file;
        foreach($this->scan_patterns as $pattern) {
            if(preg_match($pattern,$contents)) {
                if($file !== __FILE__) {
                    $this->infected_files[] = array('file' => $file, 'pattern_matched' => $pattern);
                    break;
                }
            }
        }
    }


    function sendalert() {
        if(count($this->infected_files) != 0) {
            $message = "== MALICIOUS CODE FOUND == \n\n";
            $message .= "The following files appear to be infected: \n";
            foreach($this->infected_files as $inf) {
                $message .= "  -  ".$inf['file'] ." [".$inf['pattern_matched']."]\n";
            }
            mail(SEND_EMAIL_ALERTS_TO,'Malicious Code Found!',$message,'FROM:');
        }
    }


}


############################################ INITIATE CLASS

ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)

new phpMalCodeScan;


?>
