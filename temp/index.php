<?php
//identification via le CAS
require_once("CAS.php");
session_start();
// -------------------------------- CASIFICATION de l'application --------------------------------
phpCAS::setDebug();
phpCAS::client(CAS_VERSION_2_0, "cas.emse.fr", 443, "");
phpCAS::setNoCasServerValidation();
phpCAS::forceAuthentication();
// -------------------------------- CASIFICATION de l'application --------------------------------
echo "Hello world";
print_r($_SESSION);