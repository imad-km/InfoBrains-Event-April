<?php
$response = file_get_contents('URL OF API');
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
echo $response;