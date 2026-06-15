<?php
// Intentionally vulnerable. Magic-hash type juggling auth bypass.
session_start();

// Stored "password hash" chosen as a magic hash (md5 of "240610708" == "0e462097431906509019562988736854").
$STORED_HASH = "0e462097431906509019562988736854";

$user = $_POST['user'] ?? '';
$pass = $_POST['password'] ?? '';

// VULN: loose comparison of md5() digest enables 0e-magic-hash bypass.
if (md5($pass) == $STORED_HASH) {
    $_SESSION['auth'] = true;
    header("Location: upload.php");
    exit;
}
echo "Invalid credentials";
