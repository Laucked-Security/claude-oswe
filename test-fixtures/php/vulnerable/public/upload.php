<?php
session_start();
if (empty($_SESSION['auth'])) { http_response_code(403); exit("Forbidden"); }

if (!empty($_FILES['f'])) {
    // VULN: no extension/content validation, attacker-controlled name, written under web root.
    $dest = __DIR__ . "/uploads/" . $_FILES['f']['name'];
    move_uploaded_file($_FILES['f']['tmp_name'], $dest);
    echo "Uploaded to uploads/" . $_FILES['f']['name'];
}
