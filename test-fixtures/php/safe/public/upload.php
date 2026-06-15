<?php
session_start();
if (empty($_SESSION['auth'])) { http_response_code(403); exit("Forbidden"); }

$ALLOWED = ['png' => 'image/png', 'jpg' => 'image/jpeg'];
if (!empty($_FILES['f'])) {
    $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
    $mime = mime_content_type($_FILES['f']['tmp_name']);
    if (!isset($ALLOWED[$ext]) || $ALLOWED[$ext] !== $mime) { http_response_code(400); exit("Rejected"); }
    // Safe: random name, fixed safe extension, stored OUTSIDE the web root.
    $dest = sys_get_temp_dir() . "/" . bin2hex(random_bytes(16)) . "." . $ext;
    move_uploaded_file($_FILES['f']['tmp_name'], $dest);
    echo "Uploaded";
}
