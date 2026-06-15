<?php
session_start();

// Safe: bcrypt hash verified with password_verify (no loose comparison, no magic-hash exposure).
$STORED_HASH = '$2y$10$e0NRxk7m6mQ4y3o6mY8m1uJ2bqJ9w8m5rQ0Z9c0b3xq9bq8wq9bq'; // bcrypt of a real password

$pass = $_POST['password'] ?? '';
if (password_verify($pass, $STORED_HASH)) {
    $_SESSION['auth'] = true;
    header("Location: upload.php");
    exit;
}
echo "Invalid credentials";
