<?php
require_once 'api.php';

if (php_sapi_name() !== 'cli') {
    die('This script must be run from command line');
}

if ($argc < 3) {
    echo "Usage: php change_password.php <username> <new_password>\n";
    exit(1);
}

$username = $argv[1];
$newPassword = $argv[2];

$users = Auth::loadUsers();

if (!isset($users[$username])) {
    echo "Error: User '$username' not found\n";
    exit(1);
}

$users[$username]['password'] = password_hash($newPassword, PASSWORD_BCRYPT);
$users[$username]['updated_at'] = time();

file_put_contents(
    __DIR__ . '/users.json',
    json_encode($users, JSON_PRETTY_PRINT)
);

echo "Password changed successfully for user: $username\n";
