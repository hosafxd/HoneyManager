<?php
/**
 * Honeypot Login Capture Script
 * Logs all login attempts to JSON file for analysis
 */

// Get request data
$timestamp = date('c');
$remote_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// Create log entry
$log_entry = [
    'timestamp' => $timestamp,
    'event_type' => 'login_attempt',
    'source_ip' => $remote_ip,
    'user_agent' => $user_agent,
    'username' => $username,
    'password' => str_repeat('*', strlen($password)), // Mask password in logs
    'password_length' => strlen($password),
    'success' => false,
    'honeypot' => 'web-camera',
    'device_type' => 'hikvision'
];

// Write to JSON log file
$log_file = '/var/log/honeypot/credentials.json';
$log_line = json_encode($log_entry) . "\n";
file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);

// Simulate failed login (always fails)
sleep(2); // Fake processing delay

// Redirect back with error
header('Location: /index.html?error=1');
exit;
?>
