<?php

declare(strict_types=1);
session_start();

require_once __DIR__ . '/db.php';

// Login failure function to handle errors and redirection
function login_fail(string $code): void
{
    header('Location: ../index.php?error=' . urlencode($code));
    exit;
}

// Check if the request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    login_fail('invalid');
}

// Simple session-based login attempt limit
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

if (!isset($_SESSION['login_block_until'])) {
    $_SESSION['login_block_until'] = 0;
}

if ($_SESSION['login_block_until'] > time()) {
    login_fail('too_many_attempts');
}

// Trim and assign username and password from POST request
$username = htmlspecialchars(trim((string) ($_POST['username'] ?? '')));
$password = (string) ($_POST['password'] ?? '');

// Check if username or password are empty
if ($username === '' || $password === '') {
    login_fail('missing');
}

try {
    // Connect to the database
    $pdo = db();

    // Prepare the SQL query to fetch user data by username
    $stmt = $pdo->prepare("
    SELECT 
        id, 
        full_name, 
        username, 
        role, 
        password_hash, 
        registration, 
        status, 
        college
    FROM users 
    WHERE username = :username 
    LIMIT 1
");
    $stmt->execute([':username' => $username]);

    // Fetch user data from the database
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // If no user found or password doesn't match, increase failed attempt count
    if (!$user || !password_verify($password, (string) $user['password_hash'])) {
        $_SESSION['login_attempts'] = (int) $_SESSION['login_attempts'] + 1;

        if ($_SESSION['login_attempts'] >= 5) {
            $_SESSION['login_attempts'] = 0;
            $_SESSION['login_block_until'] = time() + 300; // 5 minutes

            login_fail('too_many_attempts');
        }

        login_fail('invalid_credentials');
    }

    // Check if the user account is blocked
    if ($user['status'] === 'blocked') {
        login_fail('blocked');
    }

    // Handle user ragistration status and handle different cases using a switch statement
    switch ((string) $user['registration']) {
        case 'pending':
            login_fail('pending');
            break;
        case 'rejected':
            login_fail('rejected');
            break;
        case 'approved':
            // All good, the user is approved
            break;
        default:
            login_fail('invalid_credentials');
            break;
    }

    // Reset failed login attempts after successful login
    $_SESSION['login_attempts'] = 0;
    $_SESSION['login_block_until'] = 0;

    // Regenerate session ID for security
    session_regenerate_id(true);

    // Store user data in session
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'full_name' => (string) $user['full_name'],
        'username' => (string) $user['username'],
        'role' => (string) $user['role'],
        'college' => (string) ($user['college'] ?? '')
    ];

    // Log successful login
    $stmt_log = $pdo->prepare("INSERT INTO action_logs (user_id, action_type, description) VALUES (:user_id, :action_type, :description)");
    $stmt_log->execute([
        ':user_id' => (int) $user['id'],
        ':action_type' => 'Login',
        ':description' => 'User logged in successfully.'
    ]);

    // Redirect to the unified dashboard
    header('Location: ../dashboard.php');
    exit;
} catch (PDOException $e) {
    // Catch database connection errors
    error_log($e->getMessage()); // Log error message
    login_fail('db_error');
}
