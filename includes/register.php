<?php

declare(strict_types=1);
session_start();

require_once __DIR__ . '/db.php';

// Helper function to handle errors and redirect
function fail(string $msg, array $old = []): void
{
    $_SESSION['register_error'] = $msg;
    $_SESSION['register_old'] = $old;
    header('Location: ../register.php');
    exit;
}

// CSRF validation function
function validateCsrf(): bool
{
    return isset($_POST['csrf']) &&
        isset($_SESSION['csrf_register']) &&
        hash_equals($_SESSION['csrf_register'], (string) $_POST['csrf']);
}

// Strong password validation function
function validateStrongPassword(string $password, string $username, string $email): ?string
{
    if (strlen($password) < 8) {
        return 'Password must be at least 8 characters long.';
    }

    if (!preg_match('/[A-Z]/', $password)) {
        return 'Password must contain at least one uppercase letter.';
    }

    if (!preg_match('/[a-z]/', $password)) {
        return 'Password must contain at least one lowercase letter.';
    }

    if (!preg_match('/[0-9]/', $password)) {
        return 'Password must contain at least one number.';
    }

    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        return 'Password must contain at least one special character.';
    }

    if ($username !== '' && stripos($password, $username) !== false) {
        return 'Password must not contain your username.';
    }

    $email_name = strstr($email, '@', true);

    if ($email_name !== false && $email_name !== '' && stripos($password, $email_name) !== false) {
        return 'Password must not contain your email name.';
    }

    return null;
}

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('Invalid request.');
}

// CSRF validation
if (!validateCsrf()) {
    fail('CSRF validation failed. Please try again.');
}

// Fetch and sanitize input data
$full_name = trim((string) ($_POST['full_name'] ?? ''));
$email = strtolower(trim((string) ($_POST['email'] ?? '')));
$role = trim((string) ($_POST['role'] ?? ''));
$college = trim((string) ($_POST['college'] ?? ''));
$username = trim((string) ($_POST['username'] ?? ''));
$password = (string) ($_POST['password'] ?? '');
$confirm_password = (string) ($_POST['confirm_password'] ?? '');

// Old values for form re-population
$old = compact('full_name', 'email', 'role', 'college', 'username');

// Validate required fields
$required_fields = compact('full_name', 'email', 'role', 'college', 'username', 'password', 'confirm_password');

foreach ($required_fields as $key => $value) {
    if ($value === '') {
        fail(ucwords(str_replace('_', ' ', $key)) . ' is required.', $old);
    }
}

// Validation rules for individual fields
$validations = [
    'email' => function ($value) {
        return filter_var($value, FILTER_VALIDATE_EMAIL) ? null : 'Invalid email format.';
    },

    'role' => function ($value) {
        $allowed_roles = ['Lecturer', 'Moderator', 'HOD', 'Admin'];
        return in_array($value, $allowed_roles, true) ? null : 'Invalid role selected.';
    },

    'college' => function ($value) {
        $allowed_colleges = ['CCI', 'COE', 'COBA'];
        return in_array($value, $allowed_colleges, true) ? null : 'Invalid college selected.';
    },

    'username' => function ($value) {
        return (strlen($value) >= 3 && strlen($value) <= 50)
            ? null
            : 'Username must be 3 to 50 characters.';
    },

    'password' => function ($value) use ($username, $email) {
        return validateStrongPassword($value, $username, $email);
    },

    'confirm_password' => function ($value) use ($password) {
        return hash_equals($password, $value) ? null : 'Passwords do not match.';
    }
];

// Run validations
foreach ($validations as $field => $validate) {
    $error = $validate($$field);

    if ($error) {
        fail($error, $old);
    }
}

// Hash password
$hash = password_hash($password, PASSWORD_DEFAULT);

if ($hash === false) {
    fail('Password hashing failed.', $old);
}

try {
    $pdo = db();
    $pdo->beginTransaction();

    // Check for duplicate email or username
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM users 
        WHERE email = :email 
           OR username = :username
    ");

    $stmt->execute([
        ':email' => $email,
        ':username' => $username
    ]);

    if ((int) $stmt->fetchColumn() > 0) {
        $pdo->rollBack();
        fail('Email or username already exists.', $old);
    }

    // Insert new user with pending status
    $stmt = $pdo->prepare("
        INSERT INTO users 
            (full_name, email, username, role, college, password_hash, registration) 
        VALUES 
            (:full_name, :email, :username, :role, :college, :password_hash, 'pending')
    ");

    $stmt->execute([
        ':full_name' => $full_name,
        ':email' => $email,
        ':username' => $username,
        ':role' => $role,
        ':college' => $college,
        ':password_hash' => $hash,
    ]);

    $new_user_id = (int) $pdo->lastInsertId();

    // Log registration in action_logs
    $stmt_log = $pdo->prepare("
        INSERT INTO action_logs 
            (user_id, action_type, description) 
        VALUES 
            (:user_id, :action_type, :description)
    ");

    $stmt_log->execute([
        ':user_id' => $new_user_id,
        ':action_type' => 'Register',
        ':description' => 'New account registered successfully with role ' . $role . '.',
    ]);

    $pdo->commit();

    // Cleanup session variables
    unset($_SESSION['csrf_register'], $_SESSION['register_old']);

    // Redirect to login page with pending notice
    header('Location: ../index.php?registered=1');
    exit;
} catch (PDOException $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log("Database error: " . $e->getMessage());

    if ((int) ($e->errorInfo[1] ?? 0) === 1062) {
        fail('Email or username already exists.', $old);
    }

    fail('Database error. Please try again.', $old);
}
