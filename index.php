<?php
session_start();

// Redirect to dashboard if the user is logged in
if (isset($_SESSION['user'])) {
    header('Location: dashboard.php');
    exit;
}

// Define a function to get the appropriate message based on the error code
function getMessage(string $error_code): string
{
    $messages = [
        'registered' => 'Registration submitted successfully. Please wait for admin approval before you can login.',
        'logout' => 'Logged out successfully.',
        'invalid' => 'Invalid username or password.',
        'invalid_credentials' => 'Invalid username or password.',
        'missing' => 'Please fill in both username and password.',
        'db' => 'Database error. Please try again.',
        'db_error' => 'Database error. Please try again.',
        'pending' => 'Your registration is still pending admin approval.',
        'rejected' => 'Your registration has been rejected. Please contact the administrator.',
        'invalid_role' => 'Unauthorized attempt to log in!',
        'blocked' => 'Your account has been blocked. Please contact the administrator.',
        'too_many_attempts' => 'Too many failed login attempts. Please try again after 5 minutes.',
    ];

    return $messages[$error_code] ?? 'An unexpected error occurred. Please try again later.';
}

$msg = ''; // Default message
$msg_type = ''; // Message type: success or error

// Get the message based on GET parameters
if (isset($_GET['registered']) && $_GET['registered'] == '1') {
    $msg = getMessage('registered');
    $msg_type = 'success';
} elseif (isset($_GET['logout']) && $_GET['logout'] == '1') {
    $msg = getMessage('logout');
    $msg_type = 'success';
} elseif (isset($_GET['error'])) {
    $msg = getMessage((string) $_GET['error']);
    $msg_type = 'error';
}
?>

<!doctype html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login - SEPMS</title>
    <link rel="stylesheet" href="assets/css/login.css" />
</head>

<body>
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <img src="assets/images/logo.png" alt="SEPMS Logo" class="logo" />
                <h2>SEPMS</h2>
                <h4>Secure Examination Paper Management System</h4>
            </div>

            <!-- Display messages if any -->
            <?php if ($msg): ?>
                <div class="alert <?= $msg_type === 'error' ? 'alert-error' : 'alert-success'; ?>">
                    <?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <!-- Login form -->
            <form method="POST" action="includes/login.php">
                <h5>Username</h5>
                <input type="text" name="username" placeholder="Enter your username" required />
                <h5>Password</h5>
                <input type="password" name="password" placeholder="Enter your password" required />
                <button type="submit" name="login">Login</button>
            </form>

            <!-- Login options: Forgot Password, Register -->
            <div class="login-options">
                <!-- <a href="forgot_password.php">Forgot Password?</a> -->
                <a href="register.php">Register</a>
            </div>
        </div>
    </div>
</body>

</html>