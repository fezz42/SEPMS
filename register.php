<?php

declare(strict_types=1);

session_start();

require_once 'includes/db.php';

// Generate CSRF token if not already set
if (empty($_SESSION['csrf_register'])) {
    $_SESSION['csrf_register'] = bin2hex(random_bytes(32));
}

// Handle error and old data for form re-population
$error = $_SESSION['register_error'] ?? '';
$old = $_SESSION['register_old'] ?? [];

unset($_SESSION['register_error'], $_SESSION['register_old']);

// Helper function to display error message
function displayError(?string $error): string
{
    return $error ? "<div class='msg error'>" . htmlspecialchars($error) . "</div>" : '';
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - SEPMS</title>

    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/register.css">
</head>

<body>
    <div class="register-container">
        <div class="register-card">

            <div class="back-login">
                <a href="index.php">
                    <i class="fa-solid fa-arrow-left-long"></i> Back to Login
                </a>
            </div>

            <div class="register-header">
                <img src="assets/images/logo.png" alt="SEPM Logo" class="logo">

                <div class="register-text">
                    <h2>Create Account</h2>
                    <h4>Register for SEPMS</h4>
                </div>
            </div>

            <!-- Display Error Message -->
            <?= displayError($error); ?>

            <!-- Registration Form -->
            <form method="POST" action="includes/register.php">
                <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_register']); ?>">

                <h5>Full Name</h5>
                <input type="text" name="full_name" placeholder="Dr. John Smith" required
                    value="<?= htmlspecialchars($old['full_name'] ?? ''); ?>">

                <h5>Email</h5>
                <input type="email" name="email" placeholder="john.smith@uniten.edu.my" required
                    value="<?= htmlspecialchars($old['email'] ?? ''); ?>">

                <div class="form-row">
                    <div class="select-container">
                        <h5>Role</h5>
                        <select name="role" required>
                            <option value="">Select role</option>

                            <?php
                            $roles = ['Lecturer', 'Moderator', 'HOD', 'Admin'];

                            foreach ($roles as $role) {
                                $selected = ($old['role'] ?? '') === $role ? 'selected' : '';
                                echo "<option value=\"$role\" $selected>$role</option>";
                            }
                            ?>
                        </select>
                    </div>

                    <div class="select-container">
                        <h5>College</h5>
                        <select name="college" required>
                            <option value="">Select College</option>

                            <?php
                            $colleges = ['CCI', 'COE', 'COBA'];

                            foreach ($colleges as $college) {
                                $selected = ($old['college'] ?? '') === $college ? 'selected' : '';
                                echo "<option value=\"$college\" $selected>$college</option>";
                            }
                            ?>
                        </select>
                    </div>
                </div>

                <h5>Username</h5>
                <input type="text" name="username" placeholder="Username" required
                    value="<?= htmlspecialchars($old['username'] ?? ''); ?>">

                <h5>Password</h5>
                <input
                    type="password"
                    name="password"
                    id="password"
                    placeholder="Password"
                    pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$"
                    title="Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
                    required>

                <small class="password-hint">
                    Password must contain at least 8 characters, uppercase letter, lowercase letter, number, and special character.
                </small>

                <h5>Confirm Password</h5>
                <input
                    type="password"
                    name="confirm_password"
                    id="confirm_password"
                    placeholder="Re-enter password"
                    required>

                <button type="submit" name="register">Register</button>
            </form>

        </div>
    </div>
</body>

</html>