<?php
session_start();

// Include database connection
require_once '../includes/db.php'; // Ensure this is included before any database operations

// Ensure admin is logged in
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

// Create CSRF token for user management actions
if (empty($_SESSION['csrf_user_action'])) {
    $_SESSION['csrf_user_action'] = bin2hex(random_bytes(32));
}

// Fetch users from the database
$pdo = db();
$stmt = $pdo->prepare("SELECT id, full_name, username, email, role, registration, status FROM users");
$stmt->execute();
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - SEPMS</title>
    <link rel="stylesheet" href="../assets/css/um.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
</head>

<body>

    <div class="dashboard-header">
        <div class="container">
            <div class="header-left">
                <div class="logout">
                    <a href="../dashboard.php" class="back-link">
                        <i class="fas fa-arrow-left logout-icon"></i> Back to Dashboard
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- User Management Content -->
    <div class="container" style="margin-top: 20px;">
        <div class="exam-papers-table">
            <h3>User Management</h3>

            <!-- Search and filter bar -->
            <div class="user-management-search">
                <input type="text" id="search-bar" placeholder="Search users..." class="search-users">
                <select id="role-filter" class="role-filter">
                    <option value="all-roles">All Roles</option>
                    <option value="lecturer">Lecturer</option>
                    <option value="moderator">Moderator</option>
                    <option value="hod">HOD</option>
                    <option value="admin">Admin</option>
                </select>
            </div>

            <!-- Users Table -->
            <table class="user-table" id="user-table">
                <thead>
                    <tr>
                        <th>Full Name</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Registration Status</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                            <td><span
                                    class="role <?php echo strtolower($user['role']); ?>"><?php echo strtoupper($user['role']); ?></span>
                            </td>
                            <td><span class="registration"><?php echo ucfirst($user['registration']); ?></span></td>
                            <td><span
                                    class="status <?php echo strtolower($user['status']); ?>"><?php echo ucfirst($user['status']); ?></span>
                            </td>
                            <td>
                                <?php if ((int) $user['id'] === (int) $_SESSION['user']['id']): ?>
                                    <span class="status active">Current Admin</span>
                                <?php else: ?>
                                    <button class="btn-delete" data-user-id="<?php echo (int) $user['id']; ?>">Delete</button>

                                    <button
                                        class="btn-block <?php echo $user['status'] === 'blocked' ? 'unblock' : 'block'; ?>"
                                        data-user-id="<?php echo (int) $user['id']; ?>">
                                        <?php echo $user['status'] === 'blocked' ? 'Unblock' : 'Block'; ?>
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const csrfUserAction = "<?php echo htmlspecialchars($_SESSION['csrf_user_action'], ENT_QUOTES, 'UTF-8'); ?>";
        // Filter users based on search input
        document.getElementById("search-bar").addEventListener("keyup", function() {
            const searchValue = this.value.toLowerCase();
            const rows = document.querySelectorAll("#user-table tbody tr");
            rows.forEach(row => {
                const name = row.cells[0].textContent.toLowerCase();
                const username = row.cells[1].textContent.toLowerCase();
                if (name.includes(searchValue) || username.includes(searchValue)) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        });

        // Filter users based on selected role
        document.getElementById("role-filter").addEventListener("change", function() {
            const selectedRole = this.value;
            const rows = document.querySelectorAll("#user-table tbody tr");
            rows.forEach(row => {
                const roleSpan = row.cells[3].querySelector('.role');
                const role = roleSpan ? roleSpan.classList[1] : ''; // Get role from class of span (e.g., lecturer, moderator)

                if (selectedRole === "all-roles" || role === selectedRole) {
                    row.style.display = ""; // Show the row
                } else {
                    row.style.display = "none"; // Hide the row
                }
            });
        });

        // Add event listener to Block/Unblock buttons
        document.querySelectorAll('.btn-block').forEach(button => {
            button.addEventListener('click', function() {
                const userId = this.getAttribute('data-user-id');
                const newStatus = this.classList.contains('unblock') ? 'active' : 'blocked';

                // Confirm action before proceeding
                const confirmation = confirm(`Are you sure you want to ${newStatus === 'blocked' ? 'block' : 'unblock'} this account?`);

                if (!confirmation) {
                    return; // If the admin cancels, do nothing
                }

                // Send an AJAX request to update the user status in the database
                fetch('../includes/update_user_status.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: `user_id=${encodeURIComponent(userId)}&status=${encodeURIComponent(newStatus)}&csrf_token=${encodeURIComponent(csrfUserAction)}`
                    })
                    .then(response => response.text())
                    .then(data => {
                        console.log(data); // Log the response from PHP (for debugging)
                        if (data.includes('User status updated successfully')) {
                            // Toggle button text and class based on status
                            if (newStatus === 'blocked') {
                                this.textContent = 'Unblock';
                                this.classList.remove('block');
                                this.classList.add('unblock');
                            } else {
                                this.textContent = 'Block';
                                this.classList.remove('unblock');
                                this.classList.add('block');
                            }

                            // Update the status in the DOM
                            const statusCell = this.closest('tr').querySelector('.status');
                            statusCell.textContent = newStatus === 'blocked' ? 'Blocked' : 'Active';
                            statusCell.className = `status ${newStatus}`; // Update status class (blocked/active)
                        } else {
                            alert('Error updating status. Please try again.');
                            console.error('Error Response from PHP:', data); // Log error response from PHP
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error); // Log AJAX error in the console
                        alert('Error updating status');
                    });
            });
        });

        // Add event listener to Delete buttons
        document.querySelectorAll('.btn-delete').forEach(button => {
            button.addEventListener('click', function() {
                const userId = this.getAttribute('data-user-id');

                // Confirm delete action before proceeding
                const confirmation = confirm('Are you sure you want to delete this user? This action cannot be undone.');

                if (!confirmation) {
                    return; // If the admin cancels, do nothing
                }

                // Send an AJAX request to delete the user
                fetch('../includes/update_user_status.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: `delete_user_id=${encodeURIComponent(userId)}&csrf_token=${encodeURIComponent(csrfUserAction)}`
                    })
                    .then(response => response.text())
                    .then(data => {
                        alert(data); // Show the response from PHP (success message or error)
                        // Reload the page to reflect the changes after deletion
                        window.location.reload();
                    })
                    .catch(error => {
                        console.error('Error:', error); // Log AJAX error in the console
                        alert('Error deleting user');
                    });
            });
        });
    </script>

</body>

</html>