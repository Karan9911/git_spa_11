<?php
session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

// This script helps you add admin users properly
// Run this once and then delete it for security

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['username'] ?? '');
    $email = sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($email) || empty($password)) {
        $error = 'All fields are required';
    } else {
        try {
            $db = getDB();
            
            // Check if username already exists
            $stmt = $db->prepare("SELECT id FROM admins WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            if ($stmt->fetch()) {
                $error = 'Username or email already exists';
            } else {
                // Hash the password properly
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                
                // Insert new admin
                $stmt = $db->prepare("INSERT INTO admins (username, email, password) VALUES (?, ?, ?)");
                if ($stmt->execute([$username, $email, $hashedPassword])) {
                    $success = "Admin user '$username' created successfully!";
                    $username = $email = $password = ''; // Clear form
                } else {
                    $error = 'Failed to create admin user';
                }
            }
        } catch (Exception $e) {
            $error = 'Database error: ' . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Admin User</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">Add New Admin User</h4>
                    </div>
                    <div class="card-body">
                        <?php if (isset($error)): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        
                        <?php if (isset($success)): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Username</label>
                                <input type="text" class="form-control" name="username" 
                                       value="<?php echo htmlspecialchars($username ?? ''); ?>" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Email</label>
                                <input type="email" class="form-control" name="email" 
                                       value="<?php echo htmlspecialchars($email ?? ''); ?>" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input type="password" class="form-control" name="password" required>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">Create Admin User</button>
                        </form>
                        
                        <div class="mt-4">
                            <h6>Current Admin Users:</h6>
                            <?php
                            try {
                                $db = getDB();
                                $stmt = $db->prepare("SELECT username, email, created_at FROM admins ORDER BY created_at DESC");
                                $stmt->execute();
                                $admins = $stmt->fetchAll();
                                
                                if ($admins) {
                                    echo '<ul class="list-group">';
                                    foreach ($admins as $admin) {
                                        echo '<li class="list-group-item d-flex justify-content-between">';
                                        echo '<span><strong>' . htmlspecialchars($admin['username']) . '</strong> (' . htmlspecialchars($admin['email']) . ')</span>';
                                        echo '<small class="text-muted">' . date('M j, Y', strtotime($admin['created_at'])) . '</small>';
                                        echo '</li>';
                                    }
                                    echo '</ul>';
                                } else {
                                    echo '<p class="text-muted">No admin users found.</p>';
                                }
                            } catch (Exception $e) {
                                echo '<p class="text-danger">Error loading admin users.</p>';
                            }
                            ?>
                        </div>
                    </div>
                    <div class="card-footer text-muted">
                        <small><strong>Security Note:</strong> Delete this file after creating your admin users!</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>