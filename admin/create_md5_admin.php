<?php
// Simple script to generate MD5 hashed passwords for admin users
// Run this to get the correct MD5 hash for your passwords

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    if (!empty($password)) {
        $md5Hash = md5($password);
        $result = "MD5 Hash for password '$password': $md5Hash";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MD5 Password Generator</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">MD5 Password Generator for Admin</h4>
                    </div>
                    <div class="card-body">
                        <?php if (isset($result)): ?>
                            <div class="alert alert-success">
                                <strong>Generated Hash:</strong><br>
                                <code><?php echo htmlspecialchars($md5Hash); ?></code>
                            </div>
                            
                            <div class="alert alert-info">
                                <strong>SQL Query to insert admin:</strong><br>
                                <code>
                                INSERT INTO `admins` (`username`, `email`, `password`, `created_at`) <br>
                                VALUES ('your_username', 'your_email@example.com', '<?php echo $md5Hash; ?>', NOW());
                                </code>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Password to Hash</label>
                                <input type="text" class="form-control" name="password" 
                                       value="<?php echo htmlspecialchars($password ?? ''); ?>" required>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">Generate MD5 Hash</button>
                        </form>
                        
                        <hr>
                        
                        <h6>Quick Examples:</h6>
                        <ul>
                            <li><strong>admin123</strong> → <code><?php echo md5('admin123'); ?></code></li>
                            <li><strong>password</strong> → <code><?php echo md5('password'); ?></code></li>
                            <li><strong>123456</strong> → <code><?php echo md5('123456'); ?></code></li>
                        </ul>
                    </div>
                    <div class="card-footer text-muted">
                        <small><strong>Security Note:</strong> MD5 is not recommended for production. Consider upgrading to bcrypt.</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>