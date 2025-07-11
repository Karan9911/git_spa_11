<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Redirect if already logged in
if (isUserLoggedIn()) {
    if (isAdminUser()) {
        header('Location: admin/index.php');
    } else {
        header('Location: index.php');
    }
    exit;
}

$pageTitle = 'Login';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $emailOrPhone = sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($emailOrPhone) || empty($password)) {
        $error = 'Please enter both email/phone and password';
    } else {
        $result = loginUser($emailOrPhone, $password);
        if ($result['success']) {
            // Role-based redirection - FIXED
            if ($result['user']['role'] === 'admin') {
                header('Location: admin/index.php');
            } else {
                header('Location: index.php');
            }
            exit;
        } else {
            $error = $result['message'];
        }
    }
}
?>

<?php include 'includes/header.php'; ?>

<section class="py-5">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-5">
                <div class="auth-card">
                    <div class="auth-header">
                        <h2 class="text-center mb-4">Welcome Back</h2>
                        <p class="text-center text-muted">Sign in to your account</p>
                    </div>
                    
                    <?php if ($error): ?>
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i><?php echo $error; ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="POST" class="needs-validation" novalidate>
                        <div class="mb-3">
                            <label class="form-label">Email or Phone Number</label>
                            <input type="text" class="form-control" name="email" 
                                   value="<?php echo htmlspecialchars($emailOrPhone ?? ''); ?>" 
                                   placeholder="Enter email or 10-digit phone number" required>
                            <div class="invalid-feedback">Please enter your email or phone number.</div>
                            <small class="form-text text-muted">You can login with either your email address or phone number</small>
                        </div>
                        
                        <div class="mb-4">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" name="password" required>
                            <div class="invalid-feedback">Please enter your password.</div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary btn-lg">
                                <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
                            </button>
                        </div>
                    </form>
                    
                    <div class="text-center mt-4">
                        <p class="mb-0">Don't have an account? <a href="signup.php" class="text-primary">Sign up here</a></p>
                    </div>
                    
                    <!--<div class="text-center mt-4">-->
                    <!--    <div class="alert alert-info">-->
                    <!--        <strong>Demo Credentials:</strong><br>-->
                    <!--        <strong>Admin:</strong> admin@spa.com / admin123<br>-->
                    <!--        <strong>User:</strong> user@spa.com / user123-->
                    <!--    </div>-->
                    <!--</div>-->
                </div>
            </div>
        </div>
    </div>
</section>

<?php include 'includes/footer.php'; ?>