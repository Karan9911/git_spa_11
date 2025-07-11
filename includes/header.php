<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($pageTitle) ? $pageTitle . ' - ' : ''; ?>Hammam Spa</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="<?php echo SITE_URL; ?>/assets/css/style.css" rel="stylesheet">
    <!-- Pricing CSS -->
    <link href="<?php echo SITE_URL; ?>/assets/css/pricing.css" rel="stylesheet">
    <!-- Google Tag Manager -->
    <script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
    new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
    j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
    'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
    })(window,document,'script','dataLayer','GTM-WNRTPJJJ');</script>
    <!-- End Google Tag Manager -->
    
    <!-- Google Tag Manager (noscript) -->
    <noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-WNRTPJJJ"
    height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
    <!-- End Google Tag Manager (noscript) -->
    
    <?php if (isset($extraHead)) echo $extraHead; ?>
</head>
<body>
    <?php if (!isset($hideNavbar) || !$hideNavbar): ?>
    <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm fixed-top">
        <div class="container">
            <!-- Mobile Layout (visible on mobile only) -->
            <div class="d-lg-none d-flex align-items-center w-100">
                <!-- 1. Hamburger menu -->
                <button class="navbar-toggler me-2" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                
                <!-- 2. Logo -->
                <a class="navbar-brand fw-bold text-primary flex-grow-1" href="<?php echo SITE_URL; ?>">
                    <img src="<?php echo SITE_URL; ?>/uploads/website/logo.png" width="120px">
                </a>
                
                <!-- 3. Region Price Indicator -->
                <div class="region-price-indicator me-2">
                    <button class="btn btn-outline-primary btn-sm" id="regionPriceBtnMobile" onclick="openRegionModal()">
                        <i class="bi bi-buildings"></i>
                    </button>
                </div>
                
                <!-- 4. User icon -->
                <div class="d-flex align-items-center">
                    <?php if (isUserLoggedIn()): ?>
                        <div class="dropdown">
                            <button class="btn btn-link p-0" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="bi bi-person-circle fs-4 text-primary"></i>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><a class="dropdown-item" href="profile.php">
                                    <i class="bi bi-person me-2"></i>Profile
                                </a></li>
                                <li><a class="dropdown-item" href="my-bookings.php">
                                    <i class="bi bi-calendar-check me-2"></i>My Bookings
                                </a></li>
                                <?php if (isAdminUser()): ?>
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item" href="admin/index.php">
                                        <i class="bi bi-speedometer2 me-2"></i>Admin Panel
                                    </a></li>
                                <?php endif; ?>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item" href="logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>Logout
                                </a></li>
                            </ul>
                        </div>
                    <?php else: ?>
                        <button class="btn btn-link p-0" onclick="openMobileLoginModal()">
                            <i class="bi bi-person-circle fs-4 text-primary"></i>
                        </button>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Desktop Layout (visible on desktop only) -->
            <div class="d-none d-lg-flex align-items-center w-40">
                <a class="navbar-brand fw-bold text-primary d-flex align-items-center" href="<?php echo SITE_URL; ?>">
                    <img src="<?php echo SITE_URL; ?>/uploads/website/logo.png" width="150px">
                </a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
            </div>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto ms-3">
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo SITE_URL; ?>">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo SITE_URL; ?>/models.php">Models</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo SITE_URL; ?>/services.php">Services</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo SITE_URL; ?>/therapies.php">Therapies</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo SITE_URL; ?>/about.php">About</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo SITE_URL; ?>/contact.php">Contact</a>
                    </li>
                    
                    <!-- Mobile-only user menu items (when not logged in) -->
                    <?php if (!isUserLoggedIn()): ?>
                        <li class="nav-item d-lg-none">
                            <hr class="dropdown-divider">
                        </li>
                        <li class="nav-item d-lg-none">
                            <a class="nav-link" href="<?php echo SITE_URL; ?>/login.php">
                                <i class="bi bi-box-arrow-in-right me-2"></i>Login
                            </a>
                        </li>
                        <li class="nav-item d-lg-none">
                            <a class="nav-link" href="<?php echo SITE_URL; ?>/signup.php">
                                <i class="bi bi-person-plus me-2"></i>Sign Up
                            </a>
                        </li>
                    <?php else: ?>
                        <!-- Mobile-only user menu items (when logged in) -->
                        <li class="nav-item d-lg-none">
                            <hr class="dropdown-divider">
                        </li>
                        <li class="nav-item d-lg-none">
                            <a class="nav-link" href="profile.php">
                                <i class="bi bi-person me-2"></i>Profile
                            </a>
                        </li>
                        <li class="nav-item d-lg-none">
                            <a class="nav-link" href="my-bookings.php">
                                <i class="bi bi-calendar-check me-2"></i>My Bookings
                            </a>
                        </li>
                        <?php if (isAdminUser()): ?>
                            <li class="nav-item d-lg-none">
                                <a class="nav-link" href="admin/index.php">
                                    <i class="bi bi-speedometer2 me-2"></i>Admin Panel
                                </a>
                            </li>
                        <?php endif; ?>
                        <li class="nav-item d-lg-none">
                            <a class="nav-link" href="logout.php">
                                <i class="bi bi-box-arrow-right me-2"></i>Logout
                            </a>
                        </li>
                    <?php endif; ?>
                </ul>
                
                <!-- Region Price Indicator (Desktop only) -->
                <div class="region-price-indicator me-2 d-none d-lg-block">
                    <button class="btn btn-outline-primary btn-sm" id="regionPriceBtn" onclick="openRegionModal()">
                        <i class="bi bi-building me-1"></i>
                        <span id="currentRegionText">Delhi-NCR</span>
                        <i class="bi bi-chevron-down ms-1 d-none d-sm-inline"></i>
                    </button>
                </div>
                
                <div class="navbar-nav d-none d-lg-block">
                    <?php if (isUserLoggedIn()): ?>
                        <div class="user-info d-flex align-items-center">
                            <div class="user-avatar me-2">
                                <?php echo strtoupper(substr($_SESSION['user_name'], 0, 1)); ?>
                            </div>
                            <div class="dropdown">
                                <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" data-bs-toggle="dropdown">
                                    <div class="text-start d-none d-md-block">
                                        <div class="fw-semibold">Hi, <?php echo htmlspecialchars(explode(' ', $_SESSION['user_name'])[0]); ?></div>
                                        <?php if (!empty($_SESSION['user_city'])): ?>
                                            <small class="text-muted">
                                                <i class="bi bi-geo-alt me-1"></i><?php echo htmlspecialchars($_SESSION['user_city']); ?>
                                            </small>
                                        <?php endif; ?>
                                    </div>
                                </a>
                                <ul class="dropdown-menu dropdown-menu-end">
                                    <li><a class="dropdown-item" href="profile.php">
                                        <i class="bi bi-person me-2"></i>Profile
                                    </a></li>
                                    <li><a class="dropdown-item" href="my-bookings.php">
                                        <i class="bi bi-calendar-check me-2"></i>My Bookings
                                    </a></li>
                                    <?php if (isAdminUser()): ?>
                                        <li><hr class="dropdown-divider"></li>
                                        <li><a class="dropdown-item" href="admin/index.php">
                                            <i class="bi bi-speedometer2 me-2"></i>Admin Panel
                                        </a></li>
                                    <?php endif; ?>
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item" href="logout.php">
                                        <i class="bi bi-box-arrow-right me-2"></i>Logout
                                    </a></li>
                                </ul>
                            </div>
                        </div>
                    <?php else: ?>
                        <!-- Desktop Login/Signup -->
                        <li class="nav-item d-none d-lg-block">
                            <a class="nav-link" href="<?php echo SITE_URL; ?>/login.php">
                                <i class="bi bi-box-arrow-in-right me-1 d-none d-xl-inline"></i>Login
                            </a>
                        </li>
                        <li class="nav-item d-none d-lg-block">
                            <a class="nav-link btn btn-primary text-white ms-1 px-3" href="<?php echo SITE_URL; ?>/signup.php">
                                <i class="bi bi-person-plus me-1 d-none d-xl-inline"></i>Sign Up
                            </a>
                        </li>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </nav>
    
    <!-- Add padding to body to account for fixed navbar -->
    <div style="padding-top: 80px;"></div>
    <?php endif; ?>

    <!-- Mobile Login Modal -->
    <?php if (!isUserLoggedIn()): ?>
    <div class="modal fade" id="mobileLoginModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Account Access</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body text-center">
                    <div class="mb-4">
                        <i class="bi bi-person-circle display-1 text-primary"></i>
                        <h4 class="mt-3">Welcome to Serenity Spa</h4>
                        <p class="text-muted">Sign in to book appointments and manage your profile</p>
                    </div>
                    
                    <div class="d-grid gap-2">
                        <a href="<?php echo SITE_URL; ?>/login.php" class="btn btn-primary btn-lg">
                            <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
                        </a>
                        <a href="<?php echo SITE_URL; ?>/signup.php" class="btn btn-outline-primary btn-lg">
                            <i class="bi bi-person-plus me-2"></i>Create Account
                        </a>
                    </div>
                    
                    <div class="mt-4">
                        <small class="text-muted">
                            <i class="bi bi-shield-check me-1"></i>
                            Your data is secure with us
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function openMobileLoginModal() {
            new bootstrap.Modal(document.getElementById('mobileLoginModal')).show();
        }
    </script>
    <?php endif; ?>
    
    <!-- Region Selection Modal -->
    <div class="modal fade" id="regionModal" tabindex="-1">
        <div class="modal-dialog modal-sm">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-geo-alt me-2"></i>Select Your Region
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p class="text-muted mb-3">Choose your region to see accurate pricing:</p>
                    <div class="d-grid gap-2">
                        <button class="btn btn-outline-primary region-select-btn" data-region="ncr">
                            <i class="bi bi-buildings me-2"></i>
                            <div>
                                <strong>Delhi-NCR</strong>
                                <br><small>Delhi, Gurgaon, Noida, Faridabad</small>
                            </div>
                        </button>
                        <button class="btn btn-outline-primary region-select-btn" data-region="other">
                            <i class="bi bi-geo-alt-fill me-2"></i>
                            <div>
                                <strong>Rest of India</strong>
                                <br><small>All other cities</small>
                            </div>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>