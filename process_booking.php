<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

// // Validate CSRF token if implemented
//   if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
//      echo json_encode(['success' => false, 'message' => 'Invalid security token']);
//      exit;
//  }

// Validate required fields
$required_fields = ['therapist_id', 'full_name', 'phone', 'booking_date', 'booking_time', 'total_amount'];
$errors = [];

foreach ($required_fields as $field) {
    if (empty($_POST[$field])) {
        $errors[] = ucfirst(str_replace('_', ' ', $field)) . ' is required';
    }
}

if (!empty($errors)) {
    echo json_encode(['success' => false, 'message' => implode(', ', $errors)]);
    exit;
}

// Sanitize and validate inputs
$therapist_id = (int)$_POST['therapist_id'];
$full_name = sanitizeInput($_POST['full_name']);
$email = sanitizeInput($_POST['email']);
$phone = sanitizeInput($_POST['phone']);
$booking_date = sanitizeInput($_POST['booking_date']);
$booking_time = sanitizeInput($_POST['booking_time']);
$message = sanitizeInput($_POST['message'] ?? '');
$total_amount = (float)$_POST['total_amount'];
$region = sanitizeInput($_POST['region'] ?? 'other');
$is_night = isset($_POST['is_night']) && $_POST['is_night'] === '1';
$night_charge = (float)($_POST['night_charge'] ?? 0);

// Auto-detect night time from booking time if not explicitly set
if (!$is_night) {
    $bookingHour = (int)date('H', strtotime($booking_time));
    $is_night = ($bookingHour >= 20 || $bookingHour < 8);
    if ($is_night) {
        $night_charge = 1500;
    }
}

// Validate region
if (!in_array($region, ['ncr', 'other'])) {
    $region = 'other'; // Default fallback
}

// Validate email (only if provided)
if (!empty($email) && !validateEmail($email)) {
    echo json_encode(['success' => false, 'message' => 'Invalid email format']);
    exit;
}

// Validate phone
if (!validatePhone($phone)) {
    echo json_encode(['success' => false, 'message' => 'Invalid phone number format']);
    exit;
}

// Validate date
$today = date('Y-m-d');
if ($booking_date < $today) {
    echo json_encode(['success' => false, 'message' => 'Booking date cannot be in the past']);
    exit;
}

// Verify therapist exists
$therapist = getTherapistById($therapist_id);
if (!$therapist) {
    echo json_encode(['success' => false, 'message' => 'Selected therapist not found']);
    exit;
}

// Check for existing booking conflicts
$db = getDB();
$stmt = $db->prepare("
    SELECT COUNT(*) as count 
    FROM bookings 
    WHERE therapist_id = ? AND booking_date = ? AND booking_time = ? AND status != 'cancelled'
");
$stmt->execute([$therapist_id, $booking_date, $booking_time]);
$existing = $stmt->fetch();

if ($existing['count'] > 0) {
    echo json_encode(['success' => false, 'message' => 'This time slot is already booked']);
    exit;
}

try {
    // Create booking
    $bookingData = [
        'therapist_id' => $therapist_id,
        'full_name' => $full_name,
        'email' => $email,
        'phone' => $phone,
        'booking_date' => $booking_date,
        'booking_time' => $booking_time,
        'message' => $message,
        'total_amount' => $total_amount,
        'region' => $region,
        'is_night' => $is_night,
        'night_charge' => $night_charge
    ];
    
    $result = createBookingWithRegion($bookingData);
    
    if ($result['success']) {
        // Send confirmation email
        sendBookingConfirmation($result['booking_id']);
        
        echo json_encode([
            'success' => true, 
            'message' => 'Booking confirmed successfully!',
            'booking_id' => $result['booking_id']
        ]);
    } else {
        echo json_encode(['success' => false, 'message' => $result['message']]);
    }
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'An error occurred while processing your booking']);
}
?>