<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

requireUserLogin();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$bookingId = (int)($input['booking_id'] ?? 0);
$newDate = sanitizeInput($input['booking_date'] ?? '');
$newTime = sanitizeInput($input['booking_time'] ?? '');
$isNight = $input['is_night'] ?? false;

if ($bookingId <= 0 || empty($newDate) || empty($newTime)) {
    echo json_encode(['success' => false, 'message' => 'Missing required fields']);
    exit;
}

// Validate date
$today = date('Y-m-d');
if ($newDate < $today) {
    echo json_encode(['success' => false, 'message' => 'Booking date cannot be in the past']);
    exit;
}

try {
    $db = getDB();
    $db->beginTransaction();
    
    // Get current booking details
    $stmt = $db->prepare("
        SELECT b.*, t.price_ncr, t.price_other 
        FROM bookings b 
        LEFT JOIN therapists t ON b.therapist_id = t.id 
        WHERE b.id = ? AND b.email = ?
    ");
    $stmt->execute([$bookingId, $_SESSION['user_email']]);
    $booking = $stmt->fetch();
    
    if (!$booking) {
        $db->rollback();
        echo json_encode(['success' => false, 'message' => 'Booking not found or access denied']);
        exit;
    }
    
    if ($booking['status'] !== 'pending') {
        $db->rollback();
        echo json_encode(['success' => false, 'message' => 'Only pending bookings can be edited']);
        exit;
    }
    
    // Check for conflicts with the new time slot
    $stmt = $db->prepare("
        SELECT COUNT(*) as count 
        FROM bookings 
        WHERE therapist_id = ? AND booking_date = ? AND booking_time = ? 
        AND status != 'cancelled' AND id != ?
    ");
    $stmt->execute([$booking['therapist_id'], $newDate, $newTime, $bookingId]);
    $conflict = $stmt->fetch();
    
    if ($conflict['count'] > 0) {
        $db->rollback();
        echo json_encode(['success' => false, 'message' => 'This time slot is already booked']);
        exit;
    }
    
    // Calculate new price based on night time
    $region = $booking['region'] ?? 'other';
    $basePrice = $region === 'ncr' ? 
        ($booking['price_ncr'] ?? $booking['total_amount']) : 
        ($booking['price_other'] ?? $booking['total_amount']);
    
    // Remove old night charge if any
    if ($booking['is_night']) {
        $basePrice = $booking['total_amount'] - ($booking['night_charge'] ?? 1500);
    }
    
    $nightCharge = $isNight ? 1500 : 0;
    $newTotalAmount = $basePrice + $nightCharge;
    
    // Update booking
    $stmt = $db->prepare("
        UPDATE bookings 
        SET booking_date = ?, booking_time = ?, is_night = ?, night_charge = ?, total_amount = ?
        WHERE id = ?
    ");
    $result = $stmt->execute([
        $newDate, 
        $newTime, 
        $isNight ? 1 : 0, 
        $nightCharge, 
        $newTotalAmount, 
        $bookingId
    ]);
    
    if ($result) {
        $db->commit();
        echo json_encode([
            'success' => true, 
            'message' => 'Booking updated successfully',
            'new_amount' => $newTotalAmount
        ]);
    } else {
        $db->rollback();
        echo json_encode(['success' => false, 'message' => 'Failed to update booking']);
    }
    
} catch (Exception $e) {
    $db->rollback();
    echo json_encode(['success' => false, 'message' => 'An error occurred while updating the booking']);
}
?>