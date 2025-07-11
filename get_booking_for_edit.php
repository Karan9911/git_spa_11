<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

requireUserLogin();

header('Content-Type: application/json');

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid booking ID']);
    exit;
}

$bookingId = (int)$_GET['id'];

try {
    $db = getDB();
    
    // Get booking details - verify it belongs to user
    $stmt = $db->prepare("
        SELECT b.*, t.name as therapist_name 
        FROM bookings b 
        LEFT JOIN therapists t ON b.therapist_id = t.id 
        WHERE b.id = ? AND b.email = ?
    ");
    $stmt->execute([$bookingId, $_SESSION['user_email']]);
    $booking = $stmt->fetch();
    
    if (!$booking) {
        echo json_encode(['success' => false, 'message' => 'Booking not found or access denied']);
        exit;
    }
    
    if ($booking['status'] !== 'pending') {
        echo json_encode(['success' => false, 'message' => 'Only pending bookings can be edited']);
        exit;
    }
    
    // Check if booking is not in the past
    $bookingDateTime = $booking['booking_date'] . ' ' . $booking['booking_time'];
    if (strtotime($bookingDateTime) < time()) {
        echo json_encode(['success' => false, 'message' => 'Cannot edit past bookings']);
        exit;
    }
    
    echo json_encode([
        'success' => true,
        'booking' => $booking
    ]);
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Server error occurred']);
}
?>