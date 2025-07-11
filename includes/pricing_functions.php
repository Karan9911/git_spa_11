<?php
// Pricing utility functions

function getTherapistPrice($therapist, $region = 'other') {
    if ($region === 'ncr') {
        return (float)($therapist['price_ncr'] ?? $therapist['price_per_session']);
    }
    return (float)($therapist['price_other'] ?? $therapist['price_per_session']);
}

function calculateTotalPrice($basePrice, $isNight = false) {
    $nightCharge = $isNight ? 1500 : 0;
    return $basePrice + $nightCharge;
}

function getRegionName($region) {
    return $region === 'ncr' ? 'Delhi-NCR' : 'Rest of India';
}

function formatPriceWithRegion($therapist, $region = 'other', $isNight = false) {
    $basePrice = getTherapistPrice($therapist, $region);
    $totalPrice = calculateTotalPrice($basePrice, $isNight);
    
    return [
        'base_price' => $basePrice,
        'night_charge' => $isNight ? 1500 : 0,
        'total_price' => $totalPrice,
        'formatted_base' => formatPrice($basePrice),
        'formatted_total' => formatPrice($totalPrice)
    ];
}

function updateTherapistPricing($therapistId, $priceNcr, $priceOther) {
    $db = getDB();
    $stmt = $db->prepare("UPDATE therapists SET price_ncr = ?, price_other = ? WHERE id = ?");
    return $stmt->execute([$priceNcr, $priceOther, $therapistId]);
}

function createBookingWithRegion($data) {
    $db = getDB();
    
    try {
        $stmt = $db->prepare("
            INSERT INTO bookings (
                therapist_id, full_name, email, phone, booking_date, booking_time, 
                message, total_amount, region, is_night, night_charge, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        ");
        
        $result = $stmt->execute([
            $data['therapist_id'],
            $data['full_name'],
            $data['email'],
            $data['phone'],
            $data['booking_date'],
            $data['booking_time'],
            $data['message'],
            $data['total_amount'],
            $data['region'],
            $data['is_night'] ? 1 : 0,
            $data['night_charge']
        ]);
        
        if ($result) {
            $bookingId = $db->lastInsertId();
            
            // Create lead entry
            createLead([
                'type' => 'booking',
                'therapist_id' => $data['therapist_id'],
                'full_name' => $data['full_name'],
                'email' => $data['email'],
                'phone' => $data['phone'],
                'message' => $data['message'] ?? '',
                'status' => 'new'
            ]);
            
            return ['success' => true, 'booking_id' => $bookingId];
        }
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
    
    return ['success' => false, 'message' => 'Booking failed'];
}
?>