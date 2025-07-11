-- Database updates for region-based pricing system

-- Add new columns to therapists table
ALTER TABLE therapists 
ADD COLUMN price_ncr DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER price_per_session,
ADD COLUMN price_other DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER price_ncr;

-- Update existing therapists with region-based pricing
-- Set NCR prices 20% higher than current prices, and other regions same as current
UPDATE therapists 
SET 
    price_ncr = ROUND(price_per_session * 1.2, 2),
    price_other = price_per_session
WHERE price_per_session > 0;

-- Add new columns to bookings table
ALTER TABLE bookings 
ADD COLUMN region ENUM('ncr', 'other') NOT NULL DEFAULT 'other' AFTER total_amount,
ADD COLUMN is_night BOOLEAN DEFAULT FALSE AFTER region,
ADD COLUMN night_charge DECIMAL(10,2) DEFAULT 0 AFTER is_night;

-- Create index for better performance
CREATE INDEX idx_therapists_pricing ON therapists(price_ncr, price_other);
CREATE INDEX idx_bookings_region ON bookings(region, is_night);