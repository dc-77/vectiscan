-- Migration 013: Add company_name to customers
ALTER TABLE customers ADD COLUMN IF NOT EXISTS company_name VARCHAR(255);
