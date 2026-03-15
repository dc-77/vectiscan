-- Migration 007: Add findings_data JSONB column to reports table
-- Stores the structured Claude-processed findings for dashboard display
ALTER TABLE reports ADD COLUMN IF NOT EXISTS findings_data JSONB;
