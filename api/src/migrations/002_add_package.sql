ALTER TABLE scans ADD COLUMN IF NOT EXISTS package VARCHAR(20) NOT NULL DEFAULT 'professional';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_package'
  ) THEN
    ALTER TABLE scans ADD CONSTRAINT chk_scans_package
      CHECK (package IN ('basic', 'professional', 'nis2'));
  END IF;
END
$$;
