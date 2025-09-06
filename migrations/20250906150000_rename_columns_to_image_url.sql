-- Rename banner_image_url to image_url in events table
ALTER TABLE events 
RENAME COLUMN banner_image_url TO image_url;

-- Rename file_url to image_url in event_sessions table
ALTER TABLE event_sessions 
RENAME COLUMN file_url TO image_url;
