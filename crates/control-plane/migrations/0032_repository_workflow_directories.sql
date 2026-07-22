ALTER TABLE repository_workflow_settings
    RENAME COLUMN workflow_path TO workflow_directory;

PRAGMA user_version = 32;
